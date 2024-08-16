package nvd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	nvdModule "khazande/internal/nvd"
	"khazande/internal/types"
	envsModule "khazande/pkg/envs"
	pb "khazande/pkg/grpc"

	"go.uber.org/zap"
)

type Server struct {
	pb.UnimplementedScrapperServiceServer
	Logger *zap.Logger
	Envs   *envsModule.Envs
}

type GitHubVulnerabilityQuery struct {
	Query string `json:"query"`
}

func handlePanic() {
	a := recover()

	if a != nil {
		fmt.Printf("Recover from panic: %v", a)
	}
}

func (s *Server) FetchVulnerabilities(ctx context.Context, req *pb.VulnerabilityRequest) (*pb.VulnerabilityResponse, error) {
	defer handlePanic()

	query := req.GetName()
	s.Logger.Info(fmt.Sprintf("Start searching for %s vulnerabilities", query))

	githubVulnerabilities := s.fetchVulnerabiltyOfSpecificPackage(query)

	for _, vul := range githubVulnerabilities {
		s.Logger.Sugar().Infof("New vulnerability is found for %s from Github Advisor Database - %s", query, vul.CVEID)
	}

	crawler := nvdModule.Crawler{Logger: s.Logger}

	nvdlinks := crawler.ExtractVulnerabilitiesLinks(query)

	if len(nvdlinks) == 0 && len(githubVulnerabilities) == 0 {
		return nil, fmt.Errorf("there is no matching Vulnerabilities")
	}

	nvdVulnerabilities := crawler.ExtractVulnerabilitiesDetails(query, nvdlinks)

	if len(nvdVulnerabilities) != 0 {
		s.Logger.Info(fmt.Sprintf("Web Scrapper has extracted %d vulnerabilities successfully!", len(nvdVulnerabilities)))
	} else {
		s.Logger.Info(fmt.Sprintf("Crawler found no vulnerabilities from NVD for %s", query))
	}

	vulnerabilities := map[string]*types.Vulnerability{}

	for _, vulnerability := range nvdVulnerabilities {
		vulnerabilities[vulnerability.CVEID] = &vulnerability
	}

	for _, vulnerability := range githubVulnerabilities {
		vulnerabilities[vulnerability.CVEID] = vulnerability
	}

	result := []*pb.Vulnerability{}
	for _, vulnerability := range vulnerabilities {
		result = append(result, &pb.Vulnerability{
			Name:               vulnerability.Name,
			CVEID:              vulnerability.CVEID,
			PublishedDate:      vulnerability.PublishedDate,
			LastModified:       vulnerability.LastModified,
			Description:        vulnerability.Description,
			VulnerableVersions: vulnerability.VulnerableVersions,
			NVDScore:           vulnerability.NVDScore,
			CNAScore:           vulnerability.CNAScore,
			Summary:            vulnerability.Summary,
			AffectedVersions:   vulnerability.AffectedVersions,
			PatchedVersions:    vulnerability.PatchedVersions,
			Severity:           vulnerability.Severity,
		})
	}

	return &pb.VulnerabilityResponse{
		Vulnerabilities: result,
	}, nil
}

func (s *Server) fetchVulnerabiltyOfSpecificPackage(packageName string) []*types.Vulnerability {
	query := GitHubVulnerabilityQuery{
		Query: fmt.Sprintf(`	
		{
			securityVulnerabilities(first: 100, package: "%s") {
				nodes {
					package {
						name
					}
					advisory {
						summary
						description
						severity
						identifiers {
							type
							value
						}
						publishedAt

					}
					vulnerableVersionRange
					firstPatchedVersion {
						identifier
					}
					updatedAt
				}
			}
		}`, packageName),
	}

	jsonQuery, err := json.Marshal(query)
	if err != nil {
		s.Logger.Sugar().Errorf("Failed to marshal query: %v", err)
		return nil
	}

	req, err := http.NewRequest("POST", s.Envs.GITHUB_ADVISORT_DATABASE_URL, bytes.NewBuffer(jsonQuery))
	if err != nil {
		s.Logger.Sugar().Errorf("Failed to create request: %v", err)
		return nil
	}

	req.Header.Set("Authorization", "Bearer "+s.Envs.GITHUB_TOKEN)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		s.Logger.Sugar().Errorf("Failed to perform request: %v", err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.Logger.Sugar().Errorf("Failed to read response body: %v", err)
		return nil
	}

	var githubResponse types.GitHubVulnerabilityQueryResponse

	if err := json.Unmarshal(body, &githubResponse); err != nil {
		s.Logger.Sugar().Errorf("Failed to unmarshal response: %v", err)
		return nil
	}

	var result []*types.Vulnerability

	for _, vulnerabilityNode := range githubResponse.Data.SecurityVulnerabilities.Nodes {
		if strings.EqualFold(vulnerabilityNode.Package.Name, packageName) {
			vulnerability := new(types.Vulnerability)

			vulnerability.Name = vulnerabilityNode.Package.Name
			vulnerability.Summary = vulnerabilityNode.Advisory.Summary
			vulnerability.Description = vulnerabilityNode.Advisory.Description
			vulnerability.Severity = vulnerabilityNode.Advisory.Severity
			vulnerability.PublishedDate = vulnerabilityNode.Advisory.PublishedAt.String()
			vulnerability.LastModified = vulnerabilityNode.UpdatedAt.String()
			vulnerability.AffectedVersions = vulnerabilityNode.VulnerableVersionRange
			vulnerability.PatchedVersions = vulnerabilityNode.FirstPatchedVersion.Identifier
			vulnerability.NVDScore = vulnerabilityNode.Advisory.CVSS.Score

			for _, identifier := range vulnerabilityNode.Advisory.Identifiers {
				if identifier.Type == "CVE" {
					vulnerability.CVEID = identifier.Value
				}
			}

			result = append(result, vulnerability)

		}
	}

	return result
}
