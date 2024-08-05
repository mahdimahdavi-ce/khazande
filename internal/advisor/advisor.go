package advisor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	types "khazande/internal/types"
	envsModule "khazande/pkg/envs"
	"net/http"
	"sync"

	"github.com/Masterminds/semver/v3"
	"go.uber.org/zap"
)

type Advisor struct {
	Logger *zap.Logger
	Envs   *envsModule.Envs
}

type GitHubVulnerabilityQuery struct {
	Query string `json:"query"`
}

func (a *Advisor) FetchVulnerabilitiesFromGithub(packages map[string]string) map[string][]*types.Vulnerability {
	vulnerabilites := make(map[string][]*types.Vulnerability)
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for packageName, packageVersion := range packages {
		wg.Add(1)

		go func() {
			defer wg.Done()
			packageVulnerabilities := a.fetchVulnerabiltyOfSpecificPackage(packageName, packageVersion)

			mutex.Lock()
			vulnerabilites[packageName] = packageVulnerabilities
			mutex.Unlock()
		}()
	}

	wg.Wait()

	return vulnerabilites
}

func (a *Advisor) fetchVulnerabiltyOfSpecificPackage(packageName string, version string) []*types.Vulnerability {
	query := GitHubVulnerabilityQuery{
		Query: fmt.Sprintf(`	
		{
			securityVulnerabilities(first: 100, package: "%s", ecosystem: GO) {
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
		a.Logger.Sugar().Errorf("Failed to marshal query: %v", err)
		return nil
	}

	req, err := http.NewRequest("POST", a.Envs.GITHUB_ADVISORT_DATABASE_URL, bytes.NewBuffer(jsonQuery))
	if err != nil {
		a.Logger.Sugar().Errorf("Failed to create request: %v", err)
		return nil
	}

	req.Header.Set("Authorization", "Bearer "+a.Envs.GITHUB_TOKEN)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		a.Logger.Sugar().Errorf("Failed to perform request: %v", err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		a.Logger.Sugar().Errorf("Failed to read response body: %v", err)
		return nil
	}

	var githubResponse types.GitHubVulnerabilityQueryResponse

	if err := json.Unmarshal(body, &githubResponse); err != nil {
		a.Logger.Sugar().Errorf("Failed to unmarshal response: %v", err)
		return nil
	}

	var result []*types.Vulnerability

	for _, vulnerabilityNode := range githubResponse.Data.SecurityVulnerabilities.Nodes {
		if vulnerabilityNode.Package.Name == packageName {
			inRange, err := isVersionInRange(version, vulnerabilityNode.VulnerableVersionRange)
			if err != nil {
				a.Logger.Sugar().Errorf("Error checking version range: %v", err)
			}

			if inRange {
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
	}

	return result
}

func isVersionInRange(version string, versionRange string) (bool, error) {
	// Parse the version from the go.mod
	v, err := semver.NewVersion(version)
	if err != nil {
		return false, err
	}

	// Parse the version range from the advisory data
	constraint, err := semver.NewConstraint(versionRange)
	if err != nil {
		return false, err
	}

	// Check if the version satisfies the constraint
	return constraint.Check(v), nil
}
