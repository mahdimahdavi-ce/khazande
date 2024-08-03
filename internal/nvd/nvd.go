package nvd

import (
	"context"
	"fmt"

	crawlerModule "khazande/internal/crawler"
	pb "khazande/pkg/grpc"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type Server struct {
	pb.UnimplementedScrapperServiceServer
	Logger      *zap.Logger
	RedisClient *redis.Client
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

	crawler := crawlerModule.Crawler{Logger: s.Logger, RedisClient: s.RedisClient}

	links := crawler.ExtractVulnerabilitiesLinks(query)

	if len(links) == 0 {
		return nil, fmt.Errorf("there is no matching Vulnerabilities")
	}

	vulnerabilities := crawler.ExtractVulnerabilitiesDetails(query, links)

	if len(vulnerabilities) != 0 {
		s.Logger.Info(fmt.Sprintf("Web Scrapper has extracted %d vulnerabilities successfully!", len(vulnerabilities)))
	} else {
		s.Logger.Info(fmt.Sprintf("Failed to extract vulnerabilities for %s", query))
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
		})
	}

	return &pb.VulnerabilityResponse{
		Vulnerabilities: result,
	}, nil
}
