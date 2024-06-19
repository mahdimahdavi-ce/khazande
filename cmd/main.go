package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	crawlerModule "khazande/internal/crawler"
	pb "khazande/internal/grpc"
	envsModule "khazande/pkg/envs"
	loggerModule "khazande/pkg/logger"
	redisModule "khazande/pkg/redis"
)

type server struct {
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

func (s *server) FetchVulnerabilities(ctx context.Context, req *pb.VulnerabilityRequest) (*pb.VulnerabilityResponse, error) {
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

func main() {
	envs := envsModule.ReadEnvs()
	logger := loggerModule.InitialLogger(envs.LOG_LEVEL)
	redisClient := redisModule.Init(envs)

	lis, tcpErr := net.Listen("tcp", fmt.Sprintf("%s:%s", envs.GRPC_SERVER_ADDRESS, envs.GRPC_SERVER_PORT))
	if tcpErr != nil {
		log.Fatalf("Failed to stablish a tcp connections: %v", tcpErr)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterScrapperServiceServer(grpcServer, &server{Logger: logger, RedisClient: redisClient})

	channel := make(chan os.Signal, 1)
	signal.Notify(channel, os.Interrupt)

	go func() {
		logger.Info("Service is started and waiting for incoming messages ...")
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to start gRPC server: %v", err)
		}
	}()

	<-channel
	grpcServer.Stop()
	logger.Info("gRPC server is stoped")
	lis.Close()
	logger.Info("TCP connection is closed")
}
