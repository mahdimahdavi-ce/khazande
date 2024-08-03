package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"google.golang.org/grpc"

	nvdModule "khazande/internal/nvd"
	envsModule "khazande/pkg/envs"
	pb "khazande/pkg/grpc"
	loggerModule "khazande/pkg/logger"
	redisModule "khazande/pkg/redis"
)

func main() {
	envs := envsModule.ReadEnvs()
	logger := loggerModule.InitialLogger(envs.LOG_LEVEL)
	redisClient := redisModule.Init(envs)

	lis, tcpErr := net.Listen("tcp", fmt.Sprintf("%s:%s", envs.GRPC_SERVER_ADDRESS, envs.GRPC_SERVER_PORT))
	if tcpErr != nil {
		log.Fatalf("Failed to stablish a tcp connections: %v", tcpErr)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterScrapperServiceServer(grpcServer, &nvdModule.Server{Logger: logger, RedisClient: redisClient})

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
