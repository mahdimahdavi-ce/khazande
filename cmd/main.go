package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"google.golang.org/grpc"

	"khazande/ent"
	grpcModule "khazande/internal/grpc"
	routerModule "khazande/internal/routers"
	envsModule "khazande/pkg/envs"
	pb "khazande/pkg/grpc"
	loggerModule "khazande/pkg/logger"

	_ "github.com/lib/pq"
)

func main() {
	app := fiber.New()
	app.Use(logger.New())

	envs := envsModule.ReadEnvs()
	logger := loggerModule.InitialLogger(envs.LOG_LEVEL)
	psqlClient := InitialDatabase(envs.PSQL_HOST, envs.PSQL_PORT, envs.PSQL_USERNAME, envs.PSQL_PASSWORD, envs.PSQL_DATABASE_NAME)

	lis, tcpErr := net.Listen("tcp", fmt.Sprintf("%s:%s", envs.GRPC_SERVER_ADDRESS, envs.GRPC_SERVER_PORT))
	if tcpErr != nil {
		log.Fatalf("Failed to stablish a tcp connections: %v", tcpErr)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterScrapperServiceServer(grpcServer, &grpcModule.Server{Logger: logger, Envs: envs})

	channel := make(chan os.Signal, 1)
	signal.Notify(channel, os.Interrupt)

	go func() {
		logger.Info("Service is started and waiting for incoming messages ...")
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to start gRPC server: %v", err)
		}
	}()

	routers := routerModule.Initial(envs, logger, psqlClient)
	routers.SetupRouters(app)

	grpcServer.Stop()
	logger.Info("gRPC server is stoped")
	lis.Close()
	logger.Info("TCP connection is closed")
}

func InitialDatabase(host, port, username, password, databaseName string) *ent.Client {
	// NOTE: On production sslmode must be enabled !!!
	dsn := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable", host, port, username, databaseName, password)

	client, err := ent.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed opening connection to postgres: %v", err)
	}

	if migrationErr := client.Schema.Create(context.Background()); migrationErr != nil {
		log.Fatalf("Failed creating schema resources: %v", migrationErr)
	}

	return client
}
