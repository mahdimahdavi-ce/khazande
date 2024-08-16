package envs

import "os"

type Envs struct {
	GRPC_SERVER_ADDRESS          string
	GRPC_SERVER_PORT             string
	LOG_LEVEL                    string
	REDIS_ADDRESS                string
	REDIS_PORT                   string
	GITHUB_ADVISORT_DATABASE_URL string
	GITHUB_TOKEN                 string
	PSQL_HOST                    string
	PSQL_PORT                    string
	PSQL_USERNAME                string
	PSQL_PASSWORD                string
	PSQL_DATABASE_NAME           string
}

func ReadEnvs() *Envs {
	envs := Envs{}
	envs.GRPC_SERVER_ADDRESS = os.Getenv("GRPC_SERVER_ADDRESS")
	envs.GRPC_SERVER_PORT = os.Getenv("GRPC_SERVER_PORT")
	envs.LOG_LEVEL = os.Getenv("LOG_LEVEL")
	envs.REDIS_ADDRESS = os.Getenv("REDIS_ADDRESS")
	envs.REDIS_PORT = os.Getenv("REDIS_PORT")
	envs.GITHUB_ADVISORT_DATABASE_URL = os.Getenv("GITHUB_ADVISORT_DATABASE_URL")
	envs.GITHUB_TOKEN = os.Getenv("GITHUB_TOKEN")
	envs.PSQL_HOST = os.Getenv("PSQL_HOST")
	envs.PSQL_PORT = os.Getenv("PSQL_PORT")
	envs.PSQL_USERNAME = os.Getenv("PSQL_USERNAME")
	envs.PSQL_PASSWORD = os.Getenv("PSQL_PASSWORD")
	envs.PSQL_DATABASE_NAME = os.Getenv("PSQL_DATABASE_NAME")

	return &envs
}
