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

	return &envs
}
