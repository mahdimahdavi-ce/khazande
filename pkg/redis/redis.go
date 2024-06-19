package redisModule

import (
	"fmt"
	envsModule "khazande/pkg/envs"

	"github.com/redis/go-redis/v9"
)

func Init(envs *envsModule.Envs) *redis.Client {
	redisUri := fmt.Sprintf("%s:%s", envs.REDIS_ADDRESS, envs.REDIS_PORT)
	return redis.NewClient(&redis.Options{
		Addr:     redisUri,
		Password: "", // no password set
		DB:       0,  // use default DB
	})
}
