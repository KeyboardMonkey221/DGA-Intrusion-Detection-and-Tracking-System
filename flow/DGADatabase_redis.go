package main

import (
	"fmt"
	"log"

	"github.com/go-redis/redis"
)

var DGARedisClient *redis.Client

func initRedisDB() {
	// Create connection to redis db
	DGARedisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	_, err := DGARedisClient.Ping().Result()
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("Successfully connected to redis db...")
	}
}
