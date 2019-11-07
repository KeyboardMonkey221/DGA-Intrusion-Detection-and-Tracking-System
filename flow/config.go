package main

import "flag"
import (
	"fmt"
	"github.com/BurntSushi/toml"
)

// Declaring as an exportable type in case you move this to a separate package
type FlowConfig struct {
	Nats Nats
}

type Nats struct {
	NatsURL string `toml:"nats_url"`
}

func GetConfig() FlowConfig {
	var conf FlowConfig

	filePath := getPath()
	if _, err := toml.DecodeFile(filePath, &conf); err != nil {
		fmt.Println("Error reading config", err)
		panic("Kill")
	}
	return conf
}

func getPath() string {
	return flag.Lookup("config").Value.(flag.Getter).Get().(string)
}
