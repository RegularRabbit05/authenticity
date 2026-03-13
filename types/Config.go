package types

import (
	"encoding/json"
	"fmt"
	"os"
)

type AppConfiguration struct {
	Key                 string           `json:"key"`
	ServiceNotFoundCode int              `json:"serviceNotFoundCode"`
	ProxiedServices     []ProxiedService `json:"proxiedServices"`
}

func (config *AppConfiguration) LoadFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	err = json.Unmarshal(data, config)
	if err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	for i, service := range config.ProxiedServices {
		key, err := os.ReadFile(service.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to read private key file for service %s: %w", service.Hostname, err)
		}
		config.ProxiedServices[i].PrivateKey = string(key)
	}

	return nil
}
