package types

import (
	"errors"
	"flag"
	"sync"
)

type App struct {
	Mtx    sync.RWMutex
	Port   uint16
	Config AppConfiguration
}

var portFlag = flag.Uint("port", 8080, "Port to listen on")
var configNameFlag = flag.String("config", "config.json", "Path to configuration file")

func (app *App) AppLoadConfig() error {
	flag.Parse()
	var config AppConfiguration
	err := config.LoadFromFile(*configNameFlag)
	if err != nil {
		return err
	}

	app.Mtx.Lock()
	defer app.Mtx.Unlock()
	app.Config = config
	app.Port = uint16(*portFlag)
	return nil
}

func (app *App) GetKey() string {
	app.Mtx.RLock()
	defer app.Mtx.RUnlock()
	return app.Config.Key
}

func (app *App) FindProxiedService(hostname string) (ProxiedService, error) {
	app.Mtx.RLock()
	defer app.Mtx.RUnlock()
	for _, service := range app.Config.ProxiedServices {
		if service.Hostname == hostname {
			return service, nil
		}
		if service.CorsRewrite == hostname || service.CorsRewrite == "https://"+hostname {
			return service, nil
		}
	}
	return ProxiedService{}, errors.New("proxied service not found")
}
