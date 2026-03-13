package server

import (
	"authenticity/types"
	"io"
	"net/http"
)

func ProxyConnectionHandler(app *types.App) func(http.ResponseWriter, *http.Request) {
	encKey := app.GetKey()

	proxyRequest := func(w http.ResponseWriter, r *http.Request, proxiedService types.ProxiedService) {
		targetURL := proxiedService.Target + r.URL.Path
		request, err := http.NewRequest(r.Method, targetURL, r.Body)
		if err != nil {
			http.Error(w, "Failed to create request", http.StatusInternalServerError)
			return
		}

		request.Header = r.Header

		client := &http.Client{}
		response, err := client.Do(request)
		if err != nil {
			http.Error(w, "Failed to forward request", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()

		if proxiedService.CorsRewrite != "" {
			response.Header.Set("Access-Control-Allow-Origin", proxiedService.CorsRewrite)
			response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			response.Header.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			response.Header.Set("Access-Control-Allow-Credentials", "true")
		}

		for key, values := range response.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		w.WriteHeader(response.StatusCode)
		_, err = io.Copy(w, response.Body)

		if err != nil {
			http.Error(w, "Failed to read response", http.StatusInternalServerError)
			return
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			proxiedService, err := app.FindProxiedService(r.Host)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			if proxiedService.CorsRewrite != "" {
				w.Header().Set("Access-Control-Allow-Origin", proxiedService.CorsRewrite)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		cookie, err := r.Cookie("authenticity")
		if err != nil || cookie.Value == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var session types.Session
		if err = session.FromB64Cookie(encKey, cookie.Value); err != nil {
			http.Error(w, "Failed to parse session", http.StatusUnauthorized)
			return
		}

		if !session.IsValid(r.Host) {
			http.Error(w, "Invalid authorization", http.StatusUnauthorized)
			return
		}

		proxiedService, err := app.FindProxiedService(r.Host)
		if err != nil {
			app.Mtx.RLock()
			defer app.Mtx.RUnlock()
			http.Error(w, "Service not found", app.Config.ServiceNotFoundCode)
			return
		}

		proxyRequest(w, r, proxiedService)
	}
}
