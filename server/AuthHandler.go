package server

import (
	"authenticity/types"
	"net/http"
	"time"
)

func AuthenticationHandler(app *types.App) func(http.ResponseWriter, *http.Request) {
	encKey := app.GetKey()

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

		auth := r.URL.Query().Get("auth")
		if auth == "" {
			http.Error(w, "Missing authorization", http.StatusUnauthorized)
			return
		}

		proxiedService, err := app.FindProxiedService(r.Host)
		if err != nil {
			app.Mtx.RLock()
			defer app.Mtx.RUnlock()
			http.Error(w, "Service not found", app.Config.ServiceNotFoundCode)
			return
		}

		authResult, err := proxiedService.ParseAuth(auth)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !authResult.IsValid(r.Host) {
			http.Error(w, "Invalid", http.StatusUnauthorized)
			return
		}

		session := types.NewSession(r.Host, authResult.Expiry).SetPayload(authResult.Payload)

		sessionCookie, err := session.AsB64Cookie(encKey)
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		sameSiteMode := http.SameSiteStrictMode
		if proxiedService.CorsRewrite != "" {
			w.Header().Set("Access-Control-Allow-Origin", proxiedService.CorsRewrite)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			sameSiteMode = http.SameSiteNoneMode
		}

		http.SetCookie(w, &http.Cookie{
			Name:        "authenticity",
			Value:       sessionCookie,
			Expires:     time.Unix(authResult.Expiry, 0),
			HttpOnly:    false,
			Secure:      true,
			SameSite:    sameSiteMode,
			Path:        "/",
			Partitioned: true,
		})

		if session.Payload != nil {
			if data, err := session.AsB64Storage(); err == nil {
				http.SetCookie(w, &http.Cookie{
					Name:        "authenticity-storage",
					Value:       data,
					Expires:     time.Unix(authResult.Expiry, 0),
					HttpOnly:    false,
					Secure:      true,
					SameSite:    sameSiteMode,
					Path:        "/",
					Partitioned: true,
				})
			}
		}

		http.Redirect(w, r, authResult.Redirect, http.StatusFound)
	}
}
