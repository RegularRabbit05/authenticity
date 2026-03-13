package types

import "time"

type AuthPayload struct {
	Expiry   int64       `json:"expiry"`
	Hostname string      `json:"hostname"`
	Redirect string      `json:"redirect"`
	Payload  interface{} `json:"storage,omitempty"`
}

func (payload *AuthPayload) IsValid(hostname string) bool {
	if payload.Hostname != hostname {
		return false
	}

	return payload.Expiry > (time.Now().Unix())
}
