package types

import (
	"encoding/base64"
	"encoding/json"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

var pgp = crypto.PGP()

type ProxiedService struct {
	Hostname    string `json:"hostname"`
	Target      string `json:"target"`
	PrivateKey  string `json:"privateKey"`
	CorsRewrite string `json:"corsRewrite"`
}

func (service *ProxiedService) ParseAuth(payload string) (AuthPayload, error) {
	data, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return AuthPayload{}, err
	}

	privateKey, err := crypto.NewPrivateKeyFromArmored(service.PrivateKey, []byte(""))
	if err != nil {
		return AuthPayload{}, err
	}

	decHandle, err := pgp.Decryption().DecryptionKey(privateKey).New()
	if err != nil {
		return AuthPayload{}, err
	}
	defer decHandle.ClearPrivateParams()

	decrypted, err := decHandle.Decrypt(data, crypto.Armor)
	if err != nil {
		return AuthPayload{}, err
	}

	message := decrypted.Bytes()

	var authPayload AuthPayload
	err = json.Unmarshal(message, &authPayload)
	if err != nil {
		return AuthPayload{}, err
	}

	return authPayload, nil
}
