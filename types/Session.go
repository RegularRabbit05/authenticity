package types

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"time"
)

var globalGCM cipher.AEAD

type Session struct {
	Hostname string      `json:"hostname"`
	Expiry   int64       `json:"expiry"`
	Payload  interface{} `json:"storage,omitempty"`
}

func NewSession(hostname string, expires int64) *Session {
	return &Session{
		Hostname: hostname,
		Expiry:   expires,
		Payload:  nil,
	}
}

func (session *Session) SetPayload(payload interface{}) *Session {
	session.Payload = payload
	return session
}

func (session *Session) AsB64Storage() (string, error) {
	if session.Payload == nil {
		return "", errors.New("payload is nil")
	}

	jsonBytes, err := json.Marshal(session.Payload)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(jsonBytes), nil
}

func (session *Session) AsB64Cookie(key string) (string, error) {
	if globalGCM == nil {
		if err := sessionInitCipher(key); err != nil {
			return "", fmt.Errorf("failed to initialize cipher: %w", err)
		}
	}

	jsonBytes, err := json.Marshal(session)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, globalGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := globalGCM.Seal(nonce, nonce, jsonBytes, nil)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func (session *Session) FromB64Cookie(key string, b64Data string) error {
	if globalGCM == nil {
		if err := sessionInitCipher(key); err != nil {
			return fmt.Errorf("failed to initialize cipher: %w", err)
		}
	}

	data, err := base64.URLEncoding.DecodeString(b64Data)
	if err != nil {
		return err
	}

	nonceSize := globalGCM.NonceSize()
	if len(data) < nonceSize {
		return errors.New("ciphertext too short")
	}
	nonce, actualCiphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := globalGCM.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed (invalid key or tampered data): %w", err)
	}

	return json.Unmarshal(plaintext, session)
}

func (session *Session) IsValid(requestedHost string) bool {
	if session.Hostname != requestedHost {
		return false
	}

	return session.Expiry > (time.Now().Unix())
}

func sessionInitCipher(secretKey string) error {
	hasher := sha256.New()
	hasher.Write([]byte(secretKey))
	key := hasher.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Failed to create AES cipher: %v", err)
		return err
	}

	globalGCM, err = cipher.NewGCM(block)
	return err
}
