package api

import (
	"context"
	"net/http"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
)

// requireAuthentication checks incoming requests for tokens presented using the Authorization header
func (a *API) requireAuthentication(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	logrus.Info("Getting auth token")
	token, err := a.extractBearerToken(w, r)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("Parsing JWT claims: %v", token)
	return a.parseJWTClaims(token, r)
}

func (a *API) extractBearerToken(w http.ResponseWriter, r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", unauthorizedError("This endpoint requires a Bearer token")
	}

	matches := bearerRegexp.FindStringSubmatch(authHeader)
	if len(matches) != 2 {
		return "", unauthorizedError("This endpoint requires a Bearer token")
	}

	return matches[1], nil
}

func padTo32(str string) string {
	if len(str) >= 32 {
		return str[:32]
	}
	return str + strings.Repeat("\x00", 32-len(str))
}

func decrypt(encryptedText, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	nonceSize := 12
	authTagSize := 16

	nonce := data[:nonceSize]
	cipherText := data[nonceSize : len(data)-authTagSize]
	authTag := data[len(data)-authTagSize:]

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plainText, err := aesGCM.Open(nil, nonce, append(cipherText, authTag...), nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}


func (a *API) parseJWTClaims(bearer string, r *http.Request) (context.Context, error) {
	config := getConfig(r.Context())
	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	token, err := p.ParseWithClaims(bearer, &GatewayClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JWT.Secret), nil
	})
	if err != nil {
		return nil, unauthorizedError("Invalid token: %v", err)
	}

	newCtx := withToken(r.Context(), token)
	claims := getClaims(newCtx)

	config.GitHub.Repo = ""
	config.GitHub.AccessToken = ""
	config.GitLab.Repo = ""
	config.GitLab.AccessToken = ""
	
	logrus.Info("Grabbing gateway details from JWT")

	gitProvider := claims.AppMetaData["git_provider"].(string)
	repo := claims.AppMetaData["repo"].(string)
	accessToken := claims.AppMetaData["access_token"].(string)

	if strings.HasPrefix(accessToken, "encrypted_") {
		logrus.Info("Decrypting access token")
		encrypted := strings.TrimPrefix(accessToken, "encrypted_")
		decrypted, err := decrypt(encrypted, padTo32(config.JWT.Secret))
		logrus.Debugf("Encrypted: %s, Decrypted: %s", encrypted, decrypted)
		if err != nil {
			return nil, unauthorizedError("Failed to decrypt: %v", err)
		}
		accessToken = decrypted
	}

	if gitProvider == "github" {
		logrus.Info("Configure github request")
		config.GitHub.Repo = repo
		config.GitHub.AccessToken = accessToken
	}

	if gitProvider == "gitlab" {
		logrus.Info("Configure gitlab request")
		config.GitLab.Repo = repo
		config.GitLab.AccessToken = accessToken
	}

	return newCtx, nil
}
