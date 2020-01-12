package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"time"
)

func createJWT(privateKeyPath string, algorithm string, expiration time.Duration) (string, error) {
	claims := jwt.StandardClaims{
		Audience:  "example",
		ExpiresAt: time.Now().Add(expiration).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	keyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(algorithm), claims)

	switch algorithm {
	case "RS256":
		privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
		if err != nil {
			return "", err
		}
		return token.SignedString(privKey)
	}
	return "", nil
}

func verifyJWT(publicKeyPath string, token string) (bool, error) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (i interface{}, err error) {
		if token.Method != (jwt.SigningMethodRS256) {
			return nil, fmt.Errorf("invalid signing method")
		}
		verifyBytes, err := ioutil.ReadFile(publicKeyPath)
		if err != nil {
			return nil, err
		}
		return jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	})
	if err != nil {
		return false, err
	}
	return t.Valid, nil
}

func main() {
	privateKeyPath := "./secrets/rsa"
	algorithm := "RS256"
	expiration := time.Hour

	token, err := createJWT(privateKeyPath, algorithm, expiration)
	if err != nil {
		log.Fatal(err)
	}
	publicKeyPath := "./secrets/rsa.pub.pkcs8"
	ok, err := verifyJWT(publicKeyPath, token)
	if err != nil {
		log.Fatal(err)
	}
	if ok {
		fmt.Println("token signature is verified")
	} else {
		fmt.Println("token signature is invalid")
	}
}