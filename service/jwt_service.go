package service

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type JWTClaims struct {
	UserID string `json:"user_id"`
	Mobile string `json:"mobile"`
	Type   string `json:"type"`
	jwt.RegisteredClaims
}

type JWTService interface {
	GenerateAccessToken(userID bson.ObjectID, mobile string) (string, error)
	GenerateRefreshToken(userID bson.ObjectID, mobile string) (string, error)
	ValidateToken(tokenStr string) (*JWTClaims, error)
}

type jwtService struct {
	privateKey         *rsa.PrivateKey
	publicKey          *rsa.PublicKey
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
}

func NewJWTService(privateKeyPEM, publicKeyPEM string, accessExp, refreshExp int) (JWTService, error) {
	privateKeyPEM = strings.ReplaceAll(privateKeyPEM, `\n`, "\n")
	publicKeyPEM = strings.ReplaceAll(publicKeyPEM, `\n`, "\n")

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse private key PEM")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	block2, _ := pem.Decode([]byte(publicKeyPEM))
	if block2 == nil {
		return nil, errors.New("failed to parse public key PEM")
	}
	pubKeyInterface, err := x509.ParsePKIXPublicKey(block2.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pubKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return &jwtService{
		privateKey:         privKey,
		publicKey:          pubKey,
		accessTokenExpiry:  time.Duration(accessExp) * time.Minute,
		refreshTokenExpiry: time.Duration(refreshExp) * 24 * time.Hour,
	}, nil
}

func (s *jwtService) GenerateAccessToken(userID bson.ObjectID, mobile string) (string, error) {
	claims := JWTClaims{
		UserID: userID.Hex(),
		Mobile: mobile,
		Type:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.accessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "banking-auth-service",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

func (s *jwtService) GenerateRefreshToken(userID bson.ObjectID, mobile string) (string, error) {
	claims := JWTClaims{
		UserID: userID.Hex(),
		Mobile: mobile,
		Type:   "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.refreshTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "banking-auth-service",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

func (s *jwtService) ValidateToken(tokenStr string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
