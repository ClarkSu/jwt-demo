package v1

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTClaims struct {
	UserID    uint   `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"` // access 或 refresh
	jwt.RegisteredClaims
}

type TokenService struct {
	accessSecret  string
	refreshSecret string
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

func NewTokenService(accessSecret, refreshSecret string) *TokenService {
	return &TokenService{
		accessSecret:  accessSecret,
		refreshSecret: refreshSecret,
		accessTTL:     15 * time.Minute,   // 访问令牌15分钟
		refreshTTL:    7 * 24 * time.Hour, // 刷新令牌7天
	}
}

func (s *TokenService) GenerateTokenPair(userID uint, username, role string) (accessToken, refreshToken string, err error) {
	// 生成访问令牌
	accessToken, err = s.generateToken(userID, username, role, "access", s.accessSecret, s.accessTTL)
	if err != nil {
		return "", "", err
	}

	// 生成刷新令牌
	refreshToken, err = s.generateToken(userID, username, role, "refresh", s.refreshSecret, s.refreshTTL)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *TokenService) generateToken(userID uint, username, role, tokenType, secret string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		UserID:    userID,
		Username:  username,
		Role:      role,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "your-app-name",
			Subject:   string(userID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
func (s *TokenService) ValidateToken(tokenString, tokenType string) (*JWTClaims, error) {
	secret := s.accessSecret
	if tokenType == "refresh" {
		secret = s.refreshSecret
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims.TokenType != tokenType {
		return nil, errors.New("incorrect token type")
	}

	return claims, nil
}
func (s *TokenService) RefreshTokens(refreshToken string) (newAccessToken, newRefreshToken string, err error) {
	// 验证刷新令牌
	claims, err := s.ValidateToken(refreshToken, "refresh")
	if err != nil {
		return "", "", err
	}

	// 生成新的令牌对
	newAccessToken, newRefreshToken, err = s.GenerateTokenPair(
		claims.UserID,
		claims.Username,
		claims.Role,
	)

	return newAccessToken, newRefreshToken, err
}
