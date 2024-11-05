package v2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenPair 包含访问令牌和刷新令牌
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// TokenClaims JWT claims结构
type TokenClaims struct {
	jwt.RegisteredClaims
	UserID    uint   `json:"uid"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"` // "access" or "refresh"
	DeviceID  string `json:"device_id,omitempty"`
}

// TokenConfig 配置
type TokenConfig struct {
	AccessTokenSecret  string
	RefreshTokenSecret string
	AccessTokenTTL     time.Duration // 默认15分钟
	RefreshTokenTTL    time.Duration // 默认7天
}

// UserSession 用户会话信息
type UserSession struct {
	UserID       uint      `json:"user_id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	DeviceID     string    `json:"device_id"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	LastLogin    time.Time `json:"last_login"`
	LastActivity time.Time `json:"last_activity"`
}

type TokenService struct {
	config *TokenConfig
	tm     *TokenManager
}

func NewTokenService(config *TokenConfig, tm *TokenManager) *TokenService {
	return &TokenService{
		config: config,
		tm:     tm,
	}
}

// 生成token对
func (s *TokenService) GenerateTokenPair(ctx context.Context, user UserSession) (*TokenPair, error) {
	// 生成Access Token
	accessToken, err := s.createToken(user, "access", s.config.AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 生成Refresh Token
	refreshToken, err := s.createToken(user, "refresh", s.config.RefreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// 存储到Redis
	if err := s.storeTokens(ctx, user, accessToken, refreshToken); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// 创建token
func (s *TokenService) createToken(user UserSession, tokenType string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		UserID:    user.UserID,
		Username:  user.Username,
		Role:      user.Role,
		TokenType: tokenType,
		DeviceID:  user.DeviceID,
	}

	secret := s.config.AccessTokenSecret
	if tokenType == "refresh" {
		secret = s.config.RefreshTokenSecret
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// 存储tokens到Redis
func (s *TokenService) storeTokens(ctx context.Context, user UserSession, accessToken, refreshToken string) error {
	// 存储access token信息
	accessInfo := TokenInfo{
		UserID:    user.UserID,
		Username:  user.Username,
		Role:      user.Role,
		TokenType: "access",
		DeviceID:  user.DeviceID,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.config.AccessTokenTTL),
		IP:        user.IP,
		UserAgent: user.UserAgent,
	}

	// 存储refresh token信息
	refreshInfo := TokenInfo{
		UserID:    user.UserID,
		Username:  user.Username,
		TokenType: "refresh",
		DeviceID:  user.DeviceID,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.config.RefreshTokenTTL),
		IP:        user.IP,
		UserAgent: user.UserAgent,
	}

	// 使用管道存储
	// pipe := s.redis.pool.Pipeline()
	// defer pipe.Close()

	if err := s.tm.StoreToken(ctx, accessToken, accessInfo); err != nil {
		return err
	}

	if err := s.tm.StoreToken(ctx, refreshToken, refreshInfo); err != nil {
		return err
	}

	return nil
}

// 验证access token
func (s *TokenService) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.config.AccessTokenSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims.TokenType != "access" {
		return nil, errors.New("invalid token type")
	}

	return claims, nil
}

// 验证refresh token
func (s *TokenService) ValidateRefreshToken(tokenString string) (*TokenClaims, error) {
	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.config.RefreshTokenSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims.TokenType != "refresh" {
		return nil, errors.New("invalid token type")
	}

	return claims, nil
}

// 刷新token
func (s *TokenService) RefreshTokens(ctx context.Context, refreshToken string) (*TokenPair, error) {
	// 验证refresh token
	claims, err := s.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// 检查refresh token是否在redis中
	tokenInfo, err := s.tm.GetTokenInfo(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token not found: %w", err)
	}

	// 创建新的会话信息
	session := UserSession{
		UserID:    claims.UserID,
		Username:  claims.Username,
		DeviceID:  claims.DeviceID,
		IP:        tokenInfo.IP,
		UserAgent: tokenInfo.UserAgent,
	}

	// 生成新的token对
	newTokens, err := s.GenerateTokenPair(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("generate new tokens: %w", err)
	}

	// 撤销旧的refresh token
	if err := s.tm.RevokeToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("revoke old refresh token: %w", err)
	}

	return newTokens, nil
}
