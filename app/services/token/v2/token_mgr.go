package v1

import (
	"context"
	"encoding/json"
	"fmt"
	token "jwt-demo/services/token/v1"
	"time"

	"github.com/redis/go-redis/v9"
)

type TokenManager struct {
	redis        *redis.Client
	tokenService *token.TokenService
}

// Token信息结构
type TokenInfo struct {
	UserID    uint      `json:"user_id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	DeviceID  string    `json:"device_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func NewTokenManager(redisClient *redis.Client, tokenService *token.TokenService) *TokenManager {
	return &TokenManager{
		redis:        redisClient,
		tokenService: tokenService,
	}
}

func (tm *TokenManager) StoreToken(ctx context.Context, tokenType string, token string, info *TokenInfo) error {
	// 生成Redis键
	tokenKey := fmt.Sprintf("token:%s:%s", tokenType, token)
	userTokensKey := fmt.Sprintf("user_tokens:%d", info.UserID)

	// 序列化token信息
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal token info: %w", err)
	}

	// 使用Pipeline来保证原子性
	pipe := tm.redis.Pipeline()

	// 存储token信息
	pipe.Set(ctx, tokenKey, infoJSON, time.Until(info.ExpiresAt))

	// 将token添加到用户的token集合
	pipe.SAdd(ctx, userTokensKey, token)

	// 设置用户token集合的过期时间
	pipe.ExpireAt(ctx, userTokensKey, info.ExpiresAt)

	// 执行Pipeline
	_, err = pipe.Exec(ctx)
	return err
}

// 获取Token信息
func (tm *TokenManager) GetTokenInfo(ctx context.Context, tokenType, token string) (*TokenInfo, error) {
	tokenKey := fmt.Sprintf("token:%s:%s", tokenType, token)

	infoJSON, err := tm.redis.Get(ctx, tokenKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("token not found")
		}
		return nil, err
	}

	var info TokenInfo
	if err := json.Unmarshal(infoJSON, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token info: %w", err)
	}

	return &info, nil
}

func (tm *TokenManager) RevokeToken(ctx context.Context, tokenType, token string) error {
	// 获取token信息
	info, err := tm.GetTokenInfo(ctx, tokenType, token)
	if err != nil {
		return err
	}

	tokenKey := fmt.Sprintf("token:%s:%s", tokenType, token)
	userTokensKey := fmt.Sprintf("user_tokens:%d", info.UserID)
	revokedTokenKey := fmt.Sprintf("revoked_token:%s", token)

	pipe := tm.redis.Pipeline()

	// 删除token信息
	pipe.Del(ctx, tokenKey)

	// 从用户token集合中移除
	pipe.SRem(ctx, userTokensKey, token)

	// 将token添加到撤销列表，并设置过期时间
	pipe.Set(ctx, revokedTokenKey, "revoked", time.Until(info.ExpiresAt))

	_, err = pipe.Exec(ctx)
	return err
}

// 检查token是否被撤销
func (tm *TokenManager) IsTokenRevoked(ctx context.Context, token string) bool {
	revokedTokenKey := fmt.Sprintf("revoked_token:%s", token)
	exists, _ := tm.redis.Exists(ctx, revokedTokenKey).Result()
	return exists > 0
}

// 获取用户的所有活跃token
func (tm *TokenManager) GetUserActiveTokens(ctx context.Context, userID uint) ([]string, error) {
	userTokensKey := fmt.Sprintf("user_tokens:%d", userID)
	return tm.redis.SMembers(ctx, userTokensKey).Result()
}

// 撤销用户的所有token
func (tm *TokenManager) RevokeAllUserTokens(ctx context.Context, userID uint) error {
	tokens, err := tm.GetUserActiveTokens(ctx, userID)
	if err != nil {
		return err
	}

	pipe := tm.redis.Pipeline()

	for _, token := range tokens {
		tokenKey := fmt.Sprintf("token:access:%s", token)
		revokedTokenKey := fmt.Sprintf("revoked_token:%s", token)

		pipe.Del(ctx, tokenKey)
		pipe.Set(ctx, revokedTokenKey, "revoked", 24*time.Hour) // 保留撤销记录24小时
	}

	userTokensKey := fmt.Sprintf("user_tokens:%d", userID)
	pipe.Del(ctx, userTokensKey)

	_, err = pipe.Exec(ctx)
	return err
}

// 每个设备只允许一个活跃token
func (tm *TokenManager) StoreDeviceToken(ctx context.Context, userID uint, deviceID string, token string) error {
	deviceTokenKey := fmt.Sprintf("device_token:%d:%s", userID, deviceID)

	// 获取设备当前的token
	oldToken, err := tm.redis.Get(ctx, deviceTokenKey).Result()
	if err != nil && err != redis.Nil {
		return err
	}

	pipe := tm.redis.Pipeline()

	// 如果存在旧token，先撤销它
	if oldToken != "" {
		tm.RevokeToken(ctx, "access", oldToken)
	}

	// 存储新的设备token映射
	pipe.Set(ctx, deviceTokenKey, token, 24*time.Hour)

	_, err = pipe.Exec(ctx)
	return err
}
