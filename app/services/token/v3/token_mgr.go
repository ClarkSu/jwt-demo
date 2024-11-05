package v2

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
)

// 配置结构
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
	// 连接池配置
	PoolSize      int
	MinIdleConns  int
	MaxConnAge    time.Duration
	PoolTimeout   time.Duration
	IdleTimeout   time.Duration
	IdleCheckFreq time.Duration
}

// Token管理器
type TokenManager struct {
	pool   *redis.Client
	mutex  sync.RWMutex
	config *RedisConfig
}

// Token信息
type TokenInfo struct {
	UserID     uint      `json:"user_id"`
	Username   string    `json:"username"`
	Role       string    `json:"role"`
	DeviceID   string    `json:"device_id"`
	TokenType  string    `json:"token_type"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
}

// 创建默认配置
func DefaultRedisConfig() *RedisConfig {
	return &RedisConfig{
		Host:          "localhost",
		Port:          6379,
		Password:      "",
		DB:            0,
		PoolSize:      100,
		MinIdleConns:  10,
		MaxConnAge:    30 * time.Minute,
		PoolTimeout:   4 * time.Second,
		IdleTimeout:   5 * time.Minute,
		IdleCheckFreq: 1 * time.Minute,
	}
}
func NewTokenManager(config *RedisConfig) (*TokenManager, error) {
	if config == nil {
		config = DefaultRedisConfig()
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
		PoolTimeout:  config.PoolTimeout,
	})

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, errors.Wrap(err, "failed to connect to redis")
	}

	return &TokenManager{
		pool:   rdb,
		config: config,
	}, nil
}

// 关闭连接池
func (tm *TokenManager) Close() error {
	return tm.pool.Close()
}

// 获取健康状态
func (tm *TokenManager) HealthCheck(ctx context.Context) error {
	return tm.pool.Ping(ctx).Err()
}

// 存储Token
func (tm *TokenManager) StoreToken(ctx context.Context, token string, info TokenInfo) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// 生成键名
	tokenKey := fmt.Sprintf("token:%s", token)
	userTokensKey := fmt.Sprintf("user_tokens:%d", info.UserID)
	deviceTokenKey := fmt.Sprintf("device_tokens:%d:%s", info.UserID, info.DeviceID)

	// 序列化token信息
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return errors.Wrap(err, "failed to marshal token info")
	}

	pipe := tm.pool.Pipeline()

	// 存储token信息
	pipe.Set(ctx, tokenKey, infoJSON, time.Until(info.ExpiresAt))

	// 添加到用户的token集合
	pipe.SAdd(ctx, userTokensKey, token)
	pipe.ExpireAt(ctx, userTokensKey, info.ExpiresAt)

	// 如果指定了设备ID，更新设备token映射
	if info.DeviceID != "" {
		// 获取设备当前token
		oldToken, err := tm.pool.Get(ctx, deviceTokenKey).Result()
		if err != nil && err != redis.Nil {
			return errors.Wrap(err, "failed to get device token")
		}

		// 如果存在旧token，撤销它
		if oldToken != "" {
			pipe.Del(ctx, fmt.Sprintf("token:%s", oldToken))
			pipe.SRem(ctx, userTokensKey, oldToken)
		}

		// 存储新的设备token映射
		pipe.Set(ctx, deviceTokenKey, token, time.Until(info.ExpiresAt))
	}

	_, err = pipe.Exec(ctx)
	return errors.Wrap(err, "failed to store token")
}
func (tm *TokenManager) getTokenInfo(ctx context.Context, token string) (*TokenInfo, error) {
	tokenKey := fmt.Sprintf("token:%s", token)

	// 获取token信息
	infoJSON, err := tm.pool.Get(ctx, tokenKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New("token not found")
		}
		return nil, errors.Wrap(err, "failed to get token info")
	}

	var info TokenInfo
	if err := json.Unmarshal(infoJSON, &info); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal token info")
	}

	// 更新最后使用时间
	info.LastUsedAt = time.Now()
	if updatedInfoJSON, err := json.Marshal(info); err == nil {
		tm.pool.Set(ctx, tokenKey, updatedInfoJSON, time.Until(info.ExpiresAt))
	}

	return &info, nil
}

// 获取Token信息
func (tm *TokenManager) GetTokenInfo(ctx context.Context, token string) (*TokenInfo, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	return tm.getTokenInfo(ctx, token)
}

// 撤销Token
func (tm *TokenManager) RevokeToken(ctx context.Context, token string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	info, err := tm.getTokenInfo(ctx, token)
	if err != nil {
		return err
	}

	tokenKey := fmt.Sprintf("token:%s", token)
	userTokensKey := fmt.Sprintf("user_tokens:%d", info.UserID)
	deviceTokenKey := fmt.Sprintf("device_tokens:%d:%s", info.UserID, info.DeviceID)
	revokedTokenKey := fmt.Sprintf("revoked_token:%s", token)

	pipe := tm.pool.Pipeline()

	// 删除token信息
	pipe.Del(ctx, tokenKey)

	// 从用户token集合中移除
	pipe.SRem(ctx, userTokensKey, token)

	// 如果是设备token，清除设备映射
	if info.DeviceID != "" {
		pipe.Del(ctx, deviceTokenKey)
	}

	// 添加到撤销列表
	pipe.Set(ctx, revokedTokenKey, "revoked", time.Until(info.ExpiresAt))

	_, err = pipe.Exec(ctx)
	return errors.Wrap(err, "failed to revoke token")
}

// 验证Token
func (tm *TokenManager) ValidateToken(ctx context.Context, token string) (*TokenInfo, error) {
	// 检查token是否被撤销
	revokedKey := fmt.Sprintf("revoked_token:%s", token)
	if exists, _ := tm.pool.Exists(ctx, revokedKey).Result(); exists > 0 {
		return nil, errors.New("token has been revoked")
	}

	// 获取并验证token信息
	info, err := tm.getTokenInfo(ctx, token)
	if err != nil {
		return nil, err
	}

	// 检查是否过期
	if time.Now().After(info.ExpiresAt) {
		return nil, errors.New("token has expired")
	}

	return info, nil
}

// 获取用户所有活跃token
func (tm *TokenManager) GetUserActiveTokens(ctx context.Context, userID uint) ([]*TokenInfo, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	userTokensKey := fmt.Sprintf("user_tokens:%d", userID)
	tokens, err := tm.pool.SMembers(ctx, userTokensKey).Result()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user tokens")
	}

	var tokenInfos []*TokenInfo
	for _, token := range tokens {
		if info, err := tm.getTokenInfo(ctx, token); err == nil {
			tokenInfos = append(tokenInfos, info)
		}
	}

	return tokenInfos, nil
}

// 撤销用户所有token
func (tm *TokenManager) RevokeAllUserTokens(ctx context.Context, userID uint) error {
	tokens, err := tm.GetUserActiveTokens(ctx, userID)
	if err != nil {
		return err
	}

	for _, tokenInfo := range tokens {
		if err := tm.RevokeToken(ctx, tokenInfo.TokenType); err != nil {
			return err
		}
	}

	return nil
}

// // 令牌桶限流器
// type RateLimiter struct {
// 	pool       *redis.Client
// 	maxTokens  int
// 	refillRate time.Duration
// }

// func (tm *TokenManager) NewRateLimiter(maxTokens int, refillRate time.Duration) *RateLimiter {
// 	return &RateLimiter{
// 		pool:       tm.pool,
// 		maxTokens:  maxTokens,
// 		refillRate: refillRate,
// 	}
// }

// func (rl *RateLimiter) Allow(ctx context.Context, key string) (bool, error) {
// 	script := `
//         local key = KEYS[1]
//         local max_tokens = tonumber(ARGV[1])
//         local refill_rate = tonumber(ARGV[2])
//         local now = tonumber(ARGV[3])

//         local info = redis.call('HMGET', key, 'tokens', 'last_update')
//         local tokens = tonumber(info[1] or max_tokens)
//         local last_update = tonumber(info[2] or now)

//         local elapsed = now - last_update
//         local new_tokens = math.min(max_tokens, tokens + (elapsed * refill_rate))

//         if new_tokens >= 1 then
//             redis.call('HMSET', key,
//                 'tokens', new_tokens - 1,
//                 'last_update', now)
//             return 1
//         end
//         return 0
//     `

// 	now := time.Now().Unix()
// 	result, err := tm.pool.Eval(ctx, script, []string{key},
// 		rl.maxTokens,
// 		float64(time.Second)/float64(rl.refillRate),
// 		now).Result()

// 	if err != nil {
// 		return false, err
// 	}

// 	return result.(int64) == 1, nil
// }
