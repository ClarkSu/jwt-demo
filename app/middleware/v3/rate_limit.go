package v3

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

// RateLimiter 速率限制器配置
type RateLimiter struct {
	redisClient *redis.Client
	limit       int           // 允许的请求数
	window      time.Duration // 时间窗口
	lockTimeout time.Duration // 分布式锁超时时间
}

func NewRateLimiter(redisClient *redis.Client, limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		redisClient: redisClient,
		limit:       limit,
		window:      window,
		lockTimeout: 5 * time.Second,
	}
}

// RateLimitMiddleware 速率限制中间件
func (rl *RateLimiter) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取限流 key（可以基于 IP、用户ID 或两者结合）
		userID := c.GetString("userID")
		clientIP := c.ClientIP()
		key := fmt.Sprintf("ratelimit:%s:%s", userID, clientIP)

		// 检查速率限制
		allowed, remaining, resetTime, err := rl.isAllowed(c, key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "rate limit check failed"})
			c.Abort()
			return
		}

		// 设置速率限制响应头
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", rl.limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))

		if !allowed {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": resetTime.Sub(time.Now()).Seconds(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (rl *RateLimiter) isAllowed(ctx context.Context, key string) (bool, int, time.Time, error) {
	pipe := rl.redisClient.Pipeline()
	now := time.Now()
	windowStart := now.Add(-rl.window)

	// 移除窗口外的记录
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart.UnixNano()))

	// 添加当前请求
	pipe.ZAdd(ctx, key, &redis.Z{
		Score:  float64(now.UnixNano()),
		Member: now.UnixNano(),
	})

	// 获取窗口内的请求数
	pipe.ZCard(ctx, key)

	// 设置 key 过期时间
	pipe.Expire(ctx, key, rl.window)

	cmders, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, time.Time{}, err
	}

	requestCount := cmders[2].(*redis.IntCmd).Val()
	remaining := rl.limit - int(requestCount)
	allowed := requestCount <= int64(rl.limit)
	resetTime := now.Add(rl.window)

	return allowed, remaining, resetTime, nil
}
