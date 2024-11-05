package v3

// middleware/security.go

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

// SecurityConfig 安全配置
type SecurityConfig struct {
	MaxTokensPerUser  int           // 每个用户最大允许的token数量
	MaxDevicesPerUser int           // 每个用户最大允许的设备数量
	TokenTTL          time.Duration // token有效期
	RequireMFA        bool          // 是否要求多因素认证
	AllowedOrigins    []string      // 允许的源域名
	AllowedIPs        []string      // 允许的IP地址
	BlockedIPs        []string      // 被封禁的IP地址
	SuspiciousIPs     []string      // 可疑的IP地址
}

// SecurityMiddleware 安全中间件
type SecurityMiddleware struct {
	redis      *redis.Client
	config     *SecurityConfig
	bruteforce *BruteForceProtection
}

func NewSecurityMiddleware(redis *redis.Client, config *SecurityConfig) *SecurityMiddleware {
	return &SecurityMiddleware{
		redis:      redis,
		config:     config,
		bruteforce: NewBruteForceProtection(redis),
	}
}

// SecurityCheckMiddleware 综合安全检查中间件
func (sm *SecurityMiddleware) SecurityCheckMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. IP 检查
		if !sm.checkIP(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied by IP"})
			c.Abort()
			return
		}

		// 2. Origin 检查
		if !sm.checkOrigin(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid origin"})
			c.Abort()
			return
		}

		// 3. 设备数量检查
		if !sm.checkDeviceLimit(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "device limit exceeded"})
			c.Abort()
			return
		}

		// 4. Token 数量检查
		if !sm.checkTokenLimit(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "token limit exceeded"})
			c.Abort()
			return
		}

		// 5. 暴力破解保护
		if sm.bruteforce.IsBlocked(c) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many failed attempts"})
			c.Abort()
			return
		}

		// 6. MFA 检查（如果启用）
		if sm.config.RequireMFA && !sm.checkMFA(c) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "MFA required"})
			c.Abort()
			return
		}

		// 7. 可疑活动检查
		if sm.detectSuspiciousActivity(c) {
			// 记录可疑活动但允许请求继续
			go sm.logSuspiciousActivity(c)
		}

		c.Next()
	}
}

// BruteForceProtection 暴力破解保护
type BruteForceProtection struct {
	redis       *redis.Client
	maxAttempts int
	blockTime   time.Duration
}

func NewBruteForceProtection(redis *redis.Client) *BruteForceProtection {
	return &BruteForceProtection{
		redis:       redis,
		maxAttempts: 5,
		blockTime:   30 * time.Minute,
	}
}

func (bf *BruteForceProtection) IsBlocked(c *gin.Context) bool {
	key := fmt.Sprintf("bruteforce:%s", c.ClientIP())
	attempts, err := bf.redis.Get(c, key).Int()
	if err != nil {
		return false
	}
	return attempts >= bf.maxAttempts
}

func (bf *BruteForceProtection) RecordFailedAttempt(c *gin.Context) {
	key := fmt.Sprintf("bruteforce:%s", c.ClientIP())
	bf.redis.Incr(c, key)
	bf.redis.Expire(c, key, bf.blockTime)
}

func (bf *BruteForceProtection) Reset(c *gin.Context) {
	key := fmt.Sprintf("bruteforce:%s", c.ClientIP())
	bf.redis.Del(c, key)
}

// SecurityMiddleware 的具体检查方法实现
func (sm *SecurityMiddleware) checkIP(c *gin.Context) bool {
	clientIP := c.ClientIP()

	// 检查是否在黑名单中
	for _, ip := range sm.config.BlockedIPs {
		if ip == clientIP {
			return false
		}
	}

	// 如果配置了白名单，只允许白名单中的IP
	if len(sm.config.AllowedIPs) > 0 {
		for _, ip := range sm.config.AllowedIPs {
			if ip == clientIP {
				return true
			}
		}
		return false
	}

	return true
}

func (sm *SecurityMiddleware) checkOrigin(c *gin.Context) bool {
	origin := c.GetHeader("Origin")
	if origin == "" {
		return true // 允许无 Origin 的请求
	}

	for _, allowed := range sm.config.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}

	return false
}

func (sm *SecurityMiddleware) checkDeviceLimit(c *gin.Context) bool {
	userID := c.GetString("userID")
	deviceID := c.GetString("deviceID")
	key := fmt.Sprintf("devices:%s", userID)

	// 检查设备数量
	count, err := sm.redis.SCard(c, key).Result()
	if err != nil {
		return false
	}

	// 如果是新设备且已达到限制
	if count >= int64(sm.config.MaxDevicesPerUser) {
		exists, _ := sm.redis.SIsMember(c, key, deviceID).Result()
		if !exists {
			return false
		}
	}

	// 记录设备
	sm.redis.SAdd(c, key, deviceID)
	return true
}

func (sm *SecurityMiddleware) checkTokenLimit(c *gin.Context) bool {
	userID := c.GetString("userID")
	key := fmt.Sprintf("tokens:%s", userID)

	count, err := sm.redis.SCard(c, key).Result()
	if err != nil {
		return false
	}

	return count < int64(sm.config.MaxTokensPerUser)
}

func (sm *SecurityMiddleware) checkMFA(c *gin.Context) bool {
	userID := c.GetString("userID")
	mfaVerifiedKey := fmt.Sprintf("mfa:verified:%s", userID)

	verified, err := sm.redis.Get(c, mfaVerifiedKey).Bool()
	if err != nil || !verified {
		return false
	}

	return true
}

func (sm *SecurityMiddleware) detectSuspiciousActivity(c *gin.Context) bool {
	clientIP := c.ClientIP()
	userID := c.GetString("userID")

	// 检查是否是可疑IP
	for _, ip := range sm.config.SuspiciousIPs {
		if ip == clientIP {
			return true
		}
	}

	// 检查用户行为模式
	key := fmt.Sprintf("user:activity:%s", userID)
	activity, err := sm.redis.Get(c, key).Result()
	if err == nil && activity != "" {
		// 比较用户常规行为模式
		if sm.isAbnormalBehavior(activity, c.Request) {
			return true
		}
	}

	return false
}

func (sm *SecurityMiddleware) logSuspiciousActivity(c *gin.Context) {
	event := map[string]interface{}{
		"timestamp": time.Now(),
		"userID":    c.GetString("userID"),
		"ip":        c.ClientIP(),
		"userAgent": c.GetHeader("User-Agent"),
		"path":      c.Request.URL.Path,
		"method":    c.Request.Method,
	}

	// 记录可疑活动
	key := fmt.Sprintf("suspicious:activity:%s", c.GetString("userID"))
	sm.redis.RPush(c, key, event)
}

func (sm *SecurityMiddleware) isAbnormalBehavior(normalPattern string, req *http.Request) bool {
	// 实现行为模式分析逻辑
	return false
}
