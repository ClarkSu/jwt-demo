package v2

import (
	token "jwt-demo/services/token/v2"
	"net/http"

	"github.com/gin-gonic/gin"
)

// middleware/jwt.go
func JWTAuthMiddleware(tm *token.TokenManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ExtractToken(c)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no token provided"})
			c.Abort()
			return
		}

		// 检查token是否被撤销
		if tm.IsTokenRevoked(c, token) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token has been revoked"})
			c.Abort()
			return
		}

		// 获取token信息
		info, err := tm.GetTokenInfo(c, "access", token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// 将用户信息存储到上下文
		c.Set("userID", info.UserID)
		c.Set("username", info.Username)
		c.Set("role", info.Role)
		c.Set("deviceID", info.DeviceID)

		c.Next()
	}
}
