package v3

import (
	token "jwt-demo/services/token/v3"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// middleware/jwt.go
func JWTAuthMiddleware(ts *token.TokenService, tm *token.TokenManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			c.Abort()
			return
		}

		// 移除"Bearer "前缀
		token = strings.TrimPrefix(token, "Bearer ")

		// 验证token
		claims, err := ts.ValidateAccessToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// 检查Redis中的token状态
		info, err := tm.GetTokenInfo(c, token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token revoked or expired"})
			c.Abort()
			return
		}

		// 设置用户信息到上下文
		c.Set("user_id", claims.UserID)
		c.Set("username", info.Username)
		c.Set("role", info.Role)
		c.Next()
	}
}
