package v3

import (
	token "jwt-demo/services/token/v3"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func validateCredentials(username, password string) bool {
	// 实现用户验证逻辑
	return username == "test" && password == "password" // 只是示例，实际逻辑根据需求
}

// 处理登录请求
func HandleLogin(tokenService *token.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginReq struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&loginReq); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// 验证用户凭证（示例）
		if !validateCredentials(loginReq.Username, loginReq.Password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// 创建会话
		session := token.UserSession{
			UserID:    1, // 从数据库获取
			Username:  loginReq.Username,
			Role:      "admin",
			DeviceID:  c.GetHeader("X-Device-ID"),
			IP:        c.ClientIP(),
			UserAgent: c.GetHeader("User-Agent"),
			LastLogin: time.Now(),
		}

		// 生成token对
		tokens, err := tokenService.GenerateTokenPair(c, session)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
			return
		}

		c.JSON(http.StatusOK, tokens)
	}
}

// 处理刷新token请求
func HandleRefreshToken(tokenService *token.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		refreshToken := c.GetHeader("X-Refresh-Token")
		if refreshToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token required"})
			return
		}

		newTokens, err := tokenService.RefreshTokens(c, refreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
			return
		}

		c.JSON(http.StatusOK, newTokens)
	}
}

// 处理受保护的个人资料请求
func HandleProfile(c *gin.Context) {
	userID := c.MustGet("user_id").(uint)
	username := c.MustGet("username").(string)
	role := c.MustGet("role").(string)
	c.JSON(http.StatusOK, gin.H{
		"user_id":  userID,
		"username": username,
		"role":     role,
	})
}

// 处理登出请求
func HandleLogout(tokenManager *token.TokenManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if err := tokenManager.RevokeToken(c, token); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	}
}
