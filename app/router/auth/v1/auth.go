package v1

import (
	auth "jwt-demo/services/token/v1"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	TokenService *auth.TokenService
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	UserID   uint   `json:"user_id"`
	Role     string `json:"role"`
}

func (h *AuthHandler) LoginHandler(c *gin.Context) {
	var user loginReq
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user.UserID = 1
	user.Role = "admin"

	// 验证用户（这里可以替换为数据库查询）
	if user.Username == "test" && user.Password == "password" {
		// 生成token对
		accessToken, refreshToken, err := h.TokenService.GenerateTokenPair(
			user.UserID,
			user.Username,
			user.Role,
		)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate tokens"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
	}
}

func (h *AuthHandler) RefreshHandler(c *gin.Context) {
	refreshToken := c.GetHeader("X-Refresh-Token")

	newAccessToken, newRefreshToken, err := h.TokenService.RefreshTokens(refreshToken)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid refresh token"})
		return
	}

	c.JSON(200, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}
