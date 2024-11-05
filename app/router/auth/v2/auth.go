package v2

import (
	tokenSrv "jwt-demo/services/token/v1"
	tokenMgr "jwt-demo/services/token/v2"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	TokenService *tokenSrv.TokenService
	TokenManager *tokenMgr.TokenManager
}
type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	UserID   uint   `json:"user_id"`
	Role     string `json:"role"`
}

func (h *AuthHandler) LoginHandler(c *gin.Context) {
	// ... 验证用户凭证 ...
	var user loginReq
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user.UserID = 1
	user.Role = "admin"
	if user.Username == "test" && user.Password == "password" {
		// ... 生成token ...
		accessToken, refreshToken, err := h.TokenService.GenerateTokenPair(user.UserID, user.Username, user.Role)
		if err != nil {
			c.JSON(500, gin.H{"error": "failed to generate tokens"})
			return
		}

		// 存储token信息
		err = h.TokenManager.StoreToken(c, "access", accessToken, &tokenMgr.TokenInfo{
			UserID:    user.UserID,
			Username:  user.Username,
			Role:      user.Role,
			DeviceID:  c.GetHeader("Device-ID"),
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(15 * time.Minute),
		})

		if err != nil {
			c.JSON(500, gin.H{"error": "failed to store token"})
			return
		}

		c.JSON(200, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	} else {
		c.JSON(401, gin.H{"error": "invalid username or password"})
	}
}

func (h *AuthHandler) LogoutHandler(c *gin.Context) {
	token := extractToken(c)
	if err := h.TokenManager.RevokeToken(c, "access", token); err != nil {
		c.JSON(500, gin.H{"error": "failed to revoke token"})
		return
	}

	c.JSON(200, gin.H{"message": "logged out successfully"})
}
