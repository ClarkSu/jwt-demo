package protected

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func ProtectedHandler(c *gin.Context) {
	username := c.MustGet("username").(string)
	userID := c.MustGet("userID").(string)
	role := c.MustGet("role").(string)

	// 返回包含 username, userID 和 role 的 JSON 响应
	c.JSON(http.StatusOK, gin.H{
		"message": "Hello " + username,
		"userID":  userID,
		"role":    role,
	})
}
