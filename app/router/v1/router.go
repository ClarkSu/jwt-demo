package v1

import (
	middleware "jwt-demo/middleware/v1"
	auth "jwt-demo/router/auth/v1"
	token "jwt-demo/services/token/v1"
	"os"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	// 初始化token服务
	tokenService := token.NewTokenService(
		os.Getenv("JWT_ACCESS_SECRET"),
		os.Getenv("JWT_REFRESH_SECRET"),
	)

	authHandler := &auth.AuthHandler{TokenService: tokenService}
	// 登录路由
	r.POST("/v1/auth/login", authHandler.LoginHandler)

	// 需要认证的路由组
	protected := r.Group("/api")
	protected.Use(middleware.JWTAuthMiddleware(tokenService))
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.MustGet("userID").(uint)
			username := c.MustGet("username").(string)
			role := c.MustGet("role").(string)

			c.JSON(200, gin.H{
				"user_id":  userID,
				"username": username,
				"role":     role,
			})
		})
	}

	// 刷新token的路由
	r.GET("/v1/auth/refresh", authHandler.RefreshHandler)
}
