package v2

import (
	middleware "jwt-demo/middleware/v2"
	auth "jwt-demo/router/auth/v2"
	tokenSrv "jwt-demo/services/token/v1"
	tokenMgr "jwt-demo/services/token/v2"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func SetupRoutes(r *gin.Engine) {
	// 初始化Redis客户端
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	// 初始化Token服务和Token管理器
	tokenService := tokenSrv.NewTokenService(os.Getenv("JWT_ACCESS_SECRET"), os.Getenv("JWT_REFRESH_SECRET"))
	tokenManager := tokenMgr.NewTokenManager(rdb, tokenService)
	authHandler := auth.AuthHandler{
		TokenService: tokenService,
		TokenManager: tokenManager,
	}

	r.POST("/v2/auth/login", authHandler.LoginHandler)
	// 需要认证的路由组
	protected := r.Group("/api")
	protected.Use(middleware.JWTAuthMiddleware(tokenManager))
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
	r.GET("/v2/auth/logout", authHandler.LogoutHandler)
}
