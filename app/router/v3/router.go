package v3

import (
	middleware "jwt-demo/middleware/v3"
	auth "jwt-demo/router/auth/v3"
	token "jwt-demo/services/token/v3"
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	// 初始化Redis连接
	redisConfig := token.DefaultRedisConfig()
	tokenManager, err := token.NewTokenManager(redisConfig)
	if err != nil {
		log.Fatal(err)
	}
	// defer tokenManager.Close()

	// 初始化Token服务
	tokenConfig := &token.TokenConfig{
		AccessTokenSecret:  "your-access-token-secret",
		RefreshTokenSecret: "your-refresh-token-secret",
		AccessTokenTTL:     15 * time.Minute,
		RefreshTokenTTL:    7 * 24 * time.Hour,
	}
	tokenService := token.NewTokenService(tokenConfig, tokenManager)

	// 登录接口
	r.POST("/v3/auth/login", auth.HandleLogin(tokenService))

	// 刷新token接口
	r.POST("/v3/auth/refresh", auth.HandleRefreshToken(tokenService))
	r.GET("/v3/auth/logout", middleware.JWTAuthMiddleware(tokenService, tokenManager), auth.HandleLogout(tokenManager))

	// 受保护的API路由组
	protected := r.Group("/api")
	protected.Use(middleware.JWTAuthMiddleware(tokenService, tokenManager))
	{
		protected.GET("/profile", auth.HandleProfile)
	}
}
