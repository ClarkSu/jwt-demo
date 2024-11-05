package router

import (
	"jwt-demo/middleware"
	"jwt-demo/router/auth"
	"jwt-demo/router/protected"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {

	// 获取 index.html 页面
	r.GET("/", func(c *gin.Context) {
		c.File("./static/index.html") // 假设 index.html 位于 static 目
	})
	// 登录接口
	r.POST("/auth/login", auth.LoginHandler)

	// 受保护的接口组
	api := r.Group("/api")
	{
		api.Use(middleware.ValidateRequest)
		api.Use(middleware.AuthMiddleware())

		// 受保护的接口，需要 JWT
		api.GET("/protected", protected.ProtectedHandler)
	}
}
