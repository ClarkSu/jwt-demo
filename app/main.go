package main

import (
	"jwt-demo/middleware"
	router "jwt-demo/router/v3"

	"github.com/gin-gonic/gin"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	r := gin.Default()

	// 设置 session 存储
	r.Use(middleware.Logger())
	r.Use(middleware.CORS())
	r.Use(middleware.ErrorHandler())

	router.SetupRoutes(r)

	r.Run(":8080")
}
