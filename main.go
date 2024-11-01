package main

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
)

var secretKey = []byte("your_secret_key") // JWT 密钥

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	r := gin.Default()

	// 设置 session 存储
	// store := cookie.NewStore([]byte("secret"))
	// r.Use(sessions.Sessions("mysession", store))
	store := memstore.NewStore([]byte(secretKey))
	r.Use(sessions.Sessions("mysession", store))
	// 登录接口
	r.POST("/login", login)
	// 受保护的接口，需要 JWT
	r.GET("/protected", authMiddleware(), protected)

	// 获取 index.html 页面
	r.GET("/", func(c *gin.Context) {
		c.File("./static/index.html") // 假设 index.html 位于 static 目
	})

	r.Run(":8080")
}

func login(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// 验证用户（这里可以替换为数据库查询）
	if user.Username == "testuser" && user.Password == "password" {
		// 生成 JWT
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": user.Username,
			"exp":      time.Now().Add(time.Hour * 72).Unix(), // 过期时间为72小时
		})

		tokenString, err := token.SignedString(secretKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
			return
		}

		// 保存用户信息到 session
		session := sessions.Default(c)
		session.Set("username", user.Username)
		session.Save()

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.Request.Header.Get("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			c.Abort()
			return
		}

		// 检查 Bearer 前缀并提取 Token
		if len(tokenString) < 7 || tokenString[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		// 提取实际的 Token
		tokenString = tokenString[7:] // 去掉 "Bearer " 前缀

		claims := &jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("username", (*claims)["username"])
		c.Next()
	}
}

func protected(c *gin.Context) {
	username := c.MustGet("username").(string)
	c.JSON(http.StatusOK, gin.H{"message": "Hello " + username})
}
