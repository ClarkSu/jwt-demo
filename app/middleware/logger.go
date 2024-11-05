// logger.go
package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Logger() gin.HandlerFunc {
	logger, _ := zap.NewProduction()

	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		// 处理请求前
		c.Next()

		// 处理请求后
		latency := time.Since(start)
		statusCode := c.Writer.Status()

		logger.Info("HTTP Request",
			zap.String("path", path),
			zap.Int("status", statusCode),
			zap.Duration("latency", latency),
			zap.String("method", c.Request.Method),
			zap.String("client_ip", c.ClientIP()),
		)
	}
}
