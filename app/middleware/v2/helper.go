package v2

import (
	"errors"

	"strings"

	"github.com/gin-gonic/gin"
)

var (
	ErrEmptyAuthHeader   = errors.New("auth header is empty")
	ErrInvalidAuthHeader = errors.New("auth header is invalid")
)

// TokenExtractor 定义了不同的 token 提取策略
type TokenExtractor func(*gin.Context) (string, error)

// FromHeader 从 Authorization header 中提取 token
func FromHeader(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToUpper(parts[0]) != "BEARER" {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

// FromQuery 从 URL query 参数中提取 token
func FromQuery(c *gin.Context) (string, error) {
	token := c.Query("token")
	if token == "" {
		return "", ErrEmptyAuthHeader
	}
	return token, nil
}

// FromCookie 从 cookie 中提取 token
func FromCookie(c *gin.Context) (string, error) {
	token, err := c.Cookie("token")
	if err != nil {
		return "", err
	}
	return token, nil
}

// ExtractToken 使用多种策略提取 token
func ExtractToken(c *gin.Context) string {
	// 定义提取策略顺序
	extractors := []TokenExtractor{
		FromHeader,
		FromQuery,
		FromCookie,
	}

	// 依次尝试每种提取策略
	for _, extractor := range extractors {
		token, err := extractor(c)
		if err == nil && token != "" {
			return token
		}
	}

	return ""
}

// ValidateToken 验证 token 的基本格式
func ValidateToken1(token string) error {
	if token == "" {
		return errors.New("empty token")
	}

	// 检查 token 长度
	if len(token) < 10 {
		return errors.New("token too short")
	}

	// 检查 token 是否包含三个部分（header.payload.signature）
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token format")
	}

	return nil
}
