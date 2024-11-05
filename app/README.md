
# 登录
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"password"}'

# 使用access token访问受保护的API
curl http://localhost:8080/api/profile \
  -H "Authorization: Bearer {access_token}"

# 刷新token
curl -X POST http://localhost:8080/auth/refresh \
  -H "X-Refresh-Token: {refresh_token}"

# 登出
curl -X POST http://localhost:8080/api/logout \
  -H "Authorization: Bearer {access_token}"