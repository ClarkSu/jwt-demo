// api/auth.js
class AuthService {
    constructor() {
        this.baseURL = 'http://localhost:8080';
        this.accessToken = localStorage.getItem('accessToken');
        this.refreshToken = localStorage.getItem('refreshToken');
        this.tokenExpiryTime = localStorage.getItem('tokenExpiryTime');
        
        // 添加请求拦截器用于自动刷新token
        this.initializeRequestInterceptor();
    }

    // 初始化axios请求拦截器
    initializeRequestInterceptor() {
        axios.interceptors.request.use(
            async config => {
                // 如果是刷新token的请求，直接发送
                if (config.url === '/auth/refresh') {
                    return config;
                }

                // 检查token是否需要刷新
                if (this.shouldRefreshToken()) {
                    await this.refreshAccessToken();
                }

                // 添加token到请求头
                if (this.accessToken) {
                    config.headers.Authorization = `Bearer ${this.accessToken}`;
                }

                return config;
            },
            error => {
                return Promise.reject(error);
            }
        );

        // 响应拦截器
        axios.interceptors.response.use(
            response => response,
            async error => {
                const originalRequest = error.config;

                // 如果是401错误且不是刷新token的请求，尝试刷新token
                if (error.response.status === 401 && !originalRequest._retry) {
                    originalRequest._retry = true;

                    try {
                        await this.refreshAccessToken();
                        originalRequest.headers.Authorization = `Bearer ${this.accessToken}`;
                        return axios(originalRequest);
                    } catch (refreshError) {
                        // 刷新token失败，需要重新登录
                        this.logout();
                        throw refreshError;
                    }
                }

                return Promise.reject(error);
            }
        );
    }

    // 检查token是否需要刷新
    shouldRefreshToken() {
        if (!this.tokenExpiryTime) return false;
        
        // 如果距离过期时间小于5分钟，就刷新token
        const currentTime = Date.now();
        const timeUntilExpiry = this.tokenExpiryTime - currentTime;
        return timeUntilExpiry < 5 * 60 * 1000;
    }

    // 保存tokens
    setTokens(accessToken, refreshToken, expiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.tokenExpiryTime = Date.now() + expiresIn * 1000;

        localStorage.setItem('accessToken', accessToken);
        localStorage.setItem('refreshToken', refreshToken);
        localStorage.setItem('tokenExpiryTime', this.tokenExpiryTime);
    }

    // 清除tokens
    clearTokens() {
        this.accessToken = null;
        this.refreshToken = null;
        this.tokenExpiryTime = null;

        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('tokenExpiryTime');
    }

    // 登录
    async login(username, password) {
        try {
            const response = await axios.post(`${this.baseURL}/auth/login`, {
                username,
                password
            });

            const { access_token, refresh_token } = response.data;
            this.setTokens(access_token, refresh_token, 900); // 15分钟过期
            return response.data;
        } catch (error) {
            console.error('Login failed:', error);
            throw error;
        }
    }

    // 刷新token
    async refreshAccessToken() {
        try {
            const response = await axios.post(
                `${this.baseURL}/auth/refresh`,
                {},
                {
                    headers: {
                        'X-Refresh-Token': this.refreshToken
                    }
                }
            );

            const { access_token, refresh_token } = response.data;
            this.setTokens(access_token, refresh_token, 900);
            return response.data;
        } catch (error) {
            console.error('Token refresh failed:', error);
            this.logout();
            throw error;
        }
    }

    // 登出
    async logout() {
        try {
            if (this.accessToken) {
                await axios.post(
                    `${this.baseURL}/api/logout`,
                    {},
                    {
                        headers: {
                            Authorization: `Bearer ${this.accessToken}`
                        }
                    }
                );
            }
        } catch (error) {
            console.error('Logout failed:', error);
        } finally {
            this.clearTokens();
            // 可以在这里添加重定向到登录页面的逻辑
            window.location.href = '/login';
        }
    }

    // 获取用户信息
    async getUserProfile() {
        try {
            const response = await axios.get(`${this.baseURL}/api/profile`, {
                headers: {
                    Authorization: `Bearer ${this.accessToken}`
                }
            });
            return response.data;
        } catch (error) {
            console.error('Failed to get user profile:', error);
            throw error;
        }
    }
}

// 创建单例
export const authService = new AuthService();