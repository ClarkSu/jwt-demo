// 登录页面组件
class LoginPage {
    constructor() {
        this.loginForm = document.getElementById('loginForm');
        this.setupEventListeners();
    }

    setupEventListeners() {
        this.loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            try {
                await authService.login(username, password);
                // 登录成功，跳转到主页
                window.location.href = '/dashboard';
            } catch (error) {
                // 显示错误消息
                this.showError(error.message);
            }
        });
    }

    showError(message) {
        const errorElement = document.getElementById('error-message');
        errorElement.textContent = message;
        errorElement.style.display = 'block';
    }
}

// 主页面组件
class DashboardPage {
    constructor() {
        this.init();
    }

    async init() {
        try {
            // 获取用户信息
            const userProfile = await authService.getUserProfile();
            this.updateUI(userProfile);
        } catch (error) {
            // 处理错误
            console.error('Failed to load dashboard:', error);
        }
    }

    updateUI(profile) {
        document.getElementById('username').textContent = profile.username;
        // 更新其他UI元素...
    }
}