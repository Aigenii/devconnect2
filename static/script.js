// DevConnect - Интерактивный JavaScript
// Fetch wrapper: automatically add X-CSRF-Token header for same-origin POST/PUT/DELETE JSON requests
(() => {
    try {
        const meta = document.querySelector('meta[name="csrf-token"]');
        const csrf = meta ? meta.getAttribute('content') : null;
        if (csrf && window.fetch) {
            const nativeFetch = window.fetch.bind(window);
            window.fetch = (input, init = {}) => {
                try {
                    const method = (init && init.method) ? init.method.toUpperCase() : 'GET';
                    // Only attach for mutating requests to same-origin paths
                    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
                        init.headers = init.headers || {};
                        if (!(init.headers['X-CSRF-Token'] || init.headers['x-csrf-token'] || init.headers['X-XSRF-Token'])) {
                            init.headers['X-CSRF-Token'] = csrf;
                        }
                    }
                } catch (e) {
                    // noop
                }
                return nativeFetch(input, init);
            };
        }
    } catch (e) {
        // ignore
    }
})();
class DevConnect {
    constructor() {
        this.socket = null;
        this.messageIds = new Set();
        this.typingTimer = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeAnimations();
        this.setupFormValidation();
        this.setupChatFeatures();
        this.setupThemeToggle();
        this.setupNotifications();
    }

    // Основные обработчики событий
    setupEventListeners() {
        // Автоскрытие уведомлений
        this.autoHideAlerts();
        
        // Плавная прокрутка для якорных ссылок
        this.setupSmoothScrolling();
        
        // Обработка форм
        this.setupFormHandlers();
        
        // Интерактивные элементы
        this.setupInteractiveElements();
    }

    // Анимации и эффекты
    initializeAnimations() {
        // Добавляем анимацию появления карточек
        this.animateCards();
        
        // Эффект печатания для заголовков
        this.typewriterEffect();
        
        // Параллакс эффект для фона
        this.setupParallax();
    }

    // Валидация форм
    setupFormValidation() {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', (e) => {
                if (!this.validateForm(form)) {
                    e.preventDefault();
                }
            });
        });
    }

    // Функции чата
    setupChatFeatures() {
        if (document.getElementById('messages-container')) {
            this.initializeChat();
        }
    }

    // Переключение темы
    setupThemeToggle() {
        this.createThemeToggle();
    }

    // Уведомления
    setupNotifications() {
        this.createNotificationSystem();
    }

    // Автоскрытие уведомлений
    autoHideAlerts() {
        setTimeout(() => {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                alert.style.transition = 'opacity 0.3s ease';
                alert.style.opacity = '0';
                setTimeout(() => alert.remove(), 300);
            });
        }, 5000);
    }

    // Плавная прокрутка
    setupSmoothScrolling() {
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', (e) => {
                e.preventDefault();
                const target = document.querySelector(anchor.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    }

    // Обработчики форм
    setupFormHandlers() {
        // Форматирование номера телефона
        const phoneInput = document.getElementById('phone');
        if (phoneInput) {
            phoneInput.addEventListener('input', this.formatPhoneNumber);
        }

        // Форматирование навыков
        const skillsInput = document.getElementById('skills');
        if (skillsInput) {
            skillsInput.addEventListener('input', this.formatSkills);
        }

        // Валидация в реальном времени
        this.setupRealTimeValidation();
    }

    // Интерактивные элементы
    setupInteractiveElements() {
        // Эффект наведения на карточки пользователей
        this.setupUserCardEffects();
        
        // Эффект наведения на кнопки
        this.setupButtonEffects();
        
        // Интерактивные аватары
        this.setupAvatarEffects();
    }

    // Анимация карточек
    animateCards() {
        const cards = document.querySelectorAll('.card, .user-card');
        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry, index) => {
                if (entry.isIntersecting) {
                    setTimeout(() => {
                        entry.target.style.animationDelay = `${index * 0.1}s`;
                        entry.target.classList.add('fade-in');
                    }, index * 100);
                }
            });
        }, { threshold: 0.1 });

        cards.forEach(card => observer.observe(card));
    }

    // Эффект печатания
    typewriterEffect() {
        const typewriterElements = document.querySelectorAll('.typewriter');
        typewriterElements.forEach(element => {
            const text = element.textContent;
            element.textContent = '';
            element.style.borderRight = '2px solid #667eea';
            
            let i = 0;
            const timer = setInterval(() => {
                element.textContent += text[i];
                i++;
                if (i >= text.length) {
                    clearInterval(timer);
                    setTimeout(() => {
                        element.style.borderRight = 'none';
                    }, 1000);
                }
            }, 100);
        });
    }

    // Параллакс эффект
    setupParallax() {
        window.addEventListener('scroll', () => {
            const scrolled = window.pageYOffset;
            const parallaxElements = document.querySelectorAll('.parallax');
            
            parallaxElements.forEach(element => {
                const speed = element.dataset.speed || 0.5;
                element.style.transform = `translateY(${scrolled * speed}px)`;
            });
        });
    }

    // Валидация формы
    validateForm(form) {
        const inputs = form.querySelectorAll('input[required], textarea[required]');
        let isValid = true;

        inputs.forEach(input => {
            if (!input.value.trim()) {
                this.showFieldError(input, 'Это поле обязательно для заполнения');
                isValid = false;
            } else {
                this.clearFieldError(input);
            }

            // Специальная валидация для email
            if (input.type === 'email' && input.value) {
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(input.value)) {
                    this.showFieldError(input, 'Введите корректный email адрес');
                    isValid = false;
                }
            }

            // Валидация пароля
            if (input.type === 'password' && input.value.length < 6) {
                this.showFieldError(input, 'Пароль должен содержать минимум 6 символов');
                isValid = false;
            }
        });

        return isValid;
    }

    // Валидация в реальном времени
    setupRealTimeValidation() {
        const inputs = document.querySelectorAll('input, textarea');
        inputs.forEach(input => {
            input.addEventListener('blur', () => {
                this.validateField(input);
            });

            input.addEventListener('input', () => {
                this.clearFieldError(input);
            });
        });
    }

    // Валидация отдельного поля
    validateField(field) {
        if (field.hasAttribute('required') && !field.value.trim()) {
            this.showFieldError(field, 'Это поле обязательно для заполнения');
            return false;
        }

        if (field.type === 'email' && field.value) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(field.value)) {
                this.showFieldError(field, 'Введите корректный email адрес');
                return false;
            }
        }

        this.clearFieldError(field);
        return true;
    }

    // Показать ошибку поля
    showFieldError(field, message) {
        this.clearFieldError(field);
        field.style.borderColor = '#dc3545';
        
        const errorDiv = document.createElement('div');
        errorDiv.className = 'field-error';
        errorDiv.textContent = message;
        errorDiv.style.color = '#dc3545';
        errorDiv.style.fontSize = '0.8rem';
        errorDiv.style.marginTop = '0.25rem';
        
        field.parentNode.appendChild(errorDiv);
    }

    // Очистить ошибку поля
    clearFieldError(field) {
        field.style.borderColor = '';
        const errorDiv = field.parentNode.querySelector('.field-error');
        if (errorDiv) {
            errorDiv.remove();
        }
    }

    // Форматирование номера телефона
    formatPhoneNumber(e) {
        let value = e.target.value.replace(/\D/g, '');
        if (value.length > 0) {
            if (value[0] === '8') {
                value = '7' + value.slice(1);
            }
            if (value[0] === '7') {
                value = '+7 (' + value.slice(1, 4) + ') ' + value.slice(4, 7) + '-' + value.slice(7, 9) + '-' + value.slice(9, 11);
            }
        }
        e.target.value = value;
    }

    // Форматирование навыков
    formatSkills(e) {
        let value = e.target.value;
        value = value.replace(/\s*,\s*/g, ', ').replace(/,+/g, ',');
        e.target.value = value;
    }

    // Эффекты карточек пользователей
    setupUserCardEffects() {
        const userCards = document.querySelectorAll('.user-card');
        userCards.forEach(card => {
            card.addEventListener('mouseenter', () => {
                card.style.transform = 'translateY(-8px) scale(1.02)';
            });

            card.addEventListener('mouseleave', () => {
                card.style.transform = 'translateY(0) scale(1)';
            });
        });
    }

    // Эффекты кнопок
    setupButtonEffects() {
        const buttons = document.querySelectorAll('.btn');
        buttons.forEach(button => {
            button.addEventListener('mouseenter', () => {
                button.style.transform = 'translateY(-2px)';
            });

            button.addEventListener('mouseleave', () => {
                button.style.transform = 'translateY(0)';
            });
        });
    }

    // Эффекты аватаров
    setupAvatarEffects() {
        const avatars = document.querySelectorAll('.user-avatar');
        avatars.forEach(avatar => {
            avatar.addEventListener('mouseenter', () => {
                avatar.style.transform = 'scale(1.1) rotate(5deg)';
            });

            avatar.addEventListener('mouseleave', () => {
                avatar.style.transform = 'scale(1) rotate(0deg)';
            });
        });
    }

    // Инициализация чата
    initializeChat() {
        const messagesContainer = document.getElementById('messages-container');
        const messageForm = document.getElementById('message-form');
        const messageInput = document.getElementById('message-input');
        const chatId = document.getElementById('chat-id')?.value;
        const root = document.querySelector('[data-user-id]');
        const username = root?.dataset.username;

        if (!chatId) return;

        // Автопрокрутка к последнему сообщению
        this.scrollToBottom(messagesContainer);

        // Анимация только при входе в чат: однократно анимируем уже существующие сообщения,
        // не затрагивая будущие добавления через сокеты/пуллинг
        this.animateInitialMessages(messagesContainer);

        // Автоизменение высоты textarea
        if (messageInput && messageInput.tagName.toLowerCase() === 'textarea') {
            const autoResize = () => {
                const min = 44; // px
                messageInput.style.height = 'auto';
                const h = Math.max(messageInput.scrollHeight, min);
                messageInput.style.height = h + 'px';
            };
            autoResize();
            messageInput.addEventListener('input', autoResize);
        }

        // Отправка сообщения
        if (messageForm) {
            messageForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.sendMessage(chatId, messageInput.value.trim());
            });
        }

        // Обработка Enter
        if (messageInput) {
            messageInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    messageForm.dispatchEvent(new Event('submit'));
                }
            });

            // Эмитим "печатает" при вводе
            const emitTyping = this.throttle(() => {
                if (this.socket && username) {
                    this.socket.emit('typing', { chat_id: parseInt(chatId), username });
                }
            }, 1000);
            messageInput.addEventListener('input', emitTyping);
        }

        // Автообновление сообщений
        this.startMessagePolling(chatId);

        // Подключение Socket.IO
        if (window.io) {
            try {
                this.socket = window.io({ transports: ['websocket', 'polling'] });
                // Вступаем в комнату чата
                this.socket.emit('join', { chat_id: parseInt(chatId) });

                // Получаем новые сообщения в реальном времени
                this.socket.on('message:new', (msg) => {
                    if (!msg || typeof msg.id === 'undefined') return;
                    if (this.messageIds.has(msg.id)) return;
                    this.messageIds.add(msg.id);
                    this.addMessageToChat(msg);
                    if (messagesContainer) this.scrollToBottom(messagesContainer);
                });

                // Индикатор набора
                const typingEl = document.getElementById('typing-indicator');
                this.socket.on('typing', (data) => {
                    if (!typingEl || !data || !data.username) return;
                    typingEl.textContent = `${data.username} печатает...`;
                    typingEl.style.display = 'block';
                    clearTimeout(this.typingTimer);
                    this.typingTimer = setTimeout(() => {
                        typingEl.style.display = 'none';
                    }, 2000);
                });

                // Покидаем комнату при закрытии
                window.addEventListener('beforeunload', () => {
                    try { this.socket.emit('leave', { chat_id: parseInt(chatId) }); } catch (_) {}
                });
            } catch (e) {
                console.warn('Socket.IO connection failed, fallback to polling only');
            }
        }
    }

    // Отправка сообщения
    async sendMessage(chatId, content) {
        if (!content) return;

        try {
            const response = await fetch('/send_message', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    chat_id: parseInt(chatId),
                    content: content
                })
            });

            if (!response.ok) {
                this.showNotification('Ошибка отправки сообщения', 'error');
                return;
            }

            const data = await response.json();
            if (data.status === 'success') {
                const input = document.getElementById('message-input');
                if (input) {
                    input.value = '';
                    // Сброс высоты textarea и пересчет
                    if (input.tagName.toLowerCase() === 'textarea') {
                        input.style.height = 'auto';
                        input.dispatchEvent(new Event('input'));
                    }
                }
                // Если бэкенд вернул массив сообщений (пользователь + AI), добавляем оба
                if (Array.isArray(data.messages)) {
                    data.messages.forEach(m => this.addMessageToChat(m));
                } else if (data.message) {
                    // fallback: только отправленное сообщение
                    this.addMessageToChat(data.message);
                }
                // Прокрутка вниз
                const messagesContainer = document.getElementById('messages-container');
                if (messagesContainer) this.scrollToBottom(messagesContainer);
            }
        } catch (error) {
            console.error('Error sending message:', error);
            this.showNotification('Ошибка отправки сообщения', 'error');
        }
    }

    // Загрузка сообщений
    async loadMessages(chatId) {
        try {
            const response = await fetch(`/get_messages/${chatId}`);
            const messages = await response.json();
            
            const messagesContainer = document.getElementById('messages-container');
            messagesContainer.innerHTML = '';
            // Полный ререндер: сбрасываем множество, чтобы не мешало отрисовке
            this.messageIds = new Set();
            
            messages.forEach(msg => {
                // Во время периодической подгрузки НЕ анимируем
                this.addMessageToChat(msg, /*skipDedup*/ true, /*animate*/ false);
            });
            
            this.scrollToBottom(messagesContainer);
        } catch (error) {
            console.error('Error loading messages:', error);
        }
    }

    // Добавление сообщения в чат
    addMessageToChat(message, skipDedup = false, animate = false) {
        const messagesContainer = document.getElementById('messages-container');
        const isOwn = message.sender_id === parseInt(document.querySelector('[data-user-id]')?.dataset.userId || 0);
        
        if (!skipDedup && typeof message.id !== 'undefined') {
            if (this.messageIds.has(message.id)) return;
            this.messageIds.add(message.id);
        }

        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${isOwn ? 'own' : ''}`;
        messageDiv.innerHTML = `
            <div class="message-content">
                ${this.escapeHtml(message.content)}
                <div class="message-time">${message.timestamp}</div>
            </div>
        `;
        if (animate) {
            messageDiv.classList.add('msg-appear');
        }
        messagesContainer.appendChild(messageDiv);
    }

    // Одноразовая анимация сообщений при загрузке страницы чата
    animateInitialMessages(messagesContainer) {
        if (!messagesContainer) return;
        if (messagesContainer.dataset.initialAnimated === '1') return;
        messagesContainer.dataset.initialAnimated = '1';

        const items = Array.from(messagesContainer.querySelectorAll('.message'));
        items.forEach((el, idx) => {
            // Стагерим анимацию для приятного эффекта входа
            setTimeout(() => {
                el.classList.add('msg-appear');
                // Убираем класс после завершения, чтобы повторно не анимировалось
                setTimeout(() => el.classList.remove('msg-appear'), 500);
            }, idx * 40);
        });
    }

    // Прокрутка к низу
    scrollToBottom(container) {
        container.scrollTop = container.scrollHeight;
    }

    // Автообновление сообщений
    startMessagePolling(chatId) {
        setInterval(() => {
            this.loadMessages(chatId);
        }, 3000);
    }

    // Создание переключателя темы
    createThemeToggle() {
        const themeToggle = document.createElement('button');
        themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
        themeToggle.className = 'btn btn-primary theme-toggle';
        themeToggle.style.position = 'fixed';
        themeToggle.style.bottom = '20px';
        themeToggle.style.right = '20px';
        themeToggle.style.zIndex = '1000';
        themeToggle.style.borderRadius = '50%';
        themeToggle.style.width = '50px';
        themeToggle.style.height = '50px';

        themeToggle.addEventListener('click', () => {
            document.body.classList.toggle('dark-theme');
            const isDark = document.body.classList.contains('dark-theme');
            themeToggle.innerHTML = isDark ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
        });

        // Загрузка сохраненной темы
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            document.body.classList.add('dark-theme');
            themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
        }

        document.body.appendChild(themeToggle);
    }

    // Система уведомлений
    createNotificationSystem() {
        const notificationContainer = document.createElement('div');
        notificationContainer.id = 'notification-container';
        notificationContainer.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            max-width: 300px;
        `;
        document.body.appendChild(notificationContainer);
    }

    // Показать уведомление
    showNotification(message, type = 'info') {
        const container = document.getElementById('notification-container');
        const notification = document.createElement('div');
        
        const colors = {
            success: '#28a745',
            error: '#dc3545',
            warning: '#ffc107',
            info: '#17a2b8'
        };

        notification.style.cssText = `
            background: ${colors[type] || colors.info};
            color: white;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 0.5rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            animation: slideInRight 0.3s ease-out;
        `;
        
        notification.textContent = message;
        container.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    // Экранирование HTML
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Throttle helper
    throttle(fn, wait) {
        let last = 0;
        let timeout;
        return (...args) => {
            const now = Date.now();
            const remaining = wait - (now - last);
            if (remaining <= 0) {
                last = now;
                fn.apply(this, args);
            } else {
                clearTimeout(timeout);
                timeout = setTimeout(() => {
                    last = Date.now();
                    fn.apply(this, args);
                }, remaining);
            }
        };
    }
}

// Дополнительные CSS анимации
const additionalStyles = `
@keyframes slideInRight {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

@keyframes slideOutRight {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
}

.dark-theme {
    --text-primary: #f0f6fc;
    --text-secondary: #8b949e;
    --card-background: rgba(13, 17, 23, 0.95);
    --card-border: rgba(255, 255, 255, 0.1);
}

.dark-theme .form-control {
    background: rgba(13, 17, 23, 0.8);
    border-color: rgba(255, 255, 255, 0.2);
    color: var(--text-primary);
}

.dark-theme .chat-sidebar {
    background: rgba(13, 17, 23, 0.8);
}

.dark-theme .chat-header {
    background: rgba(13, 17, 23, 0.9);
}

.dark-theme .chat-input {
    background: rgba(13, 17, 23, 0.9);
}

.field-error {
    animation: slideIn 0.3s ease-out;
}

@keyframes msgIn {
    from { transform: translateY(8px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
}

.message.msg-appear .message-content {
    animation: msgIn 0.35s ease-out both;
}
`;

// Добавляем дополнительные стили
const styleSheet = document.createElement('style');
styleSheet.textContent = additionalStyles;
document.head.appendChild(styleSheet);

// Инициализация приложения
document.addEventListener('DOMContentLoaded', () => {
    new DevConnect();
});

// Экспорт для использования в других модулях
window.DevConnect = DevConnect;

// Глобальная функция переключения темы
window.toggleTheme = function() {
    document.body.classList.toggle('dark-theme');
    const isDark = document.body.classList.contains('dark-theme');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
    
    // Обновляем иконку переключателя темы
    const themeToggle = document.querySelector('.theme-toggle');
    if (themeToggle) {
        themeToggle.innerHTML = isDark ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
    }
    
    // Показываем уведомление
    if (window.NotificationManager) {
        window.NotificationManager.instance.show(
            isDark ? 'Темная тема включена' : 'Светлая тема включена', 
            'info'
        );
    }
};
