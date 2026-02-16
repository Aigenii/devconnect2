// DevConnect - Дополнительные утилиты и эффекты

// Утилиты для работы с DOM
const DOMUtils = {
    // Создание элемента с атрибутами
    createElement(tag, attributes = {}, content = '') {
        const element = document.createElement(tag);
        Object.assign(element, attributes);
        if (content) element.innerHTML = content;
        return element;
    },

    // Добавление класса с анимацией
    addClassWithAnimation(element, className, duration = 300) {
        element.classList.add(className);
        setTimeout(() => {
            element.classList.remove(className);
        }, duration);
    },

    // Плавное появление элемента
    fadeIn(element, duration = 300) {
        element.style.opacity = '0';
        element.style.display = 'block';
        
        let opacity = 0;
        const timer = setInterval(() => {
            opacity += 0.1;
            element.style.opacity = opacity;
            if (opacity >= 1) {
                clearInterval(timer);
            }
        }, duration / 10);
    },

    // Плавное исчезновение элемента
    fadeOut(element, duration = 300) {
        let opacity = 1;
        const timer = setInterval(() => {
            opacity -= 0.1;
            element.style.opacity = opacity;
            if (opacity <= 0) {
                clearInterval(timer);
                element.style.display = 'none';
            }
        }, duration / 10);
    },

    // Прокрутка к элементу
    scrollToElement(element, offset = 0) {
        const elementPosition = element.getBoundingClientRect().top;
        const offsetPosition = elementPosition + window.pageYOffset - offset;
        
        window.scrollTo({
            top: offsetPosition,
            behavior: 'smooth'
        });
    }
};

// Утилиты для работы с анимациями
const AnimationUtils = {
    // Запуск анимации при появлении в viewport
    observeElements(selector, animationClass, threshold = 0.1) {
        const elements = document.querySelectorAll(selector);
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add(animationClass);
                }
            });
        }, { threshold });

        elements.forEach(element => observer.observe(element));
    },

    // Создание эффекта печатания
    typewriter(element, text, speed = 100) {
        element.textContent = '';
        let i = 0;
        const timer = setInterval(() => {
            element.textContent += text[i];
            i++;
            if (i >= text.length) {
                clearInterval(timer);
            }
        }, speed);
    },

    // Создание эффекта частиц
    createParticles(container, count = 50) {
        for (let i = 0; i < count; i++) {
            const particle = DOMUtils.createElement('div', {
                className: 'particle',
                style: `
                    position: absolute;
                    width: 2px;
                    height: 2px;
                    background: rgba(102, 126, 234, 0.5);
                    border-radius: 50%;
                    left: ${Math.random() * 100}%;
                    top: ${Math.random() * 100}%;
                    animation: float ${2 + Math.random() * 3}s ease-in-out infinite;
                `
            });
            container.appendChild(particle);
        }
    },

    // Создание эффекта волн
    createWaveEffect(element) {
        element.addEventListener('click', (e) => {
            const wave = DOMUtils.createElement('div', {
                className: 'wave',
                style: `
                    position: absolute;
                    border-radius: 50%;
                    background: rgba(102, 126, 234, 0.3);
                    transform: scale(0);
                    animation: waveExpand 0.6s ease-out;
                    pointer-events: none;
                `
            });

            const rect = element.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            wave.style.width = wave.style.height = size + 'px';
            wave.style.left = (e.clientX - rect.left - size / 2) + 'px';
            wave.style.top = (e.clientY - rect.top - size / 2) + 'px';

            element.style.position = 'relative';
            element.appendChild(wave);

            setTimeout(() => wave.remove(), 600);
        });
    }
};

// Утилиты для работы с формами
const FormUtils = {
    // Валидация email
    validateEmail(email) {
        const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return regex.test(email);
    },

    // Валидация пароля
    validatePassword(password) {
        return password.length >= 6;
    },

    // Форматирование номера телефона
    formatPhoneNumber(input) {
        let value = input.value.replace(/\D/g, '');
        if (value.length > 0) {
            if (value[0] === '8') {
                value = '7' + value.slice(1);
            }
            if (value[0] === '7') {
                value = '+7 (' + value.slice(1, 4) + ') ' + value.slice(4, 7) + '-' + value.slice(7, 9) + '-' + value.slice(9, 11);
            }
        }
        input.value = value;
    },

    // Создание индикатора силы пароля
    createPasswordStrengthIndicator(input) {
        const indicator = DOMUtils.createElement('div', {
            className: 'password-strength',
            style: `
                margin-top: 0.5rem;
                height: 4px;
                background: #e1e5e9;
                border-radius: 2px;
                overflow: hidden;
            `
        });

        const strengthBar = DOMUtils.createElement('div', {
            className: 'strength-bar',
            style: `
                height: 100%;
                width: 0%;
                background: #dc3545;
                transition: all 0.3s ease;
            `
        });

        indicator.appendChild(strengthBar);
        input.parentNode.appendChild(indicator);

        input.addEventListener('input', () => {
            const password = input.value;
            let strength = 0;
            let color = '#dc3545';

            if (password.length >= 6) strength += 25;
            if (password.match(/[a-z]/)) strength += 25;
            if (password.match(/[A-Z]/)) strength += 25;
            if (password.match(/[0-9]/)) strength += 25;

            if (strength >= 50) color = '#ffc107';
            if (strength >= 75) color = '#28a745';

            strengthBar.style.width = strength + '%';
            strengthBar.style.background = color;
        });
    }
};

// Утилиты для работы с уведомлениями
const NotificationUtils = {
    // Создание toast уведомления
    createToast(message, type = 'info', duration = 3000) {
        const container = document.getElementById('notification-container') || this.createContainer();
        
        const toast = DOMUtils.createElement('div', {
            className: `toast toast-${type}`,
            style: `
                background: ${this.getToastColor(type)};
                color: white;
                padding: 1rem 1.5rem;
                border-radius: 8px;
                margin-bottom: 0.5rem;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                animation: slideInRight 0.3s ease-out;
                display: flex;
                align-items: center;
                gap: 0.5rem;
                max-width: 300px;
            `
        }, `
            <i class="fas ${this.getToastIcon(type)}"></i>
            <span>${message}</span>
            <button onclick="this.parentElement.remove()" style="margin-left: auto; background: none; border: none; color: white; cursor: pointer;">
                <i class="fas fa-times"></i>
            </button>
        `);

        container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },

    // Создание контейнера для уведомлений
    createContainer() {
        const container = DOMUtils.createElement('div', {
            id: 'notification-container',
            style: `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                max-width: 300px;
            `
        });
        document.body.appendChild(container);
        return container;
    },

    // Получение цвета для типа уведомления
    getToastColor(type) {
        const colors = {
            success: '#28a745',
            error: '#dc3545',
            warning: '#ffc107',
            info: '#17a2b8'
        };
        return colors[type] || colors.info;
    },

    // Получение иконки для типа уведомления
    getToastIcon(type) {
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        return icons[type] || icons.info;
    }
};

// Утилиты для работы с локальным хранилищем
const StorageUtils = {
    // Сохранение данных
    save(key, data) {
        try {
            localStorage.setItem(key, JSON.stringify(data));
            return true;
        } catch (error) {
            console.error('Error saving to localStorage:', error);
            return false;
        }
    },

    // Загрузка данных
    load(key, defaultValue = null) {
        try {
            const data = localStorage.getItem(key);
            return data ? JSON.parse(data) : defaultValue;
        } catch (error) {
            console.error('Error loading from localStorage:', error);
            return defaultValue;
        }
    },

    // Удаление данных
    remove(key) {
        try {
            localStorage.removeItem(key);
            return true;
        } catch (error) {
            console.error('Error removing from localStorage:', error);
            return false;
        }
    }
};

// Утилиты для работы с API
const APIUtils = {
    // Базовый запрос
    async request(url, options = {}) {
        try {
            const response = await fetch(url, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    },

    // GET запрос
    async get(url) {
        return this.request(url, { method: 'GET' });
    },

    // POST запрос
    async post(url, data) {
        return this.request(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },

    // PUT запрос
    async put(url, data) {
        return this.request(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    },

    // DELETE запрос
    async delete(url) {
        return this.request(url, { method: 'DELETE' });
    }
};

// Утилиты для работы с датами
const DateUtils = {
    // Форматирование даты
    formatDate(date, format = 'dd.mm.yyyy') {
        const d = new Date(date);
        const day = String(d.getDate()).padStart(2, '0');
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const year = d.getFullYear();
        const hours = String(d.getHours()).padStart(2, '0');
        const minutes = String(d.getMinutes()).padStart(2, '0');

        return format
            .replace('dd', day)
            .replace('mm', month)
            .replace('yyyy', year)
            .replace('hh', hours)
            .replace('mm', minutes);
    },

    // Относительное время
    getRelativeTime(date) {
        const now = new Date();
        const diff = now - new Date(date);
        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (days > 0) return `${days} дн. назад`;
        if (hours > 0) return `${hours} ч. назад`;
        if (minutes > 0) return `${minutes} мин. назад`;
        return 'только что';
    }
};

// Экспорт утилит в глобальную область видимости
window.DOMUtils = DOMUtils;
window.AnimationUtils = AnimationUtils;
window.FormUtils = FormUtils;
window.NotificationUtils = NotificationUtils;
window.StorageUtils = StorageUtils;
window.APIUtils = APIUtils;
window.DateUtils = DateUtils;
