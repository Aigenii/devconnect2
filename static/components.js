// DevConnect - Демонстрационные компоненты

// Компонент модального окна
class Modal {
    constructor(options = {}) {
        this.options = {
            title: 'Модальное окно',
            content: '',
            size: 'medium',
            closable: true,
            ...options
        };
        
        this.element = null;
        this.isOpen = false;
    }
    
    create() {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-backdrop"></div>
            <div class="modal-content modal-${this.options.size}">
                <div class="modal-header">
                    <h3 class="modal-title">${this.options.title}</h3>
                    ${this.options.closable ? '<button class="modal-close">&times;</button>' : ''}
                </div>
                <div class="modal-body">
                    ${this.options.content}
                </div>
            </div>
        `;
        
        this.element = modal;
        this.setupEventListeners();
        return modal;
    }
    
    setupEventListeners() {
        const closeBtn = this.element.querySelector('.modal-close');
        const backdrop = this.element.querySelector('.modal-backdrop');
        
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.close());
        }
        
        if (backdrop) {
            backdrop.addEventListener('click', () => this.close());
        }
        
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isOpen) {
                this.close();
            }
        });
    }
    
    open() {
        if (!this.element) {
            this.create();
        }
        
        document.body.appendChild(this.element);
        this.isOpen = true;
        
        // Фокус на модальном окне
        const firstInput = this.element.querySelector('input, button');
        if (firstInput) {
            firstInput.focus();
        }
    }
    
    close() {
        if (this.element && this.isOpen) {
            this.element.style.animation = 'fadeOut 0.3s ease-out';
            setTimeout(() => {
                this.element.remove();
                this.isOpen = false;
            }, 300);
        }
    }
    
    updateContent(content) {
        if (this.element) {
            const body = this.element.querySelector('.modal-body');
            if (body) {
                body.innerHTML = content;
            }
        }
    }
}

// Компонент уведомлений
class NotificationManager {
    constructor() {
        this.container = this.createContainer();
        this.notifications = new Map();
    }
    
    createContainer() {
        let container = document.getElementById('notification-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'notification-container';
            container.className = 'notification-container';
            document.body.appendChild(container);
        }
        return container;
    }
    
    show(message, type = 'info', duration = 3000) {
        const id = Date.now() + Math.random();
        const notification = this.createNotification(id, message, type, duration);
        
        this.container.appendChild(notification);
        this.notifications.set(id, notification);
        
        // Автоудаление
        setTimeout(() => {
            this.remove(id);
        }, duration);
        
        return id;
    }
    
    createNotification(id, message, type, duration) {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <div class="notification-icon">
                <i class="fas ${this.getIcon(type)}"></i>
            </div>
            <div class="notification-content">
                <div class="notification-message">${message}</div>
            </div>
            <button class="notification-close" onclick="NotificationManager.instance.remove(${id})">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        return notification;
    }
    
    getIcon(type) {
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        return icons[type] || icons.info;
    }
    
    remove(id) {
        const notification = this.notifications.get(id);
        if (notification) {
            notification.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => {
                notification.remove();
                this.notifications.delete(id);
            }, 300);
        }
    }
    
    clear() {
        this.notifications.forEach((notification, id) => {
            this.remove(id);
        });
    }
}

// Компонент загрузчика
class LoadingSpinner {
    constructor(options = {}) {
        this.options = {
            size: 'medium',
            color: 'primary',
            text: '',
            ...options
        };
        
        this.element = null;
    }
    
    create() {
        const spinner = document.createElement('div');
        spinner.className = `loading-spinner loading-${this.options.size} loading-${this.options.color}`;
        
        if (this.options.text) {
            spinner.innerHTML = `
                <div class="spinner-icon"></div>
                <div class="spinner-text">${this.options.text}</div>
            `;
        } else {
            spinner.innerHTML = '<div class="spinner-icon"></div>';
        }
        
        this.element = spinner;
        return spinner;
    }
    
    show(container = document.body) {
        if (!this.element) {
            this.create();
        }
        
        container.appendChild(this.element);
    }
    
    hide() {
        if (this.element) {
            this.element.remove();
        }
    }
}

// Компонент прогресс-бара
class ProgressBar {
    constructor(options = {}) {
        this.options = {
            value: 0,
            max: 100,
            showPercentage: true,
            animated: true,
            ...options
        };
        
        this.element = null;
    }
    
    create() {
        const progressBar = document.createElement('div');
        progressBar.className = 'progress-bar-container';
        progressBar.innerHTML = `
            <div class="progress-bar">
                <div class="progress-fill" style="width: ${this.options.value}%"></div>
            </div>
            ${this.options.showPercentage ? '<div class="progress-text">0%</div>' : ''}
        `;
        
        this.element = progressBar;
        return progressBar;
    }
    
    update(value) {
        if (!this.element) return;
        
        const fill = this.element.querySelector('.progress-fill');
        const text = this.element.querySelector('.progress-text');
        
        if (fill) {
            fill.style.width = `${value}%`;
        }
        
        if (text) {
            text.textContent = `${Math.round(value)}%`;
        }
    }
    
    show(container = document.body) {
        if (!this.element) {
            this.create();
        }
        
        container.appendChild(this.element);
    }
    
    hide() {
        if (this.element) {
            this.element.remove();
        }
    }
}

// Компонент табов
class Tabs {
    constructor(container, options = {}) {
        this.container = container;
        this.options = {
            activeTab: 0,
            ...options
        };
        
        this.tabs = [];
        this.panels = [];
        this.init();
    }
    
    init() {
        const tabElements = this.container.querySelectorAll('[data-tab]');
        const panelElements = this.container.querySelectorAll('[data-panel]');
        
        tabElements.forEach((tab, index) => {
            this.tabs.push(tab);
            tab.addEventListener('click', () => this.activateTab(index));
        });
        
        panelElements.forEach(panel => {
            this.panels.push(panel);
        });
        
        this.activateTab(this.options.activeTab);
    }
    
    activateTab(index) {
        // Деактивируем все табы
        this.tabs.forEach(tab => tab.classList.remove('active'));
        this.panels.forEach(panel => panel.classList.remove('active'));
        
        // Активируем выбранный таб
        if (this.tabs[index]) {
            this.tabs[index].classList.add('active');
        }
        
        if (this.panels[index]) {
            this.panels[index].classList.add('active');
        }
    }
}

// Компонент аккордеона
class Accordion {
    constructor(container, options = {}) {
        this.container = container;
        this.options = {
            multiple: false,
            ...options
        };
        
        this.items = [];
        this.init();
    }
    
    init() {
        const items = this.container.querySelectorAll('.accordion-item');
        
        items.forEach((item, index) => {
            this.items.push(item);
            
            const header = item.querySelector('.accordion-header');
            const content = item.querySelector('.accordion-content');
            
            if (header && content) {
                header.addEventListener('click', () => this.toggleItem(index));
            }
        });
    }
    
    toggleItem(index) {
        const item = this.items[index];
        const content = item.querySelector('.accordion-content');
        
        if (item.classList.contains('active')) {
            this.closeItem(index);
        } else {
            if (!this.options.multiple) {
                this.closeAllItems();
            }
            this.openItem(index);
        }
    }
    
    openItem(index) {
        const item = this.items[index];
        const content = item.querySelector('.accordion-content');
        
        item.classList.add('active');
        content.style.maxHeight = content.scrollHeight + 'px';
    }
    
    closeItem(index) {
        const item = this.items[index];
        const content = item.querySelector('.accordion-content');
        
        item.classList.remove('active');
        content.style.maxHeight = '0';
    }
    
    closeAllItems() {
        this.items.forEach((item, index) => {
            this.closeItem(index);
        });
    }
}

// Компонент слайдера
class Slider {
    constructor(container, options = {}) {
        this.container = container;
        this.options = {
            autoplay: false,
            interval: 3000,
            ...options
        };
        
        this.slides = [];
        this.currentSlide = 0;
        this.init();
    }
    
    init() {
        this.slides = Array.from(this.container.querySelectorAll('.slide'));
        
        if (this.slides.length > 0) {
            this.showSlide(0);
            
            if (this.options.autoplay) {
                this.startAutoplay();
            }
        }
    }
    
    showSlide(index) {
        this.slides.forEach((slide, i) => {
            slide.classList.toggle('active', i === index);
        });
        
        this.currentSlide = index;
    }
    
    nextSlide() {
        const nextIndex = (this.currentSlide + 1) % this.slides.length;
        this.showSlide(nextIndex);
    }
    
    prevSlide() {
        const prevIndex = (this.currentSlide - 1 + this.slides.length) % this.slides.length;
        this.showSlide(prevIndex);
    }
    
    startAutoplay() {
        this.autoplayInterval = setInterval(() => {
            this.nextSlide();
        }, this.options.interval);
    }
    
    stopAutoplay() {
        if (this.autoplayInterval) {
            clearInterval(this.autoplayInterval);
        }
    }
}

// Создание экземпляров компонентов
const modal = new Modal();
const notificationManager = new NotificationManager();
const loadingSpinner = new LoadingSpinner();

// Экспорт компонентов
window.Modal = Modal;
window.NotificationManager = NotificationManager;
window.LoadingSpinner = LoadingSpinner;
window.ProgressBar = ProgressBar;
window.Tabs = Tabs;
window.Accordion = Accordion;
window.Slider = Slider;

// Создание глобального экземпляра менеджера уведомлений
NotificationManager.instance = notificationManager;

// Демонстрационные функции
window.showDemoModal = function() {
    const modal = new Modal({
        title: 'Демонстрационное модальное окно',
        content: `
            <p>Это демонстрационное модальное окно с красивыми эффектами!</p>
            <div style="margin-top: 1rem;">
                <button class="btn btn-primary" onclick="NotificationManager.instance.show('Уведомление показано!', 'success')">
                    Показать уведомление
                </button>
            </div>
        `,
        size: 'medium'
    });
    
    modal.open();
};

window.showDemoNotification = function(type = 'info') {
    const messages = {
        success: 'Операция выполнена успешно!',
        error: 'Произошла ошибка!',
        warning: 'Внимание! Проверьте данные.',
        info: 'Информационное сообщение.'
    };
    
    NotificationManager.instance.show(messages[type], type);
};

window.showDemoLoading = function() {
    const spinner = new LoadingSpinner({
        text: 'Загрузка...',
        size: 'large'
    });
    
    spinner.show();
    
    setTimeout(() => {
        spinner.hide();
        NotificationManager.instance.show('Загрузка завершена!', 'success');
    }, 3000);
};

// Автоинициализация компонентов при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
    // Инициализация табов
    const tabContainers = document.querySelectorAll('.tabs-container');
    tabContainers.forEach(container => {
        new Tabs(container);
    });
    
    // Инициализация аккордеонов
    const accordionContainers = document.querySelectorAll('.accordion-container');
    accordionContainers.forEach(container => {
        new Accordion(container);
    });
    
    // Инициализация слайдеров
    const sliderContainers = document.querySelectorAll('.slider-container');
    sliderContainers.forEach(container => {
        new Slider(container, { autoplay: true });
    });
});
