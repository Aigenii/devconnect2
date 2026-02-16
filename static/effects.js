// DevConnect - Демонстрационные эффекты и интерактивность

// Демонстрация эффектов при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
    // Инициализация всех эффектов
    initializeEffects();
    
    // Запуск демонстрационных анимаций
    startDemoAnimations();
    
    // Настройка интерактивных элементов
    setupInteractiveElements();
});

// Инициализация эффектов
function initializeEffects() {
    // Добавляем эффекты к карточкам пользователей
    addUserCardEffects();
    
    // Добавляем эффекты к кнопкам
    addButtonEffects();
    
    // Добавляем эффекты к формам
    addFormEffects();
    
    // Добавляем эффекты к навигации
    addNavigationEffects();
    
    // Добавляем эффекты к чатам
    addChatEffects();
}

// Эффекты для карточек пользователей
function addUserCardEffects() {
    const userCards = document.querySelectorAll('.user-card');
    
    userCards.forEach(card => {
        // Добавляем эффект магнитного притяжения
        card.classList.add('card-magnetic');
        
        // Добавляем эффект частиц при наведении
        card.addEventListener('mouseenter', () => {
            createParticleEffect(card);
        });
        
        // Добавляем эффект волн при клике
        AnimationUtils.createWaveEffect(card);
        
        // Добавляем эффект свечения
        card.addEventListener('mouseenter', () => {
            card.classList.add('animate-glow');
        });
        
        card.addEventListener('mouseleave', () => {
            card.classList.remove('animate-glow');
        });
    });
}

// Эффекты для кнопок
function addButtonEffects() {
    const buttons = document.querySelectorAll('.btn');
    
    buttons.forEach(button => {
        // Добавляем эффект ripple
        button.classList.add('btn-ripple');
        
        // Добавляем эффект магнитного притяжения
        button.addEventListener('mouseenter', () => {
            button.style.transform = 'translateY(-4px) scale(1.05)';
        });
        
        button.addEventListener('mouseleave', () => {
            button.style.transform = 'translateY(0) scale(1)';
        });
        
        // Добавляем эффект пульсации при фокусе
        button.addEventListener('focus', () => {
            button.classList.add('animate-pulse');
        });
        
        button.addEventListener('blur', () => {
            button.classList.remove('animate-pulse');
        });
    });
}

// Эффекты для форм
function addFormEffects() {
    const inputs = document.querySelectorAll('.form-control');
    
    inputs.forEach(input => {
        // Добавляем эффект фокуса
        input.classList.add('input-focus');
        
        // Добавляем эффект печатания для текстовых полей
        if (input.type === 'text' || input.type === 'email') {
            input.addEventListener('input', () => {
                if (input.value.length > 0) {
                    input.style.borderColor = '#28a745';
                } else {
                    input.style.borderColor = '';
                }
            });
        }
        
        // Добавляем индикатор силы пароля
        if (input.type === 'password') {
            FormUtils.createPasswordStrengthIndicator(input);
        }
        
        // Добавляем эффект валидации в реальном времени
        input.addEventListener('blur', () => {
            validateInput(input);
        });
    });
}

// Эффекты для навигации
function addNavigationEffects() {
    const navLinks = document.querySelectorAll('.nav a');
    
    navLinks.forEach(link => {
        link.classList.add('nav-link');
        
        // Добавляем эффект активной ссылки
        if (link.href === window.location.href) {
            link.classList.add('active');
        }
        
        // Добавляем эффект наведения
        link.addEventListener('mouseenter', () => {
            link.style.transform = 'translateY(-2px)';
        });
        
        link.addEventListener('mouseleave', () => {
            link.style.transform = 'translateY(0)';
        });
    });
}

// Эффекты для чатов
function addChatEffects() {
    const chatContainer = document.querySelector('.chat-container');
    if (!chatContainer) return;
    
    // Добавляем эффект частиц в фон чата
    chatContainer.classList.add('particles');
    
    // Добавляем эффект стекла
    chatContainer.classList.add('glass-effect');
    
    // Добавляем кастомный скроллбар
    const chatMessages = document.querySelector('.chat-messages');
    if (chatMessages) {
        chatMessages.classList.add('custom-scrollbar');
    }
    
    const chatSidebar = document.querySelector('.chat-sidebar');
    if (chatSidebar) {
        chatSidebar.classList.add('custom-scrollbar');
    }
}

// Создание эффекта частиц
function createParticleEffect(element) {
    const rect = element.getBoundingClientRect();
    const particleCount = 10;
    
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.cssText = `
            position: fixed;
            width: 4px;
            height: 4px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 50%;
            pointer-events: none;
            z-index: 1000;
            left: ${rect.left + Math.random() * rect.width}px;
            top: ${rect.top + Math.random() * rect.height}px;
            animation: particleFloat ${1 + Math.random() * 2}s ease-out forwards;
        `;
        
        document.body.appendChild(particle);
        
        setTimeout(() => {
            particle.remove();
        }, 3000);
    }
}

// Валидация инпута
function validateInput(input) {
    const value = input.value.trim();
    let isValid = true;
    let message = '';
    
    if (input.hasAttribute('required') && !value) {
        isValid = false;
        message = 'Это поле обязательно для заполнения';
    } else if (input.type === 'email' && value && !FormUtils.validateEmail(value)) {
        isValid = false;
        message = 'Введите корректный email адрес';
    } else if (input.type === 'password' && value && !FormUtils.validatePassword(value)) {
        isValid = false;
        message = 'Пароль должен содержать минимум 6 символов';
    }
    
    if (!isValid) {
        showInputError(input, message);
    } else {
        clearInputError(input);
        showInputSuccess(input);
    }
}

// Показать ошибку инпута
function showInputError(input, message) {
    clearInputError(input);
    
    input.style.borderColor = '#dc3545';
    input.style.boxShadow = '0 0 0 3px rgba(220, 53, 69, 0.1)';
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'input-error';
    errorDiv.style.cssText = `
        color: #dc3545;
        font-size: 0.8rem;
        margin-top: 0.25rem;
        animation: slideInDown 0.3s ease-out;
    `;
    errorDiv.textContent = message;
    
    input.parentNode.appendChild(errorDiv);
    
    // Добавляем эффект тряски
    input.classList.add('animate-shake');
    setTimeout(() => input.classList.remove('animate-shake'), 500);
}

// Очистить ошибку инпута
function clearInputError(input) {
    const errorDiv = input.parentNode.querySelector('.input-error');
    if (errorDiv) {
        errorDiv.remove();
    }
    
    input.style.borderColor = '';
    input.style.boxShadow = '';
}

// Показать успех инпута
function showInputSuccess(input) {
    input.style.borderColor = '#28a745';
    input.style.boxShadow = '0 0 0 3px rgba(40, 167, 69, 0.1)';
    
    setTimeout(() => {
        input.style.borderColor = '';
        input.style.boxShadow = '';
    }, 2000);
}

// Запуск демонстрационных анимаций
function startDemoAnimations() {
    // Анимация появления карточек
    AnimationUtils.observeElements('.card', 'animate-slide-up', 0.1);
    AnimationUtils.observeElements('.user-card', 'animate-bounce', 0.1);
    
    // Анимация появления кнопок
    AnimationUtils.observeElements('.btn', 'animate-scale', 0.1);
    
    // Анимация появления форм
    AnimationUtils.observeElements('.form-group', 'animate-slide-up', 0.1);
    
    // Эффект печатания для заголовков
    const headings = document.querySelectorAll('h1, h2, h3');
    headings.forEach(heading => {
        if (heading.textContent.includes('DevConnect')) {
            heading.classList.add('typewriter');
        }
    });
}

// Настройка интерактивных элементов
function setupInteractiveElements() {
    // Добавляем эффект магнитного курсора
    setupMagneticCursor();
    
    // Добавляем эффект параллакса
    setupParallaxEffect();
    
    // Добавляем эффект скролла
    setupScrollEffects();
    
    // Добавляем эффект клавиатуры
    setupKeyboardEffects();
}

// Магнитный курсор
function setupMagneticCursor() {
    const cursor = document.createElement('div');
    cursor.className = 'magnetic-cursor';
    cursor.style.cssText = `
        position: fixed;
        width: 20px;
        height: 20px;
        background: linear-gradient(135deg, #667eea, #764ba2);
        border-radius: 50%;
        pointer-events: none;
        z-index: 10000;
        transition: transform 0.1s ease;
        opacity: 0.7;
    `;
    document.body.appendChild(cursor);
    
    document.addEventListener('mousemove', (e) => {
        cursor.style.left = e.clientX - 10 + 'px';
        cursor.style.top = e.clientY - 10 + 'px';
    });
    
    // Эффект при наведении на интерактивные элементы
    const interactiveElements = document.querySelectorAll('a, button, .user-card, .form-control');
    interactiveElements.forEach(element => {
        element.addEventListener('mouseenter', () => {
            cursor.style.transform = 'scale(1.5)';
            cursor.style.opacity = '1';
        });
        
        element.addEventListener('mouseleave', () => {
            cursor.style.transform = 'scale(1)';
            cursor.style.opacity = '0.7';
        });
    });
}

// Эффект параллакса
function setupParallaxEffect() {
    const parallaxElements = document.querySelectorAll('.card, .user-card');
    
    parallaxElements.forEach(element => {
        element.classList.add('parallax');
        element.dataset.speed = '0.1';
    });
    
    window.addEventListener('scroll', () => {
        const scrolled = window.pageYOffset;
        
        parallaxElements.forEach(element => {
            const speed = parseFloat(element.dataset.speed) || 0.1;
            const yPos = -(scrolled * speed);
            element.style.transform = `translateY(${yPos}px)`;
        });
    });
}

// Эффекты скролла
function setupScrollEffects() {
    let lastScrollTop = 0;
    
    window.addEventListener('scroll', () => {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        
        // Эффект скрытия/показа хедера
        const header = document.querySelector('.header');
        if (scrollTop > lastScrollTop && scrollTop > 100) {
            header.style.transform = 'translateY(-100%)';
        } else {
            header.style.transform = 'translateY(0)';
        }
        
        lastScrollTop = scrollTop;
        
        // Эффект прогресс-бара скролла
        updateScrollProgress();
    });
}

// Обновление прогресс-бара скролла
function updateScrollProgress() {
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    const scrollHeight = document.documentElement.scrollHeight - window.innerHeight;
    const scrollPercent = (scrollTop / scrollHeight) * 100;
    
    let progressBar = document.querySelector('.scroll-progress');
    if (!progressBar) {
        progressBar = document.createElement('div');
        progressBar.className = 'scroll-progress';
        progressBar.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: ${scrollPercent}%;
            height: 3px;
            background: linear-gradient(90deg, #667eea, #764ba2);
            z-index: 10001;
            transition: width 0.1s ease;
        `;
        document.body.appendChild(progressBar);
    } else {
        progressBar.style.width = scrollPercent + '%';
    }
}

// Эффекты клавиатуры
function setupKeyboardEffects() {
    document.addEventListener('keydown', (e) => {
        // Эффект при нажатии Enter
        if (e.key === 'Enter') {
            const activeElement = document.activeElement;
            if (activeElement.classList.contains('btn')) {
                activeElement.classList.add('animate-bounce');
                setTimeout(() => activeElement.classList.remove('animate-bounce'), 600);
            }
        }
        
        // Эффект при нажатии Escape
        if (e.key === 'Escape') {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => modal.remove());
        }
    });
}

// Дополнительные эффекты для чата
function addAdvancedChatEffects() {
    const chatMessages = document.querySelector('.chat-messages');
    if (!chatMessages) return;
    
    // Эффект появления новых сообщений
    const observer = new MutationObserver((mutations) => {
        mutations.forEach(mutation => {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === Node.ELEMENT_NODE && node.classList.contains('message')) {
                        node.classList.add('animate-slide-up');
                        
                        // Эффект печатания для сообщений
                        const messageContent = node.querySelector('.message-content');
                        if (messageContent) {
                            const text = messageContent.textContent;
                            messageContent.textContent = '';
                            
                            let i = 0;
                            const timer = setInterval(() => {
                                messageContent.textContent += text[i];
                                i++;
                                if (i >= text.length) {
                                    clearInterval(timer);
                                }
                            }, 50);
                        }
                    }
                });
            }
        });
    });
    
    observer.observe(chatMessages, { childList: true });
}

// Инициализация продвинутых эффектов чата
if (document.querySelector('.chat-messages')) {
    addAdvancedChatEffects();
}

// Экспорт функций для использования в других модулях
window.DemoEffects = {
    initializeEffects,
    addUserCardEffects,
    addButtonEffects,
    addFormEffects,
    addNavigationEffects,
    addChatEffects,
    createParticleEffect,
    setupMagneticCursor,
    setupParallaxEffect,
    setupScrollEffects,
    setupKeyboardEffects
};
