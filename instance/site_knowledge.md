# DevConnect — Справка по сайту

## Назначение
DevConnect — площадка для специалистов и заказчиков:
- Поиск людей по навыкам и нику
- Профили с навыками, опытом и контактами
- Личные чаты и AI‑чат
- Раздел «Фриланс» с объявлениями/вакансиями

## Разделы и маршруты
- Главная: `/` — навигация по разделам
- Пользователи: `/users` — список и карточки пользователей
- Поиск: `/search` — поиск по никнейму/навыкам
- Чаты:
  - Список чатов: `/chats`
  - Диалог: `/chat/<id>` — история сообщений, ввод, индикатор печати
  - API сообщений:
    - GET `/get_messages/<chat_id>` — загрузка истории
    - POST `/send_message` — отправка сообщения `{ chat_id, content }`
- AI‑чат:
  - Страница: `/chat/ai` — автономная страница AI чата (без БД‑диалога)
  - API: 
    - POST `/api/ai_reply` — ответ AI на `{ content }` с учётом истории сессии
    - POST `/api/ai_reset` — очистить историю сессии
- Фриланс:
  - Список: `/freelance`
  - Создание: `/freelance/new`

## Технологии
- Backend: Flask, Flask‑Login, SQLAlchemy, Flask‑SocketIO (для обычных чатов)
- БД: SQLite (файл `instance/devconnect.db`)
- Шаблоны: Jinja (`templates/*.html`)
- Статика: JS/CSS в `static/`
- Логи: `instance/devconnect.log` (UTF‑8), включены traceback через сигнал `got_request_exception`

## AI‑чат (важно)
- Провайдер LLM: OpenAI или Azure OpenAI
- Ключи и настройки — в `instance/.env`:
  - `AI_PROVIDER=openai | azure`
  - `OPENAI_API_KEY=...` (для OpenAI)
  - `AI_MODEL=gpt-4o-mini` (пример)
  - или `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_KEY`, `AZURE_OPENAI_DEPLOYMENT`
- Контекст диалога хранится в сессии браузера (`session['ai_history']`), последние 30 сообщений
- Поведение: дружелюбные ответы по темам (код/фриланс/DevConnect), допустим короткий смоллтолк, мягкое возвращение к темам

## UI/UX (чаты)
- Общий стиль: `.card.fade-in` контейнер, `.chat-container` высотой ~500px, `.chat-messages` и `.chat-input`
- Сообщение: div с классом `.message` и вложенным `.message-content` и `.message-time`
- В AI‑чате кнопка «Очистить диалог» сбрасывает контекст

## Отладка
- Если страница падает: смотрите `instance/devconnect.log`
- Распространённые причины: неправильная кодировка, ошибки в шаблоне, отсутствие ключей LLM
