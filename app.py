from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import re
import sys
from flask_socketio import SocketIO, join_room, leave_room, emit
import logging
from logging.handlers import RotatingFileHandler
import traceback
from flask import got_request_exception
from flask import send_from_directory
from werkzeug.utils import secure_filename
import json
import random
import time
import urllib.request
import urllib.error
from flask import g

# Ensure UTF-8 console output on Windows to avoid UnicodeEncodeError when logging
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

app = Flask(__name__, static_folder='static', static_url_path='/static')
# Use environment SECRET_KEY if present; fallback to local value for dev only
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
os.makedirs(app.instance_path, exist_ok=True)
db_path = os.path.join(app.instance_path, 'devconnect.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_AS_ASCII'] = False
app.config['JSONIFY_MIMETYPE'] = 'application/json; charset=utf-8'
# Session cookie security
# Set SESSION_COOKIE_SECURE to True in production when using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')  # Lax is a good default
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', '0') == '1'
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=int(os.getenv('SESSION_LIFETIME_DAYS', '7')))

# Load env variables from instance/.env then project .env (no external deps)
def _load_dotenv(path):
    try:
        if not os.path.isfile(path):
            return
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                if '=' in s:
                    k, v = s.split('=', 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k and k not in os.environ:
                        os.environ[k] = v
    except Exception:
        pass

_load_dotenv(os.path.join(app.instance_path, '.env'))
_load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=False, engineio_logger=False)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.unauthorized_handler
def _unauthorized():
    try:
        # For API routes, return JSON 401 instead of HTML redirect
        if request.path.startswith('/api/'):
            return jsonify({'status': 'error', 'error': 'unauthorized'}), 401
    except Exception:
        pass
    # Fallback to default redirect behavior
    return redirect(url_for('login', next=request.url))

# AI rate limit (seconds) configurable via env; 0 disables throttling
def _ai_rate_limit_seconds() -> int:
    try:
        v = int(os.getenv('AI_RATE_LIMIT_SECONDS', '0').strip() or '0')
        return max(0, v)
    except Exception:
        return 0

# Configure UTF-8 file logging to avoid console Unicode issues on Windows
log_file = os.path.join(app.instance_path, 'devconnect.log')
try:
    fh = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3, encoding='utf-8')
    fmt = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    fh.setFormatter(fmt)
    fh.setLevel(logging.INFO)

    # Attach to Flask app logger
    app.logger.handlers = [fh]
    app.logger.setLevel(logging.INFO)

    # Route Werkzeug (server) logs to file and stop propagating to console
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.handlers = [fh]
    werkzeug_logger.setLevel(logging.INFO)
    werkzeug_logger.propagate = False
except Exception:
    pass

@app.after_request
def _force_utf8(response):
    try:
        ctype = response.headers.get('Content-Type', '')
        if ctype.startswith('text/') and 'charset=' not in ctype:
            base = ctype.split(';')[0].strip() or 'text/html'
            response.headers['Content-Type'] = f"{base}; charset=utf-8"
    except Exception:
        pass
    return response


# Security headers similar to helmet: CSP, X-Frame-Options, etc.
@app.after_request
def _security_headers(response):
    try:
        # Content Security Policy - keep conservative defaults, allow inline styles/scripts only if necessary
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https:;"
        response.headers.setdefault('Content-Security-Policy', csp)
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'no-referrer-when-downgrade')
        response.headers.setdefault('Permissions-Policy', "geolocation=(), microphone=(), camera=()")
        # HSTS only when serving over HTTPS
        if app.config.get('SESSION_COOKIE_SECURE'):
            response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    except Exception:
        pass
    return response

# Log full tracebacks for unhandled exceptions (helps diagnose 500 on /chat/ai)
def _log_exc(sender, exception, **extra):  # sender is app
    try:
        app.logger.error('Unhandled exception:\n%s', traceback.format_exc())
    except Exception:
        pass

got_request_exception.connect(_log_exc, app)


# Simple in-memory rate limiter for sensitive actions (login/register)
# Note: this is per-process and best-effort; for production use a shared store like Redis.
_rate_limits = {}

def _is_rate_limited(key: str, limit: int, window_s: int) -> bool:
    """Return True if key exceeded `limit` requests in the last `window_s` seconds."""
    now_ts = int(time.time())
    rec = _rate_limits.get(key)
    if not rec:
        _rate_limits[key] = [now_ts]
        return False
    # keep only timestamps within window
    rec = [t for t in rec if t > now_ts - window_s]
    rec.append(now_ts)
    _rate_limits[key] = rec
    return len(rec) > limit


# ===== Avatar uploads =====
ALLOWED_AVATAR_EXT = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}

def _avatars_dir():
    d = os.path.join(app.instance_path, 'avatars')
    os.makedirs(d, exist_ok=True)
    return d

def _is_allowed_avatar(filename: str) -> bool:
    if not filename:
        return False
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_AVATAR_EXT

@app.route('/uploads/avatars/<path:filename>')
def serve_avatar(filename):
    return send_from_directory(_avatars_dir(), filename)

# ===== Language / Settings =====
@app.before_request
def _load_lang():
    try:
        # Default UI language is English
        g.lang = session.get('lang', 'en')
    except Exception:
        pass

@app.context_processor
def inject_lang():
    # Default to English UI
    lang = getattr(g, 'lang', 'en')

    def t(ru_text, en_text):
        # Site is fully English now; always use English variant
        return en_text

    return { 'current_lang': lang, 't': t }


# CSRF protection: simple per-session token injected into templates and verified on POST
import secrets

@app.before_request
def _ensure_csrf_token():
    try:
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_urlsafe(32)
    except Exception:
        pass


@app.before_request
def _global_csrf_protect():
    """Require CSRF token for JSON POST requests (AJAX) to protect API endpoints.
    Expects 'X-CSRF-Token' header to match session token.
    """
    try:
        if request.method == 'POST' and (request.is_json or request.path.startswith('/api/') or request.path.startswith('/send_message')):
            token = request.headers.get('X-CSRF-Token') or request.headers.get('X-XSRF-Token')
            if not token or token != session.get('csrf_token'):
                # For APIs, return JSON 400
                if request.path.startswith('/api/') or request.is_json or request.path.startswith('/send_message'):
                    return jsonify({'status': 'error', 'error': 'csrf'}), 400
                # For regular forms, let individual routes handle messaging
                return jsonify({'status': 'error', 'error': 'csrf'}), 400
    except Exception:
        pass

@app.context_processor
def inject_csrf_token():
    return {'csrf_token': session.get('csrf_token', '')}

def _verify_csrf():
    """Verify CSRF token in form (field 'csrf_token') or header 'X-CSRF-Token'."""
    if request.method != 'POST':
        return True
    token = ''
    try:
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    except Exception:
        token = None
    if not token:
        return False
    return token == session.get('csrf_token')

@app.context_processor
def inject_now():
    # Jinja helper: use {{ now() }} in templates
    return { 'now': datetime.utcnow }

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        lang = (request.form.get('lang') or 'ru').lower()
        if lang not in ('ru','en'):
            lang = 'ru'
        session['lang'] = lang
        flash('Язык обновлен!' if lang == 'ru' else 'Language updated!')
        return redirect(url_for('profile'))
    return render_template('settings.html')

# Модели базы данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    password_hash = db.Column(db.String(120), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    skills = db.Column(db.String(500), nullable=True)
    experience_level = db.Column(db.String(50), nullable=True)
    looking_for = db.Column(db.String(200), nullable=True)
    avatar_url = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_message_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships to access users participating in the chat
    user1 = db.relationship('User', foreign_keys=[user1_id], backref='chats_as_user1')
    user2 = db.relationship('User', foreign_keys=[user2_id], backref='chats_as_user2')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    # Relationship to access sender user (used in templates and API responses)
    sender = db.relationship('User', foreign_keys=[sender_id])

# AI assistant utilities
def get_or_create_ai_user():
    ai = User.query.filter_by(username='DevBot').first()
    if not ai:
        ai = User(
            username='DevBot',
            email='devbot@example.com',
            password_hash=generate_password_hash(os.urandom(8).hex()),
            bio='AI помощник по вопросам IT, фриланса и вашего сайта',
            skills='AI, Python, JavaScript, Freelance, Flask'
        )
        db.session.add(ai)
        db.session.commit()
    return ai

def is_allowed_topic(text: str) -> bool:
    """Проверка, относится ли запрос к программированию, фрилансу или сайту DevConnect."""
    t = (text or '').lower()
    programming_kw = [
        'код', 'программ', 'разраб', 'python', 'js', 'javascript', 'flask', 'sql', 'база данных',
        'html', 'css', 'react', 'bug', 'баг', 'ошиб', 'debug', 'архитектур', 'api', 'backend', 'frontend',
        'сервер', 'деплой', 'docker', 'git', 'алгоритм', 'структур дан', 'тест'
    ]
    freelance_kw = [
        'фриланс', 'вакан', 'заказ', 'клиент', 'исполнител', 'оплата', 'ставка', 'дз', 'кейсы', 'портфолио',
        'бриф', 'тз', 'догов', 'смета', 'deadline', 'дедлайн', 'фиксация этапов'
    ]
    site_kw = [
        'devconnect', 'мой сайт', 'сайт', 'профиль', 'чаты', 'поиск', 'вакансии', 'freelance', 'по нику'
    ]
    return any(k in t for k in programming_kw + freelance_kw + site_kw)

# Site knowledge loader (reads instance/site_knowledge.md, capped length)
_SITE_KB_CACHE = None

def _load_site_knowledge():
    global _SITE_KB_CACHE
    if _SITE_KB_CACHE is not None:
        return _SITE_KB_CACHE
    try:
        path = os.path.join(app.instance_path, 'site_knowledge.md')
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8') as f:
                text = f.read()
                # Cap to ~8KB to avoid bloating context
                _SITE_KB_CACHE = text[:8192]
                return _SITE_KB_CACHE
    except Exception:
        pass
    _SITE_KB_CACHE = ''
    return _SITE_KB_CACHE

def _http_post_json(url, headers, payload, timeout=20):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        return json.loads(body.decode('utf-8', errors='ignore'))

def _get_ai_cfg():
    provider = (os.getenv('AI_PROVIDER') or '').strip().lower()
    model = (os.getenv('AI_MODEL') or '').strip()
    if provider == 'deepseek':
        key = os.getenv('DEEPSEEK_API_KEY') or ''
        use_model = model or 'deepseek-chat'
        if key and use_model:
            return {'provider': 'deepseek', 'key': key, 'model': use_model}
    if provider == 'azure':
        endpoint = (os.getenv('AZURE_OPENAI_ENDPOINT') or '').rstrip('/')
        key = os.getenv('AZURE_OPENAI_KEY') or ''
        deploy = (os.getenv('AZURE_OPENAI_DEPLOYMENT') or model).strip()
        if endpoint and key and deploy:
            return {'provider': 'azure', 'endpoint': endpoint, 'key': key, 'deployment': deploy}
    if provider == 'openai':
        key = os.getenv('OPENAI_API_KEY') or ''
        use_model = model or 'gpt-4o-mini'
        if key and use_model:
            return {'provider': 'openai', 'key': key, 'model': use_model}
    return None

# Conversation-aware chat with session history
def _ai_history_get():
    try:
        return session.get('ai_history', [])
    except Exception:
        return []

def _ai_history_set(history):
    try:
        session['ai_history'] = history
    except Exception:
        pass

def _build_system_prompt():
    return (
        'Ты DevBot — наставник по программированию на сайте DevConnect. Отвечай дружелюбно, профессионально и по делу. '
        'Разрешенные темы: (1) сайт DevConnect (структура, разделы, маршруты, как пользоваться, ограничения), (2) программирование (код, архитектура, отладка, стек). '
        'Не обсуждай посторонние темы. Если вопрос вне тем — мягко объясни рамки и предложи переформулировки в рамках сайта/кода. '
        'Стиль ответов: сначала краткое резюме, затем конкретные шаги, примеры кода при необходимости, и советы по разделам сайта DevConnect, которые помогут дальше. '
        'Уточняй недостающие детали 1–2 вопросами. '
        'Избегай повторов и шаблонных фраз, предлагай новые идеи и ракурсы, отвечай разнообразно и конкретно. '
        'Отвечай на русском.'
    )

def _few_shots():
    return [
        {
            'role': 'user',
            'content': 'Привет! Как дела?'
        },
        {
            'role': 'assistant',
            'content': (
                'Привет! Все отлично, спасибо. Давай обсудим программирование или разделы сайта DevConnect. '
                'Что именно хочешь сделать? Например: настроить профиль, найти пользователей, открыть чат или оформить вакансию.'
            )
        },
        {
            'role': 'user',
            'content': 'Можешь помочь с багом в Flask? Страница падает с 500.'
        },
        {
            'role': 'assistant',
            'content': (
                'Конечно. Уточню пару вещей: что в логе/traceback, какой маршрут падает, и какая версия Flask? '
                'Пока предложу базовую проверку: проверь логи, оберни проблемный участок try/except с логированием, '
                'и убедись, что у ответов корректный Content-Type и charset.'
            )
        },
        {
            'role': 'user',
            'content': 'Как сформировать портфолио фрилансеру новичку?'
        },
        {
            'role': 'assistant',
            'content': (
                'Резюме: сделай 3–5 мини-кейсов: задача → твоя роль → стек → результат. '\
                'Действия: (1) добавь код/скриншоты и ссылку на репозиторий; (2) кратко опиши вклад и сроки; (3) оформи профиль на DevConnect и укажи навыки. '
                'Полезные разделы: Профиль (заполнить навыки), Поиск (найти единомышленников), Фриланс (посмотреть вакансии).'
            )
        },
        {
            'role': 'user',
            'content': 'Расскажи анекдот'
        },
        {
            'role': 'assistant',
            'content': (
                'Я фокусируюсь только на программировании и возможностях DevConnect. '
                'Если хочешь — могу подсказать, как оформить профиль или как найти людей по навыкам.'
            )
        }
    ]

# Suggest relevant site sections based on keywords
def _site_suggestions(text: str) -> str:
    t = (text or '').lower()
    suggestions = []
    def add(label, url):
        suggestions.append(f"- {label}: {url}")
    # Heuristics
    if any(k in t for k in ['профил', 'аватар', 'скилл', 'skills']):
        add('Профиль', url_for('profile'))
        add('Настройки', url_for('settings'))
    if any(k in t for k in ['поиск', 'найти', 'фильтр', 'users', 'найди']):
        add('Поиск пользователей', url_for('search'))
        add('Все пользователи', url_for('users'))
    if any(k in t for k in ['чат', 'сообщен']):
        add('Чаты', url_for('chats'))
    if any(k in t for k in ['фриланс', 'ваканс', 'заказ']):
        add('Фриланс', url_for('freelance_list'))
        add('Создать вакансию', url_for('freelance_new'))
    if any(k in t for k in ['ai', 'бот', 'devbot']):
        add('AI-чат', url_for('chat_ai'))
    if not suggestions:
        return ''
    return 'Полезно на DevConnect:\n' + '\n'.join(suggestions)

# Simple small-talk handler for greetings and basic questions
def _small_talk_reply(text: str):
    t = (text or '').strip().lower()
    if not t:
        return None
    greetings = ['привет', 'здрав', 'добрый день', 'доброе утро', 'добрый вечер', 'hi', 'hello', 'hey']
    how_are_you = ['как дела', 'как ты', 'как твои дела']
    who_are_you = ['кто ты', 'что ты умеешь', 'что умеешь', 'что ты можешь', 'что можешь']
    thanks = ['спасибо', 'благодарю', 'thx', 'thanks']
    bye = ['пока', 'до свидан', 'увидимся', 'bye', 'goodbye']

    if any(w in t for w in greetings):
        return random.choice([
            'Привет! Рад помочь. Чем могу быть полезен по программированию, фрилансу или DevConnect?',
            'Здравствуйте! Подскажите, по какому вопросу: код, фриланс или разделы DevConnect?'
        ])
    if any(w in t for w in how_are_you):
        return random.choice([
            'Все отлично, спасибо! Чем помочь по коду, фрилансу или DevConnect?',
            'Хорошо, благодарю! Какой вопрос по разработке или DevConnect обсудим?'
        ])
    if any(w in t for w in who_are_you):
        return random.choice([
            'Я DevBot на DevConnect: помогаю с программированием, фрилансом и разделами сайта.',
            'DevBot к вашим услугам: код, архитектура, отладка и навигация по DevConnect.'
        ])
    if any(w in t for w in thanks):
        return random.choice([
            'Пожалуйста! Если нужно — уточните задачу, стек и желаемый результат.',
            'Всегда пожалуйста! Готов подсказать по коду и DevConnect.'
        ])
    if any(w in t for w in bye):
        return random.choice([
            'Хорошего дня! Если появятся вопросы — пишите.',
            'До связи! Удачи в проектах.'
        ])
    # Простые запросы о сайте
    site_q = ['что на сайте', 'расскажи про сайт', 'что такое devconnect', 'что за сайт', 'какие разделы']
    if any(w in t for w in site_q) or ('devconnect' in t and ('что' in t or 'какие' in t or 'раздел' in t)):
        kb = _load_site_knowledge()
        if kb:
            return 'Кратко о DevConnect:\n' + '\n'.join(kb.splitlines()[:12])
        return 'DevConnect — площадка с профилями, поиском, чатами и разделом фриланса. Чем именно помочь?'
    return None

# Build a dynamic summary of routes for system context (short, capped)
def _route_summary():
    try:
        lines = []
        for rule in app.url_map.iter_rules():
            if rule.endpoint in ('static',):
                continue
            methods = ','.join(sorted(m for m in rule.methods if m in ('GET','POST')))
            url = str(rule)
            if any(url.startswith(p) for p in ('/api/', '/chat', '/users', '/user', '/freelance', '/search', '/')):
                lines.append(f"{methods} {url} -> {rule.endpoint}")
        text = '\n'.join(sorted(set(lines)))
        return text[:4000]
    except Exception:
        return ''

def _llm_chat(messages):
    cfg = _get_ai_cfg()
    if not cfg:
        try:
            app.logger.warning('LLM config missing: check AI_PROVIDER/keys in instance/.env')
        except Exception:
            pass
        return None
    try:
        # Tunables from environment
        try:
            temperature = float(os.getenv('AI_TEMPERATURE', '0.7'))
        except Exception:
            temperature = 0.7
        try:
            max_tokens = int(os.getenv('AI_MAX_TOKENS', '800'))
        except Exception:
            max_tokens = 800
        try:
            presence_penalty = float(os.getenv('AI_PRESENCE_PENALTY', '0.6'))
        except Exception:
            presence_penalty = 0.6
        try:
            frequency_penalty = float(os.getenv('AI_FREQUENCY_PENALTY', '0.7'))
        except Exception:
            frequency_penalty = 0.7
        if cfg['provider'] == 'deepseek':
            url = 'https://api.deepseek.com/chat/completions'
            headers = {
                'Authorization': f"Bearer {cfg['key']}",
                'Content-Type': 'application/json'
            }
            # Retry/backoff for rate limits and transient errors, with token reduction per attempt
            try:
                attempts = int(os.getenv('AI_RETRY_ATTEMPTS', '2'))
            except Exception:
                attempts = 2
            try:
                backoff = float(os.getenv('AI_RETRY_BACKOFF', '1.5'))
            except Exception:
                backoff = 1.5
            base_max_tokens = max_tokens
            for attempt in range(attempts + 1):
                # reduce tokens progressively to ease provider pressure
                adj_max_tokens = max(300, int(base_max_tokens * (0.7 ** attempt)))
                payload = {
                    'model': cfg['model'],
                    'messages': messages,
                    'temperature': temperature,
                    'max_tokens': adj_max_tokens
                }
                try:
                    data = _http_post_json(url, headers, payload)
                    c = (data.get('choices') or [{}])[0].get('message', {}).get('content')
                    return c or None
                except urllib.error.HTTPError as he:
                    try:
                        g.llm_error_code = getattr(he, 'code', None)
                    except Exception:
                        pass
                    # Respect Retry-After if present
                    if getattr(he, 'code', 0) in (429, 500, 502, 503, 504) and attempt < attempts:
                        try:
                            ra = he.headers.get('Retry-After') if hasattr(he, 'headers') else None
                            wait_s = float(ra) if ra else max(0.5, backoff ** attempt)
                        except Exception:
                            wait_s = max(0.5, backoff ** attempt)
                        try:
                            app.logger.info(f"DeepSeek retry {attempt+1}/{attempts} after {wait_s:.1f}s due to HTTP {getattr(he, 'code', 'unknown')}, max_tokens={adj_max_tokens}")
                        except Exception:
                            pass
                        time.sleep(wait_s)
                        continue
                    raise
                except urllib.error.URLError:
                    if attempt < attempts:
                        wait_s = max(0.5, backoff ** attempt)
                        time.sleep(wait_s)
                        continue
                    raise
        if cfg['provider'] == 'openai':
            url = 'https://api.openai.com/v1/chat/completions'
            headers = {
                'Authorization': f"Bearer {cfg['key']}",
                'Content-Type': 'application/json'
            }
            payload = { 'model': cfg['model'], 'messages': messages, 'temperature': temperature, 'max_tokens': max_tokens }
            data = _http_post_json(url, headers, payload)
            c = (data.get('choices') or [{}])[0].get('message', {}).get('content')
            return c or None
        if cfg['provider'] == 'azure':
            api_version = '2024-02-15-preview'
            url = f"{cfg['endpoint']}/openai/deployments/{cfg['deployment']}/chat/completions?api-version={api_version}"
            headers = {
                'api-key': cfg['key'],
                'Content-Type': 'application/json'
            }
            payload = { 'messages': messages, 'temperature': temperature, 'max_tokens': max_tokens, 'presence_penalty': presence_penalty, 'frequency_penalty': frequency_penalty }
            data = _http_post_json(url, headers, payload)
            c = (data.get('choices') or [{}])[0].get('message', {}).get('content')
            return c or None
    except Exception as e:
        try:
            # Save error code (e.g., 429) to request context for downstream handling
            try:
                g.llm_error_code = getattr(e, 'code', None)
            except Exception:
                pass
            app.logger.error('LLM chat error:\n%s', traceback.format_exc())
        except Exception:
            pass
        return None
    return None

def _llm_reply(user_text):
    cfg = _get_ai_cfg()
    if not cfg:
        return None
    sys_prompt = (
        'Ты помощник DevBot. Отвечай только по темам: программирование, фриланс, сайт DevConnect. '
        'Если вопрос вне этих тем, кратко откажись и предложи сформулировать в рамках тем.'
    )
    messages = [
        { 'role': 'system', 'content': sys_prompt },
        { 'role': 'user', 'content': user_text }
    ]
    try:
        try:
            temperature = float(os.getenv('AI_TEMPERATURE', '0.7'))
        except Exception:
            temperature = 0.7
        try:
            presence_penalty = float(os.getenv('AI_PRESENCE_PENALTY', '0.6'))
        except Exception:
            presence_penalty = 0.6
        try:
            frequency_penalty = float(os.getenv('AI_FREQUENCY_PENALTY', '0.7'))
        except Exception:
            frequency_penalty = 0.7
        if cfg['provider'] == 'deepseek':
            url = 'https://api.deepseek.com/chat/completions'
            headers = {
                'Authorization': f"Bearer {cfg['key']}",
                'Content-Type': 'application/json'
            }
            # DeepSeek совместим с OpenAI Chat Completions API по основным полям
            payload = {
                'model': cfg.get('model') or 'deepseek-chat',
                'messages': messages,
                'temperature': temperature,
                # max_tokens опционален; оставим управляемым через AI_MAX_TOKENS в _llm_chat,
                # здесь можно не задавать, чтобы провайдер сам подбирал
            }
            data = _http_post_json(url, headers, payload)
            c = (data.get('choices') or [{}])[0].get('message', {}).get('content')
            return c or None
        if cfg['provider'] == 'openai':
            url = 'https://api.openai.com/v1/chat/completions'
            headers = {
                'Authorization': f"Bearer {cfg['key']}",
                'Content-Type': 'application/json'
            }
            payload = { 'model': cfg['model'], 'messages': messages, 'temperature': temperature, 'presence_penalty': presence_penalty, 'frequency_penalty': frequency_penalty }
            data = _http_post_json(url, headers, payload)
            c = (data.get('choices') or [{}])[0].get('message', {}).get('content')
            return c or None
        if cfg['provider'] == 'azure':
            api_version = '2024-02-15-preview'
            url = f"{cfg['endpoint']}/openai/deployments/{cfg['deployment']}/chat/completions?api-version={api_version}"
            headers = {
                'api-key': cfg['key'],
                'Content-Type': 'application/json'
            }
            payload = { 'messages': messages, 'temperature': temperature, 'presence_penalty': presence_penalty, 'frequency_penalty': frequency_penalty }
            data = _http_post_json(url, headers, payload)
            c = (data.get('choices') or [{}])[0].get('message', {}).get('content')
            return c or None
    except Exception:
        return None
    return None

def generate_ai_reply(text):
    t = (text or '').lower()
    # Handle small talk first for direct DevBot chats
    st = _small_talk_reply(text or '')
    if st:
        return st
    llm = _llm_reply(text or '')
    if llm:
        return llm.strip()
    if any(k in t for k in ['фриланс', 'вакан', 'заказ', 'оплата', 'ставка']):
        return (
            'Совет по фрилансу:\n'
            '- Четко опишите задачу, критерии готовности и бюджет.\n'
            '- Для подбора специалиста используйте навыки и примеры работ.\n'
            '- Фиксируйте этапы и оплату по вехам.'
        )
    if any(k in t for k in ['баг', 'ошиб', 'debug', 'лог', 'трасс']):
        return (
            'Для отладки:\n'
            '- Добавьте логирование на критичных шагах.\n'
            '- Воспроизведите минимальный кейс.\n'
            '- Проверьте консоль браузера и логи сервера.'
        )
    if any(k in t for k in ['поиск', 'ник', 'skills', 'filter', 'search']):
        return (
            'Поиск в DevConnect:\n'
            '- По нику используйте поле «Поиск по никнейму».\n'
            '- Фильтры по навыкам/опыту доступны на странице поиска.\n'
            '- В фрилансе фильтруйте по типу и навыкам.'
        )
    if any(k in t for k in ['ui', 'дизайн', 'интерфейс', 'прозрач', 'glass']):
        return (
            'UI совет:\n'
            '- Используйте стеклянные карточки (glass-effect) для акцентов.\n'
            '- Следите за контрастом текста на прозрачном фоне.'
        )
    return (
        'Я здесь, чтобы помочь с IT, фрилансом и вашим сайтом DevConnect.\n'
        'Сформулируйте вопрос или тему — предложу конкретные шаги.'
    )

# Freelance job postings
class FreelanceJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    skills = db.Column(db.String(500), nullable=True)  # comma-separated
    budget = db.Column(db.String(50), nullable=True)   # text to keep it simple
    job_type = db.Column(db.String(20), nullable=False, default='hire')  # hire | work
    is_remote = db.Column(db.Boolean, default=True)
    location = db.Column(db.String(120), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    author = db.relationship('User', foreign_keys=[author_id])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Маршруты
@app.route('/')
def index():
    if current_user.is_authenticated:
        # Показываем других пользователей для знакомства
        other_users = User.query.filter(User.id != current_user.id).limit(20).all()
        return render_template('index.html', users=other_users)
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Rate limit registrations per IP to slow automated account creation
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        key = f"register:{ip}"
        if _is_rate_limited(key, limit=5, window_s=60*60):
            flash('Слишком много попыток регистрации. Попробуйте позже.')
            return render_template('register.html'), 429

        # CSRF check
        if not _verify_csrf():
            flash('Ошибка проверки формы (CSRF).')
            return render_template('register.html'), 400

        username = request.form['username']
        email = request.form['email']
        phone = request.form.get('phone', '')
        password = request.form['password']
        
        # Проверка валидности
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким никнеймом уже существует')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует')
            return render_template('register.html')
        
        if phone and User.query.filter_by(phone=phone).first():
            flash('Пользователь с таким номером телефона уже существует')
            return render_template('register.html')
        
        # Создание пользователя
        user = User(
            username=username,
            email=email,
            phone=phone if phone else None,
            password_hash=generate_password_hash(password)
        )
        
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        # clear any rate limit record for this IP on success
        _rate_limits.pop(key, None)
        flash('Регистрация прошла успешно!')
        return redirect(url_for('profile'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Preserve ?next=... across the login flow
    if request.method == 'GET':
        next_url = request.args.get('next')
        if next_url:
            session['next_url'] = next_url

    if request.method == 'POST':
        # Rate limit login attempts per IP to mitigate brute force
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        key = f"login:{ip}"
        if _is_rate_limited(key, limit=10, window_s=5*60):
            flash('Слишком много попыток входа. Попробуйте позже.')
            return render_template('login.html'), 429

        # CSRF check
        if not _verify_csrf():
            flash('Ошибка проверки формы (CSRF).')
            return render_template('login.html'), 400

        login_input = request.form['login']
        password = request.form['password']
        
        # Поиск пользователя по email или username
        user = User.query.filter(
            (User.email == login_input) | (User.username == login_input)
        ).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            user.is_online = True
            user.last_seen = datetime.utcnow()
            db.session.commit()
            # clear rate limit on successful login
            _rate_limits.pop(key, None)
            # Redirect to preserved next_url if present
            next_url = session.pop('next_url', None)
            if next_url:
                return redirect(next_url)
            return redirect(url_for('index'))
        else:
            # keep generic message and record failed attempt
            flash('Неверный логин или пароль')
            # failed attempt already recorded by _is_rate_limited via timestamp append
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    current_user.is_online = False
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.bio = request.form.get('bio', '')
        current_user.skills = request.form.get('skills', '')
        current_user.experience_level = request.form.get('experience_level', '')
        current_user.looking_for = request.form.get('looking_for', '')

        # Обработка загрузки аватара
        file = (request.files.get('avatar') if 'avatar' in request.files else None)
        if file and file.filename:
            if not _is_allowed_avatar(file.filename):
                db.session.commit()
                flash('Недопустимый формат файла. Разрешены: PNG, JPG, JPEG, GIF, WEBP')
                return redirect(url_for('edit_profile'))
            fn = secure_filename(file.filename)
            base, ext = os.path.splitext(fn)
            safe_name = f"u{current_user.id}_{int(datetime.utcnow().timestamp())}{ext.lower()}"
            path = os.path.join(_avatars_dir(), safe_name)
            try:
                file.save(path)
                # Удалим старый файл, если он в нашей папке
                old = (current_user.avatar_url or '').strip()
                if old.startswith('/uploads/avatars/'):
                    try:
                        old_path = os.path.join(_avatars_dir(), os.path.basename(old))
                        if os.path.isfile(old_path):
                            os.remove(old_path)
                    except Exception:
                        pass
                current_user.avatar_url = f"/uploads/avatars/{safe_name}"
            except Exception as e:
                app.logger.error('Avatar upload failed: %s', e)
                db.session.commit()
                flash('Не удалось сохранить аватар. Попробуйте еще раз.')
                return redirect(url_for('edit_profile'))

        db.session.commit()
        flash('Профиль обновлен!')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html')

@app.route('/chat/<int:user_id>')
@login_required
def chat(user_id):
    other_user = User.query.get_or_404(user_id)
    
    # Найти или создать чат
    chat = Chat.query.filter(
        ((Chat.user1_id == current_user.id) & (Chat.user2_id == user_id)) |
        ((Chat.user1_id == user_id) & (Chat.user2_id == current_user.id))
    ).first()
    
    if not chat:
        chat = Chat(user1_id=current_user.id, user2_id=user_id)
        db.session.add(chat)
        db.session.commit()
    
    messages = Message.query.filter_by(chat_id=chat.id).order_by(Message.timestamp).all()
    
    return render_template('chat.html', other_user=other_user, messages=messages, chat_id=chat.id)

@app.route('/chat/ai')
@login_required
def chat_ai():
    # Новый самостоятельный AI-чат без БД
    return render_template('ai_chat.html')

@app.route('/api/ai_reply', methods=['POST'])
@login_required
def api_ai_reply():
    data = request.get_json(silent=True) or {}
    content = (data.get('content') or '').strip()
    if not content:
        return jsonify({'status': 'error', 'error': 'empty'}), 400
    # Simple per-session rate limiting to avoid hitting provider rate limits
    now_ts = time.time()
    try:
        last_ts = float(session.get('ai_last_call', 0))
    except Exception:
        last_ts = 0.0
    rl = _ai_rate_limit_seconds()
    if rl > 0 and (now_ts - last_ts) < rl:
        wait_sec = int(rl - (now_ts - last_ts)) + 1
        return jsonify({'status': 'ok', 'reply': f'Похоже, запросов слишком много. Подождите {wait_sec} сек и попробуйте снова.'})
    # Сначала быстрый ответ на смоллтолк, если распознали (до проверки тем)
    st = _small_talk_reply(content)
    if st:
        history = _ai_history_get()
        history.append({'role': 'user', 'content': content})
        sug = _site_suggestions(content)
        reply = st + (('\n\n' + sug) if sug else '')
        history.append({'role': 'assistant', 'content': reply})
        history = history[-30:]
        _ai_history_set(history)
        return jsonify({'status': 'ok', 'reply': reply})

    # Если не настроен AI-провайдер, вернем явную диагностику для UI/логов
    if not _get_ai_cfg():
        return jsonify({'status': 'error', 'error': 'cfg_missing'}), 200

    # Темы контролируем системным промптом. Если сообщение вне тем, не блокируем, а добавим мягкое напоминание к ответу.
    soft_guard = ''

    # История диалога из сессии (ограничим длину)
    history = _ai_history_get()
    # Добавляем текущее сообщение пользователя
    history.append({'role': 'user', 'content': content})
    # Ограничим последние 30 записей, чтобы не раздувать контекст
    history = history[-30:]

    # Сформируем сообщения с системным промптом
    kb = _load_site_knowledge()
    sys_msgs = [{'role': 'system', 'content': _build_system_prompt()}]
    if kb:
        sys_msgs.append({'role': 'system', 'content': 'Справка о сайте DevConnect:\n' + kb})
    routes = _route_summary()
    if routes:
        sys_msgs.append({'role': 'system', 'content': 'Карта маршрутов (сокращённо):\n' + routes})
    messages = sys_msgs + _few_shots() + history

    # Попытка LLM с учетом контекста
    # Record last call timestamp before contacting LLM to pace subsequent requests
    try:
        session['ai_last_call'] = now_ts
    except Exception:
        pass
    llm = _llm_chat(messages)
    if llm:
        text = llm.strip()
        # Предыдущий ответ ассистента (для анти-повтора)
        last_assistant = None
        for h in reversed(history):
            if h.get('role') == 'assistant':
                last_assistant = h.get('content') or ''
                break
        sug = _site_suggestions(content + ' ' + text)
        # Избежать повторяющегося guard/подсказок
        guard_prefix = '' if (soft_guard and last_assistant and soft_guard in last_assistant) else soft_guard
        sug_part = '' if (sug and last_assistant and sug in last_assistant) else (("\n\n" + sug) if sug else '')
        body = text + sug_part
        reply = (guard_prefix + ('\n\n' if guard_prefix else '')) + body
        history.append({'role': 'assistant', 'content': reply})
        _ai_history_set(history)
        return jsonify({'status': 'ok', 'reply': reply})

    # Фоллбек на локальные подсказки (без жёсткой блокировки тем)
    # Сначала пытаемся дать осмысленный ответ локально (ключевые слова/правила)
    local = (generate_ai_reply(content) or '').strip()
    # Tailor message depending on known provider errors
    err_code = getattr(g, 'llm_error_code', None)
    if not local:
        if err_code == 429:
            fb = (
                'Похоже, достигнут лимит запросов к AI (429 Too Many Requests). '\
                'Сделайте паузу 10–20 секунд и повторите. Я всё равно помогу: '\
                'кратко опишите цель, стек и что уже пробовали.'
            )
        elif err_code in (401, 403):
            fb = (
                'Пока нет доступа к AI (ошибка авторизации). Я помогу без модели: '\
                'опишите цель, стек и что уже пробовали — предложу шаги.'
            )
        else:
            fb = (
                'Сейчас не удалось обратиться к модели. Давайте всё равно продвинемся: '\
                'кратко опишите цель, какой стек используете, и что уже пробовали. '
                'Если это вопрос по DevConnect — укажите раздел и что хотите сделать.'
            )
    else:
        fb = local
    sug = _site_suggestions(content)
    last_assistant = None
    for h in reversed(history):
        if h.get('role') == 'assistant':
            last_assistant = h.get('content') or ''
            break
    guard_prefix = '' if (soft_guard and last_assistant and soft_guard in last_assistant) else soft_guard
    sug_part = '' if (sug and last_assistant and sug in last_assistant) else (("\n\n" + sug) if sug else '')
    body = fb + sug_part
    reply = (guard_prefix + ('\n\n' if guard_prefix else '')) + body
    history.append({'role': 'assistant', 'content': reply})
    _ai_history_set(history)
    return jsonify({'status': 'ok', 'reply': reply})

@app.route('/api/ai_check', methods=['GET'])
@login_required
def api_ai_check():
    cfg = _get_ai_cfg() or {}
    info = {
        'provider': cfg.get('provider', ''),
        'model': cfg.get('model') or cfg.get('deployment', ''),
        'has_key': bool(cfg.get('key')),
        'rate_limit': _ai_rate_limit_seconds(),
    }
    code = getattr(g, 'llm_error_code', None)
    if code is not None:
        info['last_error_code'] = code
    return jsonify({'status': 'ok', 'info': info})

@app.route('/api/ai_reset', methods=['POST'])
@login_required
def api_ai_reset():
    try:
        session['ai_history'] = []
    except Exception:
        pass
    return jsonify({'status': 'ok'})

@app.route('/api/ai_suggest', methods=['POST'])
@login_required
def api_ai_suggest():
    """Generate the next AI message proactively based on the current session history.
    It uses the same system context as /api/ai_reply, but adds a guiding user instruction
    to propose the next helpful step (clarifying question, short plan, or suggestion)
    strictly within allowed topics.
    """
    # Rate-limit proactive suggestions as well
    now_ts = time.time()
    try:
        last_ts = float(session.get('ai_last_call', 0))
    except Exception:
        last_ts = 0.0
    rl = _ai_rate_limit_seconds()
    if rl > 0 and (now_ts - last_ts) < rl:
        return jsonify({'status': 'ok', 'reply': 'Секунду… Давайте не слишком часто запрашивать подсказки, чтобы не упереться в лимиты.'})

    # Load recent history (keep last 30 items)
    history = _ai_history_get() or []
    history = history[-30:]

    # Build system context
    kb = _load_site_knowledge()
    sys_msgs = [{'role': 'system', 'content': _build_system_prompt()}]
    if kb:
        sys_msgs.append({'role': 'system', 'content': 'Справка о сайте DevConnect:\n' + kb})
    routes = _route_summary()
    if routes:
        sys_msgs.append({'role': 'system', 'content': 'Карта маршрутов (сокращённо):\n' + routes})

    # Add a short guiding prompt to move the dialog forward within scope
    guide = (
        'Сгенерируй следующий полезный ход в диалоге в рамках тем (программирование, фриланс, DevConnect): '
        'задай уточняющий вопрос ИЛИ предложи 2–3 шага/варианта действий по теме. Кратко и по делу. '
        'Не повторяйся и не перефразируй предыдущий ответ.'
    )
    messages = sys_msgs + _few_shots() + history + [{'role': 'user', 'content': guide}]

    # Try LLM
    text = None
    llm = _llm_chat(messages)
    if llm:
        text = llm.strip()
    else:
        # Fallback if LLM unavailable
        text = (
            'Предлагаю продолжить: уточните цель, стек (например, Flask/React/SQL), и что уже пробовали. '
            'Могу наметить чек-лист шагов и дать ссылки на разделы сайта.'
        )

    # Anti-duplicate: compare with last assistant message
    last_assistant = None
    for h in reversed(history):
        if h.get('role') == 'assistant':
            last_assistant = (h.get('content') or '').strip()
            break
    norm = (text or '').strip().lower()
    is_dup = bool(last_assistant) and (norm == last_assistant.strip().lower())
    if is_dup:
        # Retry once with a stronger anti-repeat hint
        retry_guide = 'Сформируй новый ответ, отличный от предыдущего. Добавь свежие идеи/шаги. Не повторяй формулировки.'
        retry_msgs = messages + [{'role': 'user', 'content': retry_guide}]
        llm2 = _llm_chat(retry_msgs)
        if llm2:
            text = llm2.strip()
    # Optionally add site suggestions (avoid repeating same suggestions)
    sug = _site_suggestions(text)
    sug_part = '' if (sug and last_assistant and sug in last_assistant) else (('\n\n' + sug) if sug else '')
    reply = text + sug_part

    # Save assistant reply to history
    history.append({'role': 'assistant', 'content': reply})
    history = history[-30:]
    _ai_history_set(history)

    return jsonify({'status': 'ok', 'reply': reply})

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    data = request.get_json(silent=True) or {}
    chat_id = data.get('chat_id')
    content = (data.get('content') or '').strip()

    if not chat_id or not content:
        return jsonify({'status': 'error', 'error': 'bad_request'}), 400

    message = Message(
        chat_id=chat_id,
        sender_id=current_user.id,
        content=content
    )

    db.session.add(message)

    chat = Chat.query.get(chat_id)
    if not chat:
        db.session.rollback()
        return jsonify({'status': 'error', 'error': 'chat_not_found'}), 404
    chat.last_message_at = datetime.utcnow()

    db.session.commit()

    ai = User.query.filter_by(username='DevBot').first()
    chat_users = {chat.user1_id, chat.user2_id}

    response_payload = {
        'status': 'success',
        'message': {
            'id': message.id,
            'sender_id': message.sender_id,
            'content': message.content,
            'timestamp': message.timestamp.strftime('%H:%M'),
            'sender_username': message.sender.username,
            'is_read': message.is_read
        }
    }

    if ai and ai.id in chat_users and current_user.id in chat_users:
        reply = Message(
            chat_id=chat_id,
            sender_id=ai.id,
            content=generate_ai_reply(content)
        )
        db.session.add(reply)
        chat.last_message_at = datetime.utcnow()
        db.session.commit()

        response_payload['messages'] = [
            response_payload['message'],
            {
                'id': reply.id,
                'sender_id': reply.sender_id,
                'content': reply.content,
                'timestamp': reply.timestamp.strftime('%H:%M'),
                'sender_username': reply.sender.username,
                'is_read': reply.is_read
            }
        ]

    # Emit real-time events to the chat room
    try:
        room = f"chat_{chat_id}"
        if 'messages' in response_payload:
            for m in response_payload['messages']:
                socketio.emit('message:new', m, room=room)
        else:
            socketio.emit('message:new', response_payload['message'], room=room)
    except Exception:
        pass

    return jsonify(response_payload)

@app.route('/get_messages/<int:chat_id>')
@login_required
def get_messages(chat_id):
    messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.timestamp).all()

    # Mark as read messages received by current user
    to_mark = [m for m in messages if m.sender_id != current_user.id and not m.is_read]
    read_ids = [m.id for m in to_mark]
    if to_mark:
        for m in to_mark:
            m.is_read = True
        db.session.commit()
        # notify room about read receipts
        try:
            socketio.emit('message:read', {
                'reader_id': current_user.id,
                'message_ids': read_ids
            }, room=f"chat_{chat_id}")
        except Exception:
            pass

    messages_data = []
    for msg in messages:
        messages_data.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'content': msg.content,
            'timestamp': msg.timestamp.strftime('%H:%M'),
            'sender_username': msg.sender.username,
            'is_read': msg.is_read
        })

    return jsonify(messages_data)

@app.route('/chats')
@login_required
def chats():
    # Получить все чаты пользователя
    user_chats = Chat.query.filter(
        (Chat.user1_id == current_user.id) | (Chat.user2_id == current_user.id)
    ).order_by(Chat.last_message_at.desc()).all()
    
    chats_data = []
    for chat in user_chats:
        other_user = chat.user1 if chat.user1_id != current_user.id else chat.user2
        last_message = Message.query.filter_by(chat_id=chat.id).order_by(Message.timestamp.desc()).first()
        
        chats_data.append({
            'chat_id': chat.id,
            'other_user': other_user,
            'last_message': last_message,
            'last_message_at': chat.last_message_at
        })
    return render_template('chats.html', chats=chats_data)
@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip()
    skill_filter = request.args.get('skill', '').strip()
    experience_filter = request.args.get('experience', '').strip()
    looking_for_filter = request.args.get('looking_for', '').strip()
    
    # Базовый запрос - исключаем текущего пользователя
    users_query = User.query.filter(User.id != current_user.id)
    
    # Поиск по никнейму
    if query:
        users_query = users_query.filter(User.username.ilike(f'%{query}%'))
    
    # Фильтр по навыкам
    if skill_filter:
        users_query = users_query.filter(User.skills.ilike(f'%{skill_filter}%'))
    
    # Фильтр по опыту
    if experience_filter:
        users_query = users_query.filter(User.experience_level == experience_filter)
    
    # Фильтр по целям
    if looking_for_filter:
        users_query = users_query.filter(User.looking_for == looking_for_filter)
    
    users = users_query.limit(50).all()
    
    # Получаем уникальные значения для фильтров
    all_skills = set()
    all_experience_levels = set()
    all_looking_for = set()
    
    for user in User.query.filter(User.id != current_user.id).all():
        if user.skills:
            all_skills.update([skill.strip() for skill in user.skills.split(',')])
        if user.experience_level:
            all_experience_levels.add(user.experience_level)
        if user.looking_for:
            all_looking_for.add(user.looking_for)
    
    return render_template('search.html', 
                         users=users, 
                         query=query,
                         skill_filter=skill_filter,
                         experience_filter=experience_filter,
                         looking_for_filter=looking_for_filter,
                         all_skills=sorted(all_skills),
                         all_experience_levels=sorted(all_experience_levels),
                         all_looking_for=sorted(all_looking_for))

@app.route('/api/search')
@login_required
def api_search():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    
    users = User.query.filter(
        User.id != current_user.id,
        User.username.ilike(f'%{query}%')
    ).limit(10).all()
    
    results = []
    for user in users:
        results.append({
            'id': user.id,
            'username': user.username,
            'bio': user.bio[:100] if user.bio else '',
            'skills': user.skills,
            'experience_level': user.experience_level,
            'is_online': user.is_online,
            'avatar': user.username[0].upper(),
            'avatar_url': user.avatar_url or ''
        })
    
    return jsonify(results)

@app.route('/users')
@login_required
def users():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    users_query = User.query.filter(User.id != current_user.id)
    users = users_query.paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )
    
    return render_template('users.html', users=users)

# Freelance: list and search
@app.route('/freelance')
def freelance_list():
    q = request.args.get('q', '').strip()
    skill = request.args.get('skill', '').strip()
    job_type = request.args.get('type', '').strip()  # hire | work | ''
    remote = request.args.get('remote', '').strip()  # '1' or ''

    jobs_query = FreelanceJob.query
    if q:
        like = f"%{q}%"
        jobs_query = jobs_query.filter(
            (FreelanceJob.title.ilike(like)) | (FreelanceJob.description.ilike(like))
        )
    if skill:
        jobs_query = jobs_query.filter(FreelanceJob.skills.ilike(f"%{skill}%"))
    if job_type in ('hire', 'work'):
        jobs_query = jobs_query.filter(FreelanceJob.job_type == job_type)
    if remote == '1':
        jobs_query = jobs_query.filter(FreelanceJob.is_remote.is_(True))

    jobs = jobs_query.order_by(FreelanceJob.created_at.desc()).limit(100).all()

    # build available skill tags from existing jobs
    skill_set = set()
    for j in FreelanceJob.query.all():
        if j.skills:
            skill_set.update([s.strip() for s in j.skills.split(',') if s.strip()])

    return render_template('freelance.html', jobs=jobs, q=q, skill_filter=skill,
                           job_type=job_type, remote=remote, all_skills=sorted(skill_set))

# Freelance: create new job
@app.route('/freelance/new', methods=['GET', 'POST'])
@login_required
def freelance_new():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        skills = request.form.get('skills', '').strip()
        budget = request.form.get('budget', '').strip()
        job_type = request.form.get('job_type', 'hire').strip()
        is_remote = request.form.get('is_remote') == 'on'
        location = request.form.get('location', '').strip()

        if not title or not description:
            flash('Заполните обязательные поля: Заголовок и Описание')
            return render_template('freelance_new.html')

        job = FreelanceJob(
            title=title,
            description=description,
            skills=skills,
            budget=budget,
            job_type=job_type if job_type in ('hire', 'work') else 'hire',
            is_remote=is_remote,
            location=location if not is_remote else None,
            author_id=current_user.id
        )
        db.session.add(job)
        db.session.commit()
        flash('Вакансия опубликована!')
        return redirect(url_for('freelance_detail', job_id=job.id))

    return render_template('freelance_new.html')

# Freelance: job detail
@app.route('/freelance/<int:job_id>')
def freelance_detail(job_id):
    job = FreelanceJob.query.get_or_404(job_id)
    return render_template('freelance_detail.html', job=job)

@app.route('/user/<int:user_id>')
@login_required
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return redirect(url_for('profile'))
    
    # Находим похожих пользователей по навыкам
    similar_users = []
    if user.skills:
        user_skills = [skill.strip().lower() for skill in user.skills.split(',')]
        all_users = User.query.filter(User.id != current_user.id, User.id != user.id).all()
        
        for other_user in all_users:
            if other_user.skills:
                other_skills = [skill.strip().lower() for skill in other_user.skills.split(',')]
                # Проверяем пересечение навыков
                if set(user_skills) & set(other_skills):
                    similar_users.append(other_user)

    return render_template('user_profile.html', user=user, similar_users=similar_users)

# Маршрут для статических файлов
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# ... rest of the code remains the same ...
# Тестовый маршрут для проверки CSS
@app.route('/test-css')
def test_css():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CSS Test</title>
        <link href="/static/style.css" rel="stylesheet">
    </head>
    <body>
        <div class="card">
            <h1>Тест CSS</h1>
            <p>Если вы видите фиолетовый градиентный фон и прозрачную карточку, CSS работает!</p>
        </div>
    </body>
    </html>
    '''

@socketio.on('join')
def on_join(data):
    chat_id = data.get('chat_id')
    if not chat_id:
        return
    join_room(f"chat_{chat_id}")

@socketio.on('leave')
def on_leave(data):
    chat_id = data.get('chat_id')
    if not chat_id:
        return
    leave_room(f"chat_{chat_id}")

@socketio.on('typing')
def on_typing(data):
    chat_id = data.get('chat_id')
    username = data.get('username')
    if chat_id and username:
        emit('typing', {'username': username}, room=f"chat_{chat_id}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        get_or_create_ai_user()
    socketio.run(app, debug=True)
