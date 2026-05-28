from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from database import get_db_connection, init_database, get_skill_categories
from datetime import datetime, timedelta, UTC
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import json
import os
import uuid
import sqlite3
import hashlib
import copy
import secrets
import smtplib
from email.message import EmailMessage
from google import genai
from groq import Groq
import PyPDF2
import docx
import io
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from ai_prompts import get_cv_parse_prompt, get_assignment_match_prompt, get_assignment_parse_prompt
import re

# Import authentication modules
from auth import User, get_all_users, get_all_whitelist, add_to_whitelist, remove_from_whitelist, update_user_role, deactivate_user
from decorators import admin_required, consultant_or_admin_required, check_consultant_access

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'h9sdf696f34rhfvvhkxjvodfyg8yer89g7ye-8yhoiuver8v8erf98yyh34f')
app.permanent_session_lifetime = timedelta(hours=24)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'error'

# Initialize OAuth
oauth = OAuth(app)


def env_flag(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


GOOGLE_OAUTH_ENABLED = bool(os.getenv('GOOGLE_CLIENT_ID', '').strip())
MICROSOFT_OAUTH_ENABLED = bool(os.getenv('MICROSOFT_CLIENT_ID', '').strip())
SMTP_HOST = os.getenv('SMTP_HOST', '').strip()
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '').strip()
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
SMTP_USE_TLS = env_flag('SMTP_USE_TLS', True)
SMTP_USE_SSL = env_flag('SMTP_USE_SSL', False)
SMTP_FROM_EMAIL = os.getenv('SMTP_FROM_EMAIL', '').strip()
SMTP_FROM_NAME = os.getenv('SMTP_FROM_NAME', 'BetterCV').strip()
EMAIL_LOGIN_TOKEN_TTL_MINUTES = int(os.getenv('EMAIL_LOGIN_TOKEN_TTL_MINUTES', '30'))


def email_login_enabled():
    return bool(SMTP_HOST and SMTP_FROM_EMAIL)


def complete_login(user):
    login_user(user)
    session.permanent = True

    if user.consultant_id:
        session['consultant_id'] = user.consultant_id
    else:
        session.pop('consultant_id', None)


def create_email_login_token(user_id):
    conn = get_db_connection()
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=EMAIL_LOGIN_TOKEN_TTL_MINUTES)

    conn.execute(
        'DELETE FROM email_login_tokens WHERE used_at IS NOT NULL OR expires_at < ?',
        (now.isoformat(),)
    )

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()

    conn.execute(
        '''
            INSERT INTO email_login_tokens (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)
        ''',
        (user_id, token_hash, expires_at.isoformat())
    )
    conn.commit()
    conn.close()

    return raw_token


def consume_email_login_token(raw_token):
    if not raw_token:
        return None

    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
    conn = get_db_connection()
    token_row = conn.execute(
        '''
            SELECT id, user_id, expires_at, used_at
            FROM email_login_tokens
            WHERE token_hash = ?
        ''',
        (token_hash,)
    ).fetchone()

    if not token_row or token_row['used_at']:
        conn.close()
        return None

    expires_at = datetime.fromisoformat(token_row['expires_at'])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at < datetime.now(UTC):
        conn.close()
        return None

    cursor = conn.execute(
        'UPDATE email_login_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL',
        (datetime.now(UTC).isoformat(), token_row['id'])
    )
    conn.commit()
    conn.close()

    if cursor.rowcount != 1:
        return None

    return token_row['user_id']


def send_magic_link_email(recipient_email, login_link):
    import logging
    logger = logging.getLogger(__name__)
    logging.basicConfig(filename='bettercv.log', encoding='utf-8', level=logging.DEBUG)

    logger.debug(f"[EMAIL] send_magic_link_email called for: {recipient_email}")
    logger.debug(f"[EMAIL] email_login_enabled: {email_login_enabled()}")
    logger.debug(f"[EMAIL] SMTP_HOST: {SMTP_HOST}")
    logger.debug(f"[EMAIL] SMTP_PORT: {SMTP_PORT}")
    logger.debug(f"[EMAIL] SMTP_FROM_EMAIL: {SMTP_FROM_EMAIL}")
    logger.debug(f"[EMAIL] SMTP_USE_TLS: {SMTP_USE_TLS}")
    logger.debug(f"[EMAIL] SMTP_USE_SSL: {SMTP_USE_SSL}")
    logger.debug(f"[EMAIL] SMTP_USERNAME set: {bool(SMTP_USERNAME)}")
    logger.debug(f"[EMAIL] SMTP_PASSWORD set: {bool(SMTP_PASSWORD)}")

    if not email_login_enabled():
        logger.error("[EMAIL] Email login not enabled - SMTP_HOST or SMTP_FROM_EMAIL missing")
        return False

    message = EmailMessage()
    message['Subject'] = 'Your BetterCV sign-in link'
    message['From'] = f'{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>' if SMTP_FROM_NAME else SMTP_FROM_EMAIL
    message['To'] = recipient_email
    message.set_content(
        f"Use this one-time link to sign in to BetterCV:\n\n{login_link}\n\n"
        f"This link expires in {EMAIL_LOGIN_TOKEN_TTL_MINUTES} minutes and can only be used once."
    )
    logger.debug(f"[EMAIL] Email message created - From: {message['From']}, To: {message['To']}")

    try:
        logger.debug(f"[EMAIL] Attempting SMTP connection: host={SMTP_HOST}, port={SMTP_PORT}, ssl={SMTP_USE_SSL}, tls={SMTP_USE_TLS}")

        if SMTP_USE_SSL:
            logger.debug("[EMAIL] Using SMTP_SSL connection")
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
                logger.debug("[EMAIL] SMTP_SSL connection established")
                if SMTP_USERNAME:
                    logger.debug(f"[EMAIL] Authenticating as: {SMTP_USERNAME}")
                    smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
                    logger.debug("[EMAIL] Authentication successful")
                else:
                    logger.debug("[EMAIL] No authentication required (no username)")
                logger.debug("[EMAIL] Sending message...")
                smtp.send_message(message)
                logger.info(f"[EMAIL] Message sent successfully to {recipient_email}")
        else:
            logger.debug("[EMAIL] Using standard SMTP connection")
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
                logger.debug("[EMAIL] SMTP connection established")
                if SMTP_USE_TLS:
                    logger.debug("[EMAIL] Starting TLS...")
                    smtp.starttls()
                    logger.debug("[EMAIL] TLS started")
                else:
                    logger.debug("[EMAIL] TLS not enabled")

                if SMTP_USERNAME:
                    logger.debug(f"[EMAIL] Authenticating as: {SMTP_USERNAME}")
                    smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
                    logger.debug("[EMAIL] Authentication successful")
                else:
                    logger.debug("[EMAIL] No authentication required (no username)")

                logger.debug("[EMAIL] Sending message...")
                smtp.send_message(message)
                logger.info(f"[EMAIL] Message sent successfully to {recipient_email}")

        return True
    except smtplib.SMTPAuthenticationError as auth_err:
        logger.error(f"[EMAIL] SMTP Authentication failed: {str(auth_err)}")
        return False
    except smtplib.SMTPException as smtp_err:
        logger.error(f"[EMAIL] SMTP error: {str(smtp_err)}")
        return False
    except OSError as os_err:
        logger.error(f"[EMAIL] Connection error (network/DNS): {str(os_err)}")
        return False
    except Exception as e:
        logger.error(f"[EMAIL] Unexpected error sending magic-link email: {str(e)}")
        import traceback
        logger.error(f"[EMAIL] Traceback: {traceback.format_exc()}")
        return False

# Configure Google OAuth
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Configure Microsoft OAuth
microsoft = oauth.register(
    name='microsoft',
    client_id=os.getenv('MICROSOFT_CLIENT_ID'),
    client_secret=os.getenv('MICROSOFT_CLIENT_SECRET'),
    # authorize_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize',
    authorize_url='https://login.microsoftonline.com/39e6a0f2-2da0-42b2-8a33-476485f72038/oauth2/v2.0/authorize',
    authorize_params=None,
    # access_token_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
    access_token_url='https://login.microsoftonline.com/39e6a0f2-2da0-42b2-8a33-476485f72038/oauth2/v2.0/token',
    access_token_params=None,
    refresh_token_url=None,
    client_kwargs={
        'scope': 'openid email profile',
         'validate_iss': False
    },
    jwks_uri="https://login.microsoftonline.com/common/discovery/v2.0/keys"    
)

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return User.get_by_id(user_id)

# Load translations
TRANSLATIONS = {}
TRANSLATIONS_DIR = os.path.join(os.path.dirname(__file__), 'translations')

def load_translations():
    """Load all translation files."""
    for filename in os.listdir(TRANSLATIONS_DIR):
        if filename.endswith('.json'):
            lang_code = filename[:-5]  # Remove .json extension
            with open(os.path.join(TRANSLATIONS_DIR, filename), 'r', encoding='utf-8') as f:
                TRANSLATIONS[lang_code] = json.load(f)

load_translations()

def get_translation(key, lang=None):
    """Get translation for a key in the current language."""
    if lang is None:
        lang = session.get('language', 'en')
    
    keys = key.split('.')
    value = TRANSLATIONS.get(lang, TRANSLATIONS['en'])
    
    for k in keys:
        if isinstance(value, dict):
            value = value.get(k, key)
        else:
            return key
    
    return value

def format_markdown_text(text):
    """Convert simple markdown (lines starting with *) to HTML."""
    if not text:
        return text
    
    lines = text.strip().split('\n')
    result = []
    in_list = False
    
    for line in lines:
        line = line.strip()
        if not line:
            if in_list:
                result.append('</ul>')
                in_list = False
            result.append('<br>')
            continue
        
        if line.startswith('* '):
            if not in_list:
                result.append('<ul>')
                in_list = True
            result.append(f'<li>{line[2:]}</li>')
        else:
            if in_list:
                result.append('</ul>')
                in_list = False
            result.append(f'<p>{line}</p>')
    
    if in_list:
        result.append('</ul>')
    
    return '\n'.join(result)

def extract_list_items(text):
    """Extract bulleted list items from markdown text for Word export."""
    if not text:
        return [], []
    
    lines = text.strip().split('\n')
    list_items = []
    paragraph_items = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        if line.startswith('* '):
            list_items.append(line[2:])
        else:
            paragraph_items.append(line)
    
    return list_items, paragraph_items

@app.context_processor
def inject_translations():
    """Make translation function and current language available to all templates."""
    lang = session.get('language', 'en')
    conn = get_db_connection()
    consultants = get_consultants(conn)
    current_consultant_id = resolve_current_consultant_id(conn)
    current_consultant = None
    if current_consultant_id is not None:
        current_consultant = conn.execute(
            'SELECT id, display_name FROM consultants WHERE id = ?',
            (current_consultant_id,)
        ).fetchone()
    conn.close()

    return {
        't': TRANSLATIONS.get(lang, TRANSLATIONS['en']),
        'current_lang': lang,
        'current_user': current_user,
        'consultants': consultants,
        'current_consultant': current_consultant,
        'available_languages': {
            'en': 'English',
            'nl': 'Nederlands'
        },
        'format_markdown_text': format_markdown_text
    }

# Register custom Jinja filters
app.jinja_env.filters['format_markdown'] = format_markdown_text

@app.route('/set-language/<lang>')
def set_language(lang):
    """Set the user's language preference."""
    if lang in TRANSLATIONS:
        session['language'] = lang
    return redirect(request.referrer or url_for('index'))


# ==================== Authentication Routes ====================

@app.route('/login')
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template(
        'login.html',
        show_google_login=GOOGLE_OAUTH_ENABLED,
        show_microsoft_login=MICROSOFT_OAUTH_ENABLED,
        show_email_login=email_login_enabled()
    )


@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash(get_translation('messages.logged_out'), 'success')
    return redirect(url_for('login'))


@app.route('/auth/google')
def auth_google():
    """Initiate Google OAuth"""
    if not GOOGLE_OAUTH_ENABLED:
        flash(get_translation('messages.oauth_not_configured'), 'error')
        return redirect(url_for('login'))

    # redirect_uri = url_for('auth_google_callback', _external=True)
    redirect_uri = (os.getenv('BASE_URL') + os.getenv('GOOGLE_OAUTH_REDIRECT_URI')) or url_for('auth_google_callback', _external=True)

    return google.authorize_redirect(redirect_uri)


@app.route('/auth/google/callback')
def auth_google_callback():
    """Google OAuth callback"""
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            flash(get_translation('messages.oauth_failed'), 'error')
            return redirect(url_for('login'))
        
        email = user_info.get('email')
        name = user_info.get('name')
        oauth_id = user_info.get('sub')
        
        # Check if user exists
        user = User.get_by_email(email)
        
        if not user:
            # Check whitelist and create user
            user = User.create_user(email, name, 'google', oauth_id)
            if not user:
                flash(get_translation('messages.not_whitelisted'), 'error')
                return redirect(url_for('login'))
        
        # Update last login
        User.update_last_login(user.id)
        
        # Log in user
        complete_login(user)
        flash(get_translation('messages.login_success'), 'success')
        
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"OAuth error: {str(e)}")
        flash(get_translation('messages.oauth_error'), 'error')
        return redirect(url_for('login'))


@app.route('/auth/microsoft')
def auth_microsoft():
    """Initiate Microsoft OAuth"""
    if not MICROSOFT_OAUTH_ENABLED:
        flash(get_translation('messages.oauth_not_configured'), 'error')
        return redirect(url_for('login'))

    # redirect_uri = url_for('auth_microsoft_callback', _external=True)
    redirect_uri = (os.getenv('BASE_URL') + os.getenv('MICROSOFT_OAUTH_REDIRECT_URI')) or url_for('auth_microsoft_callback', _external=True)
    print(f"Initiating Microsoft OAuth, redirect_uri: {redirect_uri}")
    return microsoft.authorize_redirect(redirect_uri)


@app.route('/auth/microsoft/callback')
def auth_microsoft_callback():
    """Microsoft OAuth callback"""
    try:
        token = microsoft.authorize_access_token()
        
        # Get user info from Microsoft Graph API
        resp = microsoft.get('https://graph.microsoft.com/v1.0/me', token=token)
        user_info = resp.json()
        
        email = user_info.get('mail') or user_info.get('userPrincipalName')
        name = user_info.get('displayName')
        oauth_id = user_info.get('id')
        
        if not email:
            print(f"Microsoft OAuth response missing email: {user_info}, json: {resp.text}")
            flash(get_translation('messages.oauth_failed'), 'error')
            return redirect(url_for('login'))
        
        # Check if user exists
        user = User.get_by_email(email)
        
        if not user:
            # Check whitelist and create user
            user = User.create_user(email, name, 'microsoft', oauth_id)
            if not user:
                flash(get_translation('messages.not_whitelisted'), 'error')
                return redirect(url_for('login'))
        
        # Update last login
        User.update_last_login(user.id)
        
        # Log in user
        complete_login(user)
        flash(get_translation('messages.login_success'), 'success')
        
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"OAuth error: {str(e)}")
        flash(get_translation('messages.oauth_error'), 'error')
        return redirect(url_for('login'))


@app.route('/auth/email/request', methods=['POST'])
def auth_email_request():
    """Send one-time login link to existing user by e-mail."""
    import logging
    logger = logging.getLogger(__name__)
    logging.basicConfig(filename='bettercv.log', encoding='utf-8', level=logging.DEBUG)

    logger.debug("[AUTH_EMAIL] auth_email_request called")

    if not email_login_enabled():
        logger.error("[AUTH_EMAIL] Email login not enabled")
        flash(get_translation('messages.email_login_not_configured'), 'error')
        return redirect(url_for('login'))

    email = (request.form.get('email') or '').strip().lower()
    logger.debug(f"[AUTH_EMAIL] Email requested: {email}")

    if not email:
        logger.warning("[AUTH_EMAIL] No email provided")
        flash(get_translation('messages.email_required'), 'error')
        return redirect(url_for('login'))

    user = User.get_by_email(email)
    logger.debug(f"[AUTH_EMAIL] User lookup result: {bool(user)}")

    if not user:
        logger.debug(f"[AUTH_EMAIL] No user found for {email}, checking whitelist...")
        whitelist_entry = User.is_whitelisted(email)
        
        if not whitelist_entry:
            domain = User._get_email_domain(email)
            auto_domains = User._get_auto_whitelist_domains()
            if domain and domain in auto_domains:
                logger.info(f"[AUTH_EMAIL] Domain {domain} is auto-whitelisted, adding to whitelist")
                from auth import add_to_whitelist
                add_to_whitelist(email, 'consultant', notes='Auto-whitelisted by domain (email login)')
                whitelist_entry = User.is_whitelisted(email)
            else:
                logger.debug(f"[AUTH_EMAIL] Email {email} and domain not whitelisted")
        
        if whitelist_entry:
            logger.info(f"[AUTH_EMAIL] Email {email} is whitelisted, creating user")
            user = User.create_user(email, None, 'email', None)
            if user:
                logger.info(f"[AUTH_EMAIL] User created for {email}, user_id={user.id}")
            else:
                logger.error(f"[AUTH_EMAIL] Failed to create user for {email}")
        else:
            logger.debug(f"[AUTH_EMAIL] Email {email} not whitelisted (security: not exposing this to user)")

    if user:
        logger.info(f"[AUTH_EMAIL] User ready for {email}, user_id={user.id}")
        token = create_email_login_token(user.id)
        logger.debug(f"[AUTH_EMAIL] Token created (hash only, not logged)")

        login_link = url_for('auth_email_verify', token=token, _external=True)
        logger.debug(f"[AUTH_EMAIL] Login link generated")

        sent = send_magic_link_email(email, login_link)
        logger.info(f"[AUTH_EMAIL] Email send result: {sent}")

        if not sent:
            logger.error(f"[AUTH_EMAIL] Failed to send email to {email}")
            flash(get_translation('messages.email_login_send_failed'), 'error')
            return redirect(url_for('login'))
        else:
            logger.info(f"[AUTH_EMAIL] Email successfully sent to {email}")
    else:
        logger.debug(f"[AUTH_EMAIL] User not eligible or not found for {email}")

    flash(get_translation('messages.email_login_link_sent'), 'success')
    logger.debug("[AUTH_EMAIL] Generic success message shown to user")
    return redirect(url_for('login'))


@app.route('/auth/email/verify')
def auth_email_verify():
    """Validate one-time login token and sign in user."""
    import logging
    logger = logging.getLogger(__name__)

    logger.debug("[AUTH_EMAIL_VERIFY] auth_email_verify called")

    token = (request.args.get('token') or '').strip()
    logger.debug(f"[AUTH_EMAIL_VERIFY] Token present: {bool(token)}")

    if not token:
        logger.warning("[AUTH_EMAIL_VERIFY] No token provided")
        flash(get_translation('messages.email_login_invalid_token'), 'error')
        return redirect(url_for('login'))

    user_id = consume_email_login_token(token)
    logger.debug(f"[AUTH_EMAIL_VERIFY] Token validation result: {bool(user_id)}")

    if not user_id:
        logger.warning("[AUTH_EMAIL_VERIFY] Invalid or expired token")
        flash(get_translation('messages.email_login_invalid_token'), 'error')
        return redirect(url_for('login'))

    user = User.get_by_id(user_id)
    logger.debug(f"[AUTH_EMAIL_VERIFY] User lookup result: {bool(user)}")

    if not user:
        logger.error(f"[AUTH_EMAIL_VERIFY] User not found for valid token user_id={user_id}")
        flash(get_translation('messages.email_login_invalid_token'), 'error')
        return redirect(url_for('login'))

    logger.info(f"[AUTH_EMAIL_VERIFY] Valid token for user: {user.email}")
    User.update_last_login(user.id)
    complete_login(user)
    flash(get_translation('messages.login_success'), 'success')
    logger.info(f"[AUTH_EMAIL_VERIFY] User {user.email} logged in successfully via email link")
    return redirect(url_for('index'))


# ==================== Admin Routes ====================

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    users = get_all_users()
    whitelist = get_all_whitelist()
    skill_categories = get_skill_categories()
    return render_template('admin.html', 
                         users=users, 
                         whitelist=whitelist,
                         skill_categories=skill_categories)


@app.route('/consultants-management')
@admin_required
def consultants_management():
    """Consultants management page"""
    conn = get_db_connection()
    consultants = get_consultants_with_completeness(conn)
    conn.close()

    active_consultants = [
        consultant for consultant in consultants
        if consultant.get('actively_searching_for_assignment')
    ]
    inactive_consultants = [
        consultant for consultant in consultants
        if not consultant.get('actively_searching_for_assignment')
    ]

    return render_template('consultants_management.html',
                         all_consultants=consultants,
                         active_consultants=active_consultants,
                         inactive_consultants=inactive_consultants)


@app.route('/admin/skill-categories/add', methods=['POST'])
@admin_required
def admin_add_skill_category():
    """Add new skill category."""
    name = request.form.get('name')
    
    if name:
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO skill_categories (name) VALUES (?)',
                (name,)
            )
            conn.commit()
            flash(get_translation('messages.category_added'), 'success')
        except sqlite3.IntegrityError:
            flash(get_translation('messages.category_exists'), 'error')
        conn.close()
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/skill-categories/delete/<int:category_id>', methods=['POST'])
@admin_required
def admin_delete_skill_category(category_id):
    """Delete skill category."""
    conn = get_db_connection()
    # Check if category is used in experience records
    experience_usage = conn.execute('''
        SELECT COUNT(*) 
        FROM experience_skills es 
        JOIN skills s ON es.skill_id = s.id 
        WHERE s.category_id = ?
    ''', (category_id,)).fetchone()[0]
    
    # Check if category is assigned to any skills (FK safety)
    skill_usage = conn.execute('SELECT COUNT(*) FROM skills WHERE category_id = ?', (category_id,)).fetchone()[0]
    
    if experience_usage > 0:
        flash(get_translation('messages.category_referenced_by_experience'), 'error')
    elif skill_usage > 0:
        flash(get_translation('messages.category_in_use'), 'error')
    else:
        conn.execute('DELETE FROM skill_categories WHERE id = ?', (category_id,))
        conn.commit()
        flash(get_translation('messages.category_deleted'), 'success')
    conn.close()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/whitelist/add', methods=['POST'])
@admin_required
def admin_add_whitelist():
    """Add email to whitelist"""
    email = request.form.get('email')
    role = request.form.get('role', 'consultant')
    notes = request.form.get('notes', '')
    
    success, message = add_to_whitelist(email, role, current_user.id, notes)
    
    if success:
        flash(get_translation('messages.whitelist_added'), 'success')
    else:
        flash(f"{get_translation('messages.whitelist_error')}: {message}", 'error')
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/whitelist/remove/<int:whitelist_id>', methods=['POST'])
@admin_required
def admin_remove_whitelist(whitelist_id):
    """Remove email from whitelist"""
    remove_from_whitelist(whitelist_id)
    flash(get_translation('messages.whitelist_removed'), 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/update-role/<int:user_id>', methods=['POST'])
@admin_required
def admin_update_user_role(user_id):
    """Update user role"""
    new_role = request.form.get('role')
    update_user_role(user_id, new_role)
    flash(get_translation('messages.user_role_updated'), 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/deactivate/<int:user_id>', methods=['POST'])
@admin_required
def admin_deactivate_user(user_id):
    """Deactivate user account"""
    if user_id == current_user.id:
        flash(get_translation('messages.cannot_deactivate_self'), 'error')
    else:
        # Get the user being deactivated to check their role
        conn = get_db_connection()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        
        if user and user['role'] == 'admin':
            flash(get_translation('messages.cannot_deactivate_admin'), 'error')
        else:
            deactivate_user(user_id)
            flash(get_translation('messages.user_deactivated'), 'success')
    return redirect(url_for('admin_dashboard'))


def get_consultants(conn):
    """Retrieve all consultants ordered by display name."""
    if current_user.is_authenticated and not current_user.is_admin():
        if not current_user.consultant_id:
            return []
        return conn.execute(
            'SELECT id, display_name FROM consultants WHERE id = ? ORDER BY display_name, id',
            (current_user.consultant_id,)
        ).fetchall()

    return conn.execute(
        'SELECT id, display_name FROM consultants ORDER BY display_name, id'
    ).fetchall()


def get_consultants_with_completeness(conn):
    """Retrieve all consultants with section completeness metadata."""
    rows = conn.execute('''
        SELECT
            c.id,
            c.display_name,
            COALESCE((
                SELECT pi.actively_searching_for_assignment
                FROM personal_info pi
                WHERE pi.consultant_id = c.id
                ORDER BY pi.id DESC
                LIMIT 1
            ), 1) AS actively_searching_for_assignment,
            CASE WHEN EXISTS (SELECT 1 FROM personal_info pi WHERE pi.consultant_id = c.id) THEN 1 ELSE 0 END AS has_personal_info,
            CASE WHEN EXISTS (SELECT 1 FROM work_experience we WHERE we.consultant_id = c.id) THEN 1 ELSE 0 END AS has_work_experience,
            CASE WHEN EXISTS (SELECT 1 FROM education e WHERE e.consultant_id = c.id) THEN 1 ELSE 0 END AS has_education,
            CASE WHEN EXISTS (SELECT 1 FROM skills s WHERE s.consultant_id = c.id) THEN 1 ELSE 0 END AS has_skills,
            CASE WHEN EXISTS (SELECT 1 FROM projects p WHERE p.consultant_id = c.id) THEN 1 ELSE 0 END AS has_projects,
            CASE WHEN EXISTS (SELECT 1 FROM certifications cert WHERE cert.consultant_id = c.id) THEN 1 ELSE 0 END AS has_certifications
        FROM consultants c
        ORDER BY c.display_name, c.id
    ''').fetchall()

    total_sections = 6
    consultants = []

    for row in rows:
        consultant = dict(row)
        completed_sections = sum([
            consultant['has_personal_info'],
            consultant['has_work_experience'],
            consultant['has_education'],
            consultant['has_skills'],
            consultant['has_projects'],
            consultant['has_certifications']
        ])
        consultant['completed_sections'] = completed_sections
        consultant['total_sections'] = total_sections
        consultant['completeness_pct'] = round((completed_sections / total_sections) * 100)
        consultants.append(consultant)

    return consultants


def resolve_current_consultant_id(conn):
    if current_user.is_authenticated and not current_user.is_admin():
        if not current_user.consultant_id:
            return None

        own_consultant = conn.execute(
            'SELECT id FROM consultants WHERE id = ?',
            (current_user.consultant_id,)
        ).fetchone()
        if not own_consultant:
            return None

        session['consultant_id'] = current_user.consultant_id
        return current_user.consultant_id

    consultant_id = session.get('consultant_id')
    if consultant_id:
        existing = conn.execute(
            'SELECT id FROM consultants WHERE id = ?',
            (consultant_id,)
        ).fetchone()
        if existing:
            return consultant_id

    first = conn.execute(
        'SELECT id FROM consultants ORDER BY display_name, id LIMIT 1'
    ).fetchone()
    if first:
        session['consultant_id'] = first['id']
        return first['id']

    return None


def flash_foreign_data_access_warning():
    flash(get_translation('messages.foreign_data_access_denied'), 'warning')


def audit_foreign_data_access(table_name, record_id):
    user_id = getattr(current_user, 'id', None)
    user_email = getattr(current_user, 'email', None)
    app.logger.warning(
        'Unauthorized data access attempt: user_id=%s email=%s role=%s consultant_id=%s table=%s record_id=%s endpoint=%s path=%s ip=%s',
        user_id,
        user_email,
        getattr(current_user, 'role', None),
        getattr(current_user, 'consultant_id', None),
        table_name,
        record_id,
        request.endpoint,
        request.path,
        request.remote_addr
    )


def get_editable_record(conn, table_name, record_id, consultant_id, not_found_message_key='messages.record_not_found'):
    """Get a record for editing/deleting with ownership checks for consultants."""
    if current_user.is_admin():
        record = conn.execute(
            f'SELECT * FROM {table_name} WHERE id = ?',
            (record_id,)
        ).fetchone()
        if not record:
            flash(get_translation(not_found_message_key), 'error')
        return record

    record = conn.execute(
        f'SELECT * FROM {table_name} WHERE id = ? AND consultant_id = ?',
        (record_id, consultant_id)
    ).fetchone()
    if record:
        return record

    existing = conn.execute(
        f'SELECT id FROM {table_name} WHERE id = ?',
        (record_id,)
    ).fetchone()
    if existing:
        audit_foreign_data_access(table_name, record_id)
        flash_foreign_data_access_warning()
    else:
        flash(get_translation(not_found_message_key), 'error')

    return None


def filter_skill_ids_for_consultant(conn, consultant_id, raw_skill_ids):
    """Return only skill ids that belong to the provided consultant."""
    skill_ids = []
    for raw_skill_id in raw_skill_ids:
        try:
            skill_id = int(raw_skill_id)
        except (TypeError, ValueError):
            continue
        if skill_id not in skill_ids:
            skill_ids.append(skill_id)

    if not skill_ids:
        return []

    placeholders = ','.join(['?'] * len(skill_ids))
    rows = conn.execute(
        f'SELECT id FROM skills WHERE consultant_id = ? AND id IN ({placeholders})',
        [consultant_id, *skill_ids]
    ).fetchall()
    return [row['id'] for row in rows]


@app.before_request
def ensure_consultant_selected():
    if request.endpoint in {
        'static',
        'set_language',
        'full_json_download',
        'list_consultants',
        'add_consultant',
        'switch_consultant',
        'import_consultant',
        'export_consultant',
        'parse_cv',
        'assignments',
        'assignment_match',
        'review_parsed_cv',
        'import_parsed_cv',
        'export_cv',
        'preview_cv',
        'export_cv_download',
        'consultants_management',
        'admin_dashboard',
        'admin_add_whitelist',
        'admin_remove_whitelist',
        'admin_update_user_role',
        'admin_deactivate_user',
        'admin_add_skill_category',
        'admin_delete_skill_category',
        'delete_consultant'
    }:
        return None

    if current_user.is_authenticated and not current_user.is_admin():
        if current_user.consultant_id:
            session['consultant_id'] = current_user.consultant_id
            return None
        flash(get_translation('messages.user_no_consultant_access'), 'error')
        logout_user()
        session.pop('consultant_id', None)
        return redirect(url_for('login'))

    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    conn.close()

    if consultant_id is None:
        return redirect(url_for('consultants_management'))

    return None


# ==================== AI Configuration and CV Parsing ====================

# Configure Gemini AI - Set your API key as environment variable
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
genai_client = None
if GEMINI_API_KEY:
    genai_client = genai.Client(api_key=GEMINI_API_KEY)

# Configure Groq AI
GROQ_API_KEY = os.getenv('GROQ_API_KEY')
groq_client = None
if GROQ_API_KEY:
    groq_client = Groq(api_key=GROQ_API_KEY)

# Configure Ollama (local by default)
OLLAMA_ENABLED = env_flag('OLLAMA_ENABLED', True)
OLLAMA_BASE_URL = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434').strip().rstrip('/')
OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'orca2').strip() or 'orca2'
OLLAMA_TIMEOUT_SECONDS = int(os.getenv('OLLAMA_TIMEOUT_SECONDS', '180'))

# ==================== CV Parsing Data Storage ====================

def get_cv_temp_dir():
    """Get or create the temporary directory for CV parsing data."""
    temp_dir = os.path.join(tempfile.gettempdir(), 'bettercv_cv_parsing')
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir


def store_parsed_cv_data(parsed_data, cv_text_preview):
    """Store parsed CV data in a temporary file and return the ID."""
    cv_id = str(uuid.uuid4())
    temp_dir = get_cv_temp_dir()
    temp_file = os.path.join(temp_dir, f'{cv_id}.json')
    
    data_to_store = {
        'parsed_data': parsed_data,
        'cv_text_preview': cv_text_preview,
        'created_at': datetime.now().isoformat()
    }
    
    with open(temp_file, 'w', encoding='utf-8') as f:
        json.dump(data_to_store, f)
    
    return cv_id


def retrieve_parsed_cv_data(cv_id):
    """Retrieve parsed CV data from temporary file."""
    temp_dir = get_cv_temp_dir()
    temp_file = os.path.join(temp_dir, f'{cv_id}.json')
    
    if not os.path.exists(temp_file):
        return None, None
    
    try:
        with open(temp_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data.get('parsed_data'), data.get('cv_text_preview')
    except (json.JSONDecodeError, IOError):
        return None, None


def delete_parsed_cv_data(cv_id):
    """Delete temporary CV parsing data file."""
    temp_dir = get_cv_temp_dir()
    temp_file = os.path.join(temp_dir, f'{cv_id}.json')
    
    try:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    except OSError:
        pass  # Silently ignore if file can't be deleted


def extract_text_from_pdf(file_content):
    """Extract text from PDF file."""
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_content))
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        return text.strip()
    except Exception as e:
        return f"Error reading PDF: {str(e)}"


def extract_text_from_docx(file_content):
    """Extract text from DOCX file."""
    try:
        doc = docx.Document(io.BytesIO(file_content))
        text = ""
        for paragraph in doc.paragraphs:
            text += paragraph.text + "\n"
        return text.strip()
    except Exception as e:
        return f"Error reading DOCX: {str(e)}"


def extract_text_from_file(file):
    """Extract text from uploaded file based on file type."""
    filename = file.filename.lower()
    file_content = file.read()
    file.seek(0)  # Reset file pointer
    
    if filename.endswith('.pdf'):
        result = extract_text_from_pdf(file_content)
    elif filename.endswith(('.docx', '.doc')):
        result = extract_text_from_docx(file_content)
    elif filename.endswith('.txt'):
        result = file_content.decode('utf-8', errors='ignore')
    else:
        result = "Unsupported file type. Please upload PDF, DOCX, or TXT files."
    
    with open(os.path.join(get_cv_temp_dir(), 'last_uploaded_cv.txt'), 'w', encoding='utf-8') as f:
        f.write(result)  # Store a preview of the last uploaded CV for debugging

    return result


def parse_cv_with_ai(cv_text, provider='gemini'):
    """Parse CV text using chosen AI provider and return structured data."""
    prompt = get_cv_parse_prompt(cv_text)
    provider = (provider or 'gemini').strip().lower()
    
    if provider == 'gemini':
        if not GEMINI_API_KEY or genai_client is None:
            return None, "Gemini API key not configured."
        
        try:
            response = genai_client.models.generate_content(
                model='gemini-flash-latest',
                contents=prompt
            )
            if not response.text:
                return None, "No response from Gemini AI"
            json_text = response.text
        except Exception as e:
            return None, f"Gemini error: {str(e)}"
            
    elif provider == 'groq':
        if not GROQ_API_KEY or groq_client is None:
            return None, "Groq API key not configured."
            
        try:
            response = groq_client.chat.completions.create(
                model='llama-3.3-70b-versatile',
                messages=[
                    {"role": "system", "content": "You are a specialized CV parsing assistant. Always respond with valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            json_text = response.choices[0].message.content
        except Exception as e:
            return None, f"Groq error: {str(e)}"
    elif provider == 'ollama':
        if not OLLAMA_ENABLED:
            return None, "Ollama provider is disabled."

        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": "You are a specialized CV parsing assistant. Always respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            "format": "json",
            "stream": False
        }

        request_body = json.dumps(payload).encode('utf-8')
        api_url = f"{OLLAMA_BASE_URL}/api/chat"
        ollama_request = urllib.request.Request(
            api_url,
            data=request_body,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        try:
            with urllib.request.urlopen(ollama_request, timeout=OLLAMA_TIMEOUT_SECONDS) as response:
                response_data = json.loads(response.read().decode('utf-8'))

            json_text = response_data.get('message', {}).get('content', '').strip()
            if not json_text:
                return None, "No response from Ollama"
        except urllib.error.HTTPError as e:
            return None, f"Ollama HTTP error: {e.code} {e.reason}"
        except urllib.error.URLError as e:
            return None, f"Ollama connection error: {e.reason}"
        except Exception as e:
            return None, f"Ollama error: {str(e)}"
    else:
        return None, f"Unknown AI provider: {provider}"

    # Try to parse the JSON response
    try:
        # Clean up the response text (remove markdown formatting if present)
        json_text = json_text.strip()
        if json_text.startswith('```json'):
            json_text = json_text[7:]
        if json_text.endswith('```'):
            json_text = json_text[:-3]
        
        parsed_data = json.loads(json_text)
        return parsed_data, None
    except json.JSONDecodeError as e:
        return None, f"Failed to parse AI response as JSON: {str(e)}\nResponse: {json_text[:200]}..."


def match_assignment_with_ai(assignment_description, consultant_payloads, provider='gemini'):
    """Match assignment text against selected consultant profiles using AI."""
    consultants_json = json.dumps(consultant_payloads, indent=2, ensure_ascii=False)
    prompt = get_assignment_match_prompt(assignment_description, consultants_json)
    provider = (provider or 'gemini').strip().lower()

    if provider == 'gemini':
        if not GEMINI_API_KEY or genai_client is None:
            return None, consultants_json, "Gemini API key not configured."

        try:
            response = genai_client.models.generate_content(
                model='gemini-flash-latest',
                contents=prompt
            )
            if not response.text:
                return None, consultants_json, "No response from Gemini AI"
            return response.text, consultants_json, None
        except Exception as e:
            return None, consultants_json, f"Gemini error: {str(e)}"

    if provider == 'groq':
        if not GROQ_API_KEY or groq_client is None:
            return None, consultants_json, "Groq API key not configured."

        try:
            response = groq_client.chat.completions.create(
                model='llama-3.3-70b-versatile',
                messages=[
                    {"role": "system", "content": "You are a recruitment matching assistant."},
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content, consultants_json, None
        except Exception as e:
            return None, consultants_json, f"Groq error: {str(e)}"

    if provider == 'ollama':
        if not OLLAMA_ENABLED:
            return None, consultants_json, "Ollama provider is disabled."

        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": "You are a recruitment matching assistant. Return valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            "format": "json",
            "stream": False
        }

        request_body = json.dumps(payload).encode('utf-8')
        api_url = f"{OLLAMA_BASE_URL}/api/chat"
        ollama_request = urllib.request.Request(
            api_url,
            data=request_body,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        try:
            with urllib.request.urlopen(ollama_request, timeout=OLLAMA_TIMEOUT_SECONDS) as response:
                response_data = json.loads(response.read().decode('utf-8'))

            match_text = response_data.get('message', {}).get('content', '').strip()
            if not match_text:
                return None, consultants_json, "No response from Ollama"
            return match_text, consultants_json, None
        except urllib.error.HTTPError as e:
            return None, consultants_json, f"Ollama HTTP error: {e.code} {e.reason}"
        except urllib.error.URLError as e:
            return None, consultants_json, f"Ollama connection error: {e.reason}"
        except Exception as e:
            return None, consultants_json, f"Ollama error: {str(e)}"

    return None, consultants_json, f"Unknown AI provider: {provider}"


def parse_assignment_with_ai(assignment_text, provider='gemini'):
    """Parse assignment text into structured JSON using chosen AI provider."""
    prompt = get_assignment_parse_prompt(assignment_text)
    provider = (provider or 'gemini').strip().lower()

    if provider == 'gemini':
        if not GEMINI_API_KEY or genai_client is None:
            return None, None, "Gemini API key not configured."

        try:
            response = genai_client.models.generate_content(
                model='gemini-flash-latest',
                contents=prompt
            )
            if not response.text:
                return None, None, "No response from Gemini AI"
            raw_text = response.text
        except Exception as e:
            return None, None, f"Gemini error: {str(e)}"

    elif provider == 'groq':
        if not GROQ_API_KEY or groq_client is None:
            return None, None, "Groq API key not configured."

        try:
            response = groq_client.chat.completions.create(
                model='llama-3.3-70b-versatile',
                messages=[
                    {"role": "system", "content": "You are an assignment parsing assistant. Always return valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            raw_text = response.choices[0].message.content
        except Exception as e:
            return None, None, f"Groq error: {str(e)}"

    elif provider == 'ollama':
        if not OLLAMA_ENABLED:
            return None, None, "Ollama provider is disabled."

        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": "You are an assignment parsing assistant. Return valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            "format": "json",
            "stream": False
        }

        request_body = json.dumps(payload).encode('utf-8')
        api_url = f"{OLLAMA_BASE_URL}/api/chat"
        ollama_request = urllib.request.Request(
            api_url,
            data=request_body,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        try:
            with urllib.request.urlopen(ollama_request, timeout=OLLAMA_TIMEOUT_SECONDS) as response:
                response_data = json.loads(response.read().decode('utf-8'))

            raw_text = response_data.get('message', {}).get('content', '').strip()
            if not raw_text:
                return None, None, "No response from Ollama"
        except urllib.error.HTTPError as e:
            return None, None, f"Ollama HTTP error: {e.code} {e.reason}"
        except urllib.error.URLError as e:
            return None, None, f"Ollama connection error: {e.reason}"
        except Exception as e:
            return None, None, f"Ollama error: {str(e)}"
    else:
        return None, None, f"Unknown AI provider: {provider}"

    clean_text = raw_text.strip()
    if clean_text.startswith('```json'):
        clean_text = clean_text[7:]
    elif clean_text.startswith('```'):
        clean_text = clean_text[3:]
    if clean_text.endswith('```'):
        clean_text = clean_text[:-3]
    clean_text = clean_text.strip()

    try:
        return json.loads(clean_text), raw_text, None
    except json.JSONDecodeError as e:
        return None, raw_text, f"Failed to parse AI response as JSON: {str(e)}"


def normalize_iso_date(value):
    """Normalize date values to YYYY-MM-DD, return empty string when invalid."""
    if not value:
        return ''
    value_str = str(value).strip()
    if not value_str:
        return ''
    try:
        return datetime.strptime(value_str, '%Y-%m-%d').strftime('%Y-%m-%d')
    except ValueError:
        return ''


def parse_date_value(value):
    """Parse a date-ish value into a date object when possible."""
    if value is None:
        return None

    value_str = str(value).strip()
    if not value_str:
        return None

    # Most stored values are YYYY-MM-DD or datetime strings starting with it.
    if len(value_str) >= 10:
        try:
            return datetime.strptime(value_str[:10], '%Y-%m-%d').date()
        except ValueError:
            pass

    try:
        parsed = datetime.fromisoformat(value_str.replace('Z', '+00:00'))
        return parsed.date()
    except ValueError:
        return None


def format_year_month(value):
    """Format a stored date value as YYYY-MM for CV rendering."""
    date_value = parse_date_value(value)
    if date_value is not None:
        return date_value.strftime('%Y-%m')

    value_str = str(value or '').strip()
    if len(value_str) >= 7:
        return value_str[:7]
    return ''


def is_assignment_active(assignment_row, reference_date=None):
    """Return True when assignment is still valid for matching dropdown selection."""
    today = reference_date or datetime.now(UTC).date()

    deadline_date = parse_date_value(assignment_row.get('deadline'))
    if deadline_date is not None:
        return deadline_date >= today

    created_date = parse_date_value(assignment_row.get('created_at'))
    if created_date is None:
        # Keep legacy rows without a parseable timestamp available.
        return True

    return created_date >= (today - timedelta(days=14))


def get_active_assignment_for_matching(conn, assignment_id):
    """Fetch an assignment only when it is still active for matching."""
    assignment_row = conn.execute(
        'SELECT * FROM assignments WHERE id = ?',
        (assignment_id,)
    ).fetchone()
    if not assignment_row:
        return None

    assignment_dict = dict(assignment_row)
    if not is_assignment_active(assignment_dict):
        return None

    return assignment_dict


def normalize_assignment_list(value):
    """Normalize list-like assignment fields to a clean list of strings."""
    if isinstance(value, list):
        result = []
        for item in value:
            item_text = str(item).strip()
            if item_text:
                result.append(item_text)
        return result

    if isinstance(value, str):
        parts = re.split(r'\r?\n|;', value)
        if len(parts) == 1:
            parts = [p.strip() for p in value.split(',')]
        return [part.strip() for part in parts if part and part.strip()]

    return []


def normalize_assignment_number(value):
    """Normalize numeric assignment field to float or None."""
    if value is None or value == '':
        return None
    if isinstance(value, (int, float)):
        return float(value)

    value_str = str(value).strip().replace(',', '.')
    if not value_str:
        return None

    try:
        return float(value_str)
    except ValueError:
        return None


def normalize_assignment_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}


def normalize_assignment_payload(raw_payload):
    """Normalize parsed assignment payload to app storage schema."""
    payload = raw_payload or {}
    assignment = payload.get('assignment') if isinstance(payload, dict) else {}
    contact = payload.get('contact') if isinstance(payload, dict) else {}

    if not isinstance(assignment, dict):
        assignment = {}
    if not isinstance(contact, dict):
        contact = {}

    start_date = normalize_iso_date(assignment.get('start_date'))
    deadline = normalize_iso_date(assignment.get('deadline'))
    deadline_estimated = normalize_assignment_bool(assignment.get('deadline_estimated'))

    if not deadline and start_date:
        start_dt = datetime.strptime(start_date, '%Y-%m-%d')
        deadline = (start_dt - timedelta(days=7)).strftime('%Y-%m-%d')
        deadline_estimated = True
    elif not deadline:
        deadline_estimated = True

    return {
        'title': str(assignment.get('title', '')).strip(),
        'description': str(assignment.get('description', '')).strip(),
        'reference_id': str(assignment.get('reference_id', '')).strip(),
        'hot_seat': str(assignment.get('hot_seat', '')).strip(),
        'hourly_rate_min': normalize_assignment_number(assignment.get('hourly_rate_min')),
        'hourly_rate_max': normalize_assignment_number(assignment.get('hourly_rate_max')),
        'hourly_rate': normalize_assignment_number(assignment.get('hourly_rate')),
        'knock_out_criteria': normalize_assignment_list(assignment.get('knock_out_criteria')),
        'nice_to_have_criteria': normalize_assignment_list(assignment.get('nice_to_have_criteria')),
        'competenties': normalize_assignment_list(assignment.get('competenties')),
        'deadline': deadline,
        'deadline_estimated': deadline_estimated,
        'start_date': start_date,
        'recruiter_name': str(contact.get('recruiter_name', '')).strip(),
        'recruiter_email': str(contact.get('recruiter_email', '')).strip(),
        'recruiter_phone': str(contact.get('recruiter_phone', '')).strip()
    }


def get_assignment_form_from_request(form_data):
    """Build assignment form model from submitted request data."""
    return {
        'title': (form_data.get('title') or '').strip(),
        'description': (form_data.get('description') or '').strip(),
        'reference_id': (form_data.get('reference_id') or '').strip(),
        'source_text': (form_data.get('source_text') or '').strip(),
        'hot_seat': (form_data.get('hot_seat') or '').strip(),
        'hourly_rate_min': (form_data.get('hourly_rate_min') or '').strip(),
        'hourly_rate_max': (form_data.get('hourly_rate_max') or '').strip(),
        'hourly_rate': (form_data.get('hourly_rate') or '').strip(),
        'knock_out_criteria_text': (form_data.get('knock_out_criteria_text') or '').strip(),
        'nice_to_have_criteria_text': (form_data.get('nice_to_have_criteria_text') or '').strip(),
        'competenties_text': (form_data.get('competenties_text') or '').strip(),
        'deadline': (form_data.get('deadline') or '').strip(),
        'deadline_estimated': bool(form_data.get('deadline_estimated')),
        'start_date': (form_data.get('start_date') or '').strip(),
        'recruiter_name': (form_data.get('recruiter_name') or '').strip(),
        'recruiter_email': (form_data.get('recruiter_email') or '').strip(),
        'recruiter_phone': (form_data.get('recruiter_phone') or '').strip()
    }


def apply_normalized_assignment_to_form(form_model, normalized_assignment):
    """Update assignment form model with normalized assignment values."""
    form_model['title'] = normalized_assignment.get('title', '')
    form_model['description'] = normalized_assignment.get('description', '')
    form_model['reference_id'] = normalized_assignment.get('reference_id', '')
    form_model['hot_seat'] = normalized_assignment.get('hot_seat', '')
    form_model['hourly_rate_min'] = '' if normalized_assignment.get('hourly_rate_min') is None else str(normalized_assignment.get('hourly_rate_min'))
    form_model['hourly_rate_max'] = '' if normalized_assignment.get('hourly_rate_max') is None else str(normalized_assignment.get('hourly_rate_max'))
    form_model['hourly_rate'] = '' if normalized_assignment.get('hourly_rate') is None else str(normalized_assignment.get('hourly_rate'))
    form_model['knock_out_criteria_text'] = '\n'.join(normalized_assignment.get('knock_out_criteria', []))
    form_model['nice_to_have_criteria_text'] = '\n'.join(normalized_assignment.get('nice_to_have_criteria', []))
    form_model['competenties_text'] = '\n'.join(normalized_assignment.get('competenties', []))
    form_model['deadline'] = normalized_assignment.get('deadline', '')
    form_model['deadline_estimated'] = bool(normalized_assignment.get('deadline_estimated'))
    form_model['start_date'] = normalized_assignment.get('start_date', '')
    form_model['recruiter_name'] = normalized_assignment.get('recruiter_name', '')
    form_model['recruiter_email'] = normalized_assignment.get('recruiter_email', '')
    form_model['recruiter_phone'] = normalized_assignment.get('recruiter_phone', '')


def build_assignment_form_defaults():
    """Return empty assignment form defaults."""
    return {
        'title': '',
        'description': '',
        'reference_id': '',
        'source_text': '',
        'hot_seat': '',
        'hourly_rate_min': '',
        'hourly_rate_max': '',
        'hourly_rate': '',
        'knock_out_criteria_text': '',
        'nice_to_have_criteria_text': '',
        'competenties_text': '',
        'deadline': '',
        'deadline_estimated': False,
        'start_date': '',
        'recruiter_name': '',
        'recruiter_email': '',
        'recruiter_phone': ''
    }


def parse_assignment_list_json(raw_json):
    """Parse JSON list field from database into Python list."""
    if not raw_json:
        return []
    try:
        parsed = json.loads(raw_json)
    except (TypeError, json.JSONDecodeError):
        return []

    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]
    return []


def build_assignment_match_text(assignment_record):
    """Build a text block for assignment matching from a stored assignment record."""
    parts = []

    title = (assignment_record.get('title') or '').strip()
    if title:
        parts.append(f"Title: {title}")

    description = (assignment_record.get('description') or '').strip()
    if description:
        parts.append(f"Description:\n{description}")

    knock_out_items = parse_assignment_list_json(assignment_record.get('knock_out_criteria'))
    if knock_out_items:
        parts.append('Knock-out criteria:\n' + '\n'.join([f"- {item}" for item in knock_out_items]))

    nice_to_have_items = parse_assignment_list_json(assignment_record.get('nice_to_have_criteria'))
    if nice_to_have_items:
        parts.append('Nice-to-have criteria:\n' + '\n'.join([f"- {item}" for item in nice_to_have_items]))

    competencies_items = parse_assignment_list_json(assignment_record.get('competenties'))
    if competencies_items:
        parts.append('Competencies:\n' + '\n'.join([f"- {item}" for item in competencies_items]))

    for label, key in [
        ('Start date', 'start_date'),
        ('Deadline', 'deadline'),
        ('Hourly rate min', 'hourly_rate_min'),
        ('Hourly rate max', 'hourly_rate_max'),
        ('Hourly rate', 'hourly_rate')
    ]:
        value = assignment_record.get(key)
        if value not in (None, ''):
            parts.append(f"{label}: {value}")

    if not parts:
        return (assignment_record.get('source_text') or '').strip()

    return '\n\n'.join(parts)


def _derive_initials(name):
    """Return initials derived from a full name string."""
    if not name:
        return ''
    parts = [part for part in re.split(r'\s+', str(name).strip()) if part]
    return ''.join(part[0].upper() for part in parts if part and part[0].isalnum())


def anonymize_consultant_payload_for_ai(payload):
    """Return a copy of consultant payload with identifying contact/name data removed."""
    payload_copy = copy.deepcopy(payload)
    personal_info = payload_copy.get('personal_info') or {}

    configured_initials = str(personal_info.get('initials', '')).strip().upper()
    if configured_initials:
        initials = configured_initials
    else:
        initials = ''.join([
            _derive_initials(personal_info.get('first_name', '')),
            _derive_initials(personal_info.get('last_name', ''))
        ])
        if not initials:
            initials = _derive_initials(payload_copy.get('consultant', {}).get('display_name', ''))

    if not initials:
        initials = f"C{payload_copy.get('consultant', {}).get('id', '')}"

    consultant = payload_copy.get('consultant') or {}
    consultant['display_name'] = initials
    payload_copy['consultant'] = consultant

    if payload_copy.get('personal_info'):
        personal_info['initials'] = initials
        personal_info.pop('first_name', None)
        personal_info.pop('last_name', None)
        personal_info.pop('email', None)
        personal_info.pop('phone', None)
        personal_info.pop('address', None)
        personal_info.pop('zip_code', None)
        personal_info.pop('linkedin_url', None)
        personal_info.pop('github_url', None)
        personal_info.pop('portfolio_url', None)
        payload_copy['personal_info'] = personal_info

    return payload_copy


def build_consultant_ai_payload(conn, consultant_id):
    """Build normalized consultant payload for export/matching AI input."""
    consultant = conn.execute(
        'SELECT id, display_name FROM consultants WHERE id = ?',
        (consultant_id,)
    ).fetchone()

    if not consultant:
        return None

    payload = {
        'consultant': {
            'id': consultant['id'],
            'display_name': consultant['display_name']
        },
        'personal_info': None,
        'work_experience': [],
        'education': [],
        'skills': [],
        'projects': [],
        'certifications': []
    }

    personal_info = conn.execute(
        'SELECT * FROM personal_info WHERE consultant_id = ? ORDER BY id DESC LIMIT 1',
        (consultant_id,)
    ).fetchone()
    if personal_info:
        payload['personal_info'] = dict(personal_info)
        payload['personal_info'].pop('id', None)
        payload['personal_info'].pop('consultant_id', None)
        payload['personal_info'].pop('created_at', None)
        payload['personal_info'].pop('updated_at', None)

    for table, key in [
        ('work_experience', 'work_experience'),
        ('education', 'education'),
        ('skills', 'skills'),
        ('projects', 'projects'),
        ('certifications', 'certifications')
    ]:
        rows = conn.execute(
            f'SELECT * FROM {table} WHERE consultant_id = ? ORDER BY id',
            (consultant_id,)
        ).fetchall()
        payload[key] = []
        for row in rows:
            row_data = dict(row)

            if table == 'skills' and row_data.get('category_id'):
                cat = conn.execute('SELECT name FROM skill_categories WHERE id = ?', (row_data['category_id'],)).fetchone()
                if cat:
                    row_data['category_name'] = cat['name']

            if table == 'work_experience':
                skills = conn.execute('''
                    SELECT s.skill_name
                    FROM skills s
                    JOIN experience_skills es ON s.id = es.skill_id
                    WHERE es.experience_id = ?
                ''', (row['id'],)).fetchall()
                row_data['skills'] = [s['skill_name'] for s in skills]

            if table == 'projects':
                skills = conn.execute('''
                    SELECT s.skill_name
                    FROM skills s
                    JOIN project_skills ps ON s.id = ps.skill_id
                    WHERE ps.project_id = ?
                ''', (row['id'],)).fetchall()
                row_data['skills'] = [s['skill_name'] for s in skills]

            if table == 'certifications':
                skills = conn.execute('''
                    SELECT s.skill_name
                    FROM skills s
                    JOIN certification_skills cs ON s.id = cs.skill_id
                    WHERE cs.certification_id = ?
                    ORDER BY s.skill_name
                ''', (row['id'],)).fetchall()
                row_data['skills'] = [s['skill_name'] for s in skills]

            if table == 'certifications' and row_data.get('issue_date'):
                issue_date_str = str(row_data['issue_date'])
                if issue_date_str and len(issue_date_str) >= 4:
                    row_data['issue_year'] = issue_date_str[:4]

            row_data.pop('id', None)
            row_data.pop('consultant_id', None)
            row_data.pop('created_at', None)
            row_data.pop('updated_at', None)
            row_data.pop('category', None)
            row_data.pop('years_of_experience', None)
            payload[key].append(row_data)

    return payload


def parse_cv_with_gemini(cv_text):
    """Backward compatibility for existing code."""
    return parse_cv_with_ai(cv_text, 'gemini')
            
@app.route('/')
@login_required
def index():
    """Home page with navigation to all sections."""
    return render_template('index.html')


# ==================== Consultant Routes ====================

@app.route('/consultants')
@login_required
def list_consultants():
    """Redirect to admin dashboard (consultants are managed there)."""
    if not current_user.is_admin():
        flash(get_translation('messages.admin_only_consultants'), 'error')
        return redirect(url_for('index'))
    return redirect(url_for('admin_dashboard'))


@app.route('/consultants/add', methods=['POST'])
@admin_required
def add_consultant():
    """Add a new consultant."""
    display_name = request.form.get('display_name', '').strip()
    if not display_name:
        flash(get_translation('messages.consultant_name_required'), 'error')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    result = conn.execute(
        'INSERT INTO consultants (display_name) VALUES (?)',
        (display_name,)
    )
    conn.commit()
    consultant_id = result.lastrowid
    conn.close()

    session['consultant_id'] = consultant_id
    flash(get_translation('messages.consultant_added'), 'success')
    return redirect(url_for('consultants_management'))


@app.route('/consultants/switch/<int:consultant_id>')
@admin_required
def switch_consultant(consultant_id):
    """Switch the active consultant."""
    conn = get_db_connection()
    existing = conn.execute(
        'SELECT id FROM consultants WHERE id = ?',
        (consultant_id,)
    ).fetchone()
    conn.close()

    if not existing:
        flash(get_translation('messages.consultant_not_found'), 'error')
        return redirect(url_for('consultants_management'))

    session['consultant_id'] = consultant_id
    return redirect(request.referrer or url_for('consultants_management'))


def parse_import_payload(payload):
    if not isinstance(payload, dict):
        return None, get_translation('messages.import_invalid_json')

    return {
        'consultant': payload.get('consultant', {}) or {},
        'personal_info': payload.get('personal_info', None),
        'work_experience': payload.get('work_experience', []) or [],
        'education': payload.get('education', []) or [],
        'skills': payload.get('skills', []) or [],
        'projects': payload.get('projects', []) or [],
        'certifications': payload.get('certifications', []) or []
    }, None


def import_consultant_data(conn, consultant_id, payload):
    # Updating, so cleanup the old data first for this consultant to avoid duplicates and stale data
    conn.execute('DELETE FROM personal_info WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM work_experience WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM education WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM skills WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM projects WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM certifications WHERE consultant_id = ?', (consultant_id,))
    
    # Also clean up junction tables for this consultant's entities
    # Note: ON DELETE CASCADE handles this if the parent rows are deleted, 
    # but since we are re-inserting, we ensure a clean slate.

    def normalize_text(value):
        if value is None:
            return ''
        return str(value).strip().lower()

    personal_info = payload.get('personal_info')
    if isinstance(personal_info, dict):
        conn.execute('''
            INSERT INTO personal_info (
                consultant_id, first_name, last_name, initials, email, phone, address, city,
                state, zip_code, country, linkedin_url, github_url, portfolio_url,
                professional_summary, actively_searching_for_assignment, available_from
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            personal_info.get('first_name', ''),
            personal_info.get('last_name', ''),
            personal_info.get('initials', ''),
            personal_info.get('email', ''),
            personal_info.get('phone', ''),
            personal_info.get('address', ''),
            personal_info.get('city', ''),
            personal_info.get('state', ''),
            personal_info.get('zip_code', ''),
            personal_info.get('country', ''),
            personal_info.get('linkedin_url', ''),
            personal_info.get('github_url', ''),
            personal_info.get('portfolio_url', ''),
            personal_info.get('professional_summary', personal_info.get('summary', '')),
            1 if normalize_assignment_bool(personal_info.get('actively_searching_for_assignment', True)) else 0,
            normalize_iso_date(personal_info.get('available_from'))
        ))

    # Map skill categories and insert skills
    categories_rows = conn.execute('SELECT id, name FROM skill_categories').fetchall()
    cat_map = {c['name'].lower(): c['id'] for c in categories_rows}
    
    # Ensure "Various" category exists for unknown categories
    if 'various' not in cat_map:
        conn.execute('INSERT INTO skill_categories (name) VALUES (?)', ('Various',))
        conn.commit()
        categories_rows = conn.execute('SELECT id, name FROM skill_categories').fetchall()
        cat_map = {c['name'].lower(): c['id'] for c in categories_rows}
    
    # Track inserted skills by name to link to experience/projects
    skill_name_to_id = {}
    seen_skills = set()

    for skill in payload.get('skills', []):
        cat_name = skill.get('category_name', skill.get('category', '')).strip()
        skill_name = skill.get('skill_name', skill.get('name', ''))
        skill_key = (normalize_text(skill_name), normalize_text(cat_name))
        if skill_key in seen_skills:
            continue
        seen_skills.add(skill_key)
        
        # Map category name to existing category
        # If category doesn't exist, use "Various"
        category_id = None
        if cat_name:
            category_lower = cat_name.lower()
            if category_lower in cat_map:
                category_id = cat_map[category_lower]
            else:
                # Unknown category - map to "Various"
                category_id = cat_map.get('various')
        
        cursor = conn.execute('''
            INSERT INTO skills (
                consultant_id, skill_name, category_id
            ) VALUES (?, ?, ?)
        ''', (
            consultant_id,
            skill_name,
            category_id
        ))
        skill_name_to_id[skill_name.lower()] = cursor.lastrowid

    seen_experience = set()

    for exp in payload.get('work_experience', []):
        exp_key = (
            normalize_text(exp.get('company_name', '')),
            normalize_text(exp.get('position_title', exp.get('job_title', ''))),
            normalize_text(exp.get('location', '')),
            normalize_text(exp.get('start_date', '')),
            normalize_text(exp.get('end_date', ''))
        )
        if exp_key in seen_experience:
            continue
        seen_experience.add(exp_key)
        cursor = conn.execute('''
            INSERT INTO work_experience (
                consultant_id, company_name, position_title, location, start_date,
                end_date, is_current, description, achievements, 
                star_situation, star_tasks, star_actions, star_results
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            exp.get('company_name', ''),
            exp.get('position_title', exp.get('job_title', '')),
            exp.get('location', ''),
            exp.get('start_date', ''),
            exp.get('end_date', None),
            1 if exp.get('is_current') or exp.get('end_date', None) is None else 0,
            exp.get('description', ''),
            exp.get('achievements', ''),
            exp.get('star_situation', ''),
            exp.get('star_tasks', ''),
            exp.get('star_actions', ''),
            exp.get('star_results', '')
        ))
        
        # Link skills to work experience
        exp_id = cursor.lastrowid
        linked_skill_ids = set()
        for skill_name in exp.get('skills', []):
            skill_id = skill_name_to_id.get(str(skill_name).strip().lower())
            if skill_id:
                if skill_id in linked_skill_ids:
                    continue
                linked_skill_ids.add(skill_id)
                conn.execute('INSERT INTO experience_skills (experience_id, skill_id) VALUES (?, ?)', (exp_id, skill_id))

    seen_education = set()

    for edu in payload.get('education', []):
        edu_key = (
            normalize_text(edu.get('institution_name', edu.get('institution', ''))),
            normalize_text(edu.get('degree', '')),
            normalize_text(edu.get('field_of_study', '')),
            normalize_text(edu.get('start_date', '')),
            normalize_text(edu.get('end_date', ''))
        )
        if edu_key in seen_education:
            continue
        seen_education.add(edu_key)
        conn.execute('''
            INSERT INTO education (
                consultant_id, institution_name, degree, field_of_study, location,
                start_date, end_date, gpa, honors, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            edu.get('institution_name', edu.get('institution', '')),
            edu.get('degree', ''),
            edu.get('field_of_study', ''),
            edu.get('location', ''),
            edu.get('start_date', None),
            edu.get('end_date', None),
            edu.get('gpa', ''),
            edu.get('honors', ''),
            edu.get('description', '')
        ))

    seen_projects = set()

    for project in payload.get('projects', []):
        project_key = (
            normalize_text(project.get('project_name', '')),
            normalize_text(project.get('role', '')),
            normalize_text(project.get('start_date', '')),
            normalize_text(project.get('end_date', ''))
        )
        if project_key in seen_projects:
            continue

        seen_projects.add(project_key)
        cursor = conn.execute('''
            INSERT INTO projects (
                consultant_id, project_name, description,
                start_date, end_date, project_url, github_url, role, achievements
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                consultant_id,
                project.get('project_name', ''),
                project.get('description', ''),
                project.get('start_date', None),
                project.get('end_date', None),
                project.get('project_url', ''),
                project.get('github_url', ''),
                project.get('role', ''),
                project.get('achievements', '')
            ))
        
        # Link skills to projects
        proj_id = cursor.lastrowid
        linked_skill_ids = set()
        for skill_name in project.get('skills', []):
            skill_id = skill_name_to_id.get(str(skill_name).strip().lower())
            if skill_id:
                if skill_id in linked_skill_ids:
                    continue
                linked_skill_ids.add(skill_id)
                conn.execute('INSERT INTO project_skills (project_id, skill_id) VALUES (?, ?)', (proj_id, skill_id))

    seen_certifications = set()

    for cert in payload.get('certifications', []):
        cert_key = (
            normalize_text(cert.get('certification_name', '')),
            normalize_text(cert.get('issuing_organization', '')),
            normalize_text(cert.get('issue_date', '')),
            normalize_text(cert.get('credential_id', ''))
        )
        if cert_key in seen_certifications:
            continue
        seen_certifications.add(cert_key)
        cursor = conn.execute('''
            INSERT INTO certifications (
                consultant_id, certification_name, issuing_organization, issue_date,
                expiration_date, credential_id, credential_url, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            cert.get('certification_name', ''),
            cert.get('issuing_organization', ''),
            cert.get('issue_date', None),
            cert.get('expiration_date', None),
            cert.get('credential_id', ''),
            cert.get('credential_url', ''),
            cert.get('description', '')
        ))

        cert_id = cursor.lastrowid
        linked_skill_ids = set()
        for skill_name in cert.get('skills', []):
            skill_id = skill_name_to_id.get(str(skill_name).strip().lower())
            if skill_id and skill_id not in linked_skill_ids:
                linked_skill_ids.add(skill_id)
                conn.execute('INSERT INTO certification_skills (certification_id, skill_id) VALUES (?, ?)', (cert_id, skill_id))


@app.route('/consultants/import', methods=['GET', 'POST'])
@admin_required
def import_consultant():
    """Import consultant data from JSON file or textarea."""
    conn = get_db_connection()
    consultants = get_consultants(conn)
    current_consultant_id = resolve_current_consultant_id(conn)
    current_consultant = None
    if current_consultant_id:
        current_consultant = conn.execute(
            'SELECT * FROM consultants WHERE id = ?',
            (current_consultant_id,)
        ).fetchone()
    prefilled_json = None

    if request.method == 'GET':
        # Check if we're prefilling from parsed CV
        cv_id = session.get('parsed_cv_id')
        if cv_id:
            parsed_data, _ = retrieve_parsed_cv_data(cv_id)
            if parsed_data:
                prefilled_json = json.dumps(parsed_data, indent=2)

    if request.method == 'POST':
        # Try to get JSON from textarea first, then from file
        json_textarea = request.form.get('json_textarea', '').strip()
        json_file = request.files.get('json_file')
        import_mode = request.form.get('import_mode')
        
        payload = None
        
        if json_textarea:
            # Parse JSON from textarea
            try:
                payload = json.loads(json_textarea)
            except json.JSONDecodeError as e:
                conn.close()
                flash(f"{get_translation('messages.import_invalid_json')}: {str(e)}", 'error')
                return redirect(url_for('import_consultant'))
        elif json_file:
            # Parse JSON from uploaded file
            try:
                payload = json.load(json_file)
            except json.JSONDecodeError:
                conn.close()
                flash(get_translation('messages.import_invalid_json'), 'error')
                return redirect(url_for('import_consultant'))
        else:
            conn.close()
            flash(get_translation('messages.import_file_required'), 'error')
            return redirect(url_for('import_consultant'))

        parsed_payload, error = parse_import_payload(payload)
        if error:
            conn.close()
            flash(error, 'error')
            return redirect(url_for('import_consultant'))

        if import_mode == 'existing':
            consultant_id = request.form.get('consultant_id')
            if not consultant_id:
                conn.close()
                flash(get_translation('messages.consultant_required'), 'error')
                return redirect(url_for('import_consultant'))

            consultant_id = int(consultant_id)
            exists = conn.execute(
                'SELECT id FROM consultants WHERE id = ?',
                (consultant_id,)
            ).fetchone()
            if not exists:
                conn.close()
                flash(get_translation('messages.consultant_not_found'), 'error')
                return redirect(url_for('import_consultant'))
        else:
            display_name = request.form.get('display_name', '').strip()
            if not display_name:
                display_name = parsed_payload.get('consultant', {}).get('display_name', '').strip()

            if not display_name:
                personal_info = parsed_payload.get('personal_info') or {}
                display_name = (
                    f"{personal_info.get('first_name', '').strip()} "
                    f"{personal_info.get('last_name', '').strip()}"
                ).strip()

            if not display_name:
                display_name = get_translation('consultants.unnamed')

            result = conn.execute(
                'INSERT INTO consultants (display_name) VALUES (?)',
                (display_name,)
            )
            consultant_id = result.lastrowid

        import_consultant_data(conn, consultant_id, parsed_payload)
        conn.commit()
        conn.close()

        session['consultant_id'] = consultant_id
        # Clear parsed CV data if it exists
        cv_id = session.pop('parsed_cv_id', None)
        if cv_id:
            delete_parsed_cv_data(cv_id)
        
        flash(get_translation('messages.import_success'), 'success')
        return redirect(url_for('view_personal_info'))

    conn.close()
    return render_template('import_consultant.html', consultants=consultants, current_consultant=current_consultant, prefilled_json=prefilled_json)


@app.route('/consultants/parse-cv', methods=['GET', 'POST'])
@admin_required
def parse_cv():
    """Parse CV using AI and import consultant data."""
    if request.method == 'POST':
        cv_file = request.files.get('cv_file')
        consultant_name = request.form.get('consultant_name', '').strip()
        ai_provider = (request.form.get('ai_provider') or 'gemini').strip().lower()
        if ai_provider not in {'gemini', 'groq', 'ollama'}:
            ai_provider = 'gemini'
        
        if not cv_file:
            flash(get_translation('messages.cv_file_required'), 'error')
            return redirect(url_for('parse_cv'))
        
        # Extract text from the uploaded file
        cv_text = extract_text_from_file(cv_file)
        if cv_text.startswith('Error') or cv_text.startswith('Unsupported'):
            flash(cv_text, 'error')
            return redirect(url_for('parse_cv'))
        
        # Parse CV with AI
        parsed_data, error = parse_cv_with_ai(cv_text, ai_provider)
        if error:
            flash(f"{get_translation('messages.ai_parse_error')}: {error}", 'error')
            return redirect(url_for('parse_cv'))
        
        if not parsed_data:
            flash(get_translation('messages.no_data_extracted'), 'error')
            return redirect(url_for('parse_cv'))
        
        # Use provided name if specified, otherwise use AI extracted name
        if consultant_name:
            if 'consultant' not in parsed_data:
                parsed_data['consultant'] = {}
            parsed_data['consultant']['display_name'] = consultant_name
        
        # Store parsed data in temporary file and save ID in session
        cv_text_preview = cv_text[:500] + "..." if len(cv_text) > 500 else cv_text
        cv_id = store_parsed_cv_data(parsed_data, cv_text_preview)
        session['parsed_cv_id'] = cv_id
        
        return redirect(url_for('review_parsed_cv'))
    
    return render_template(
        'parse_cv.html',
        has_groq=bool(GROQ_API_KEY and groq_client is not None),
        has_ollama=bool(OLLAMA_ENABLED)
    )


@app.route('/consultants/review-parsed-cv')
@admin_required
def review_parsed_cv():
    """Review AI-parsed CV data before importing."""
    cv_id = session.get('parsed_cv_id')
    
    if not cv_id:
        flash(get_translation('messages.no_parsed_data'), 'error')
        return redirect(url_for('parse_cv'))
    
    parsed_data, cv_text_preview = retrieve_parsed_cv_data(cv_id)
    
    if not parsed_data:
        flash(get_translation('messages.no_parsed_data'), 'error')
        return redirect(url_for('parse_cv'))
    
    return render_template('review_parsed_cv.html', 
                         parsed_data=parsed_data, 
                         cv_text_preview=cv_text_preview)


@app.route('/consultants/import-parsed-cv', methods=['POST'])
@admin_required
def import_parsed_cv():
    """Redirect to import screen with AI-parsed CV data prefilled for review/editing."""    
    cv_id = session.get('parsed_cv_id')
    
    if not cv_id:
        flash(get_translation('messages.no_parsed_data'), 'error')
        return redirect(url_for('parse_cv'))
    
    # Verify the data exists
    parsed_data, _ = retrieve_parsed_cv_data(cv_id)
    if not parsed_data:
        flash(get_translation('messages.no_parsed_data'), 'error')
        return redirect(url_for('parse_cv'))
    
    # Redirect to import screen with CV ID in session (will be prefilled in textarea)
    return redirect(url_for('import_consultant'))


@app.route('/assignments', methods=['GET', 'POST'])
@admin_required
def assignments():
    """Admin assignment intake page with AI-assisted structuring."""
    conn = get_db_connection()
    assignment_form = build_assignment_form_defaults()
    ai_provider = 'gemini'
    raw_ai_response = ''

    if request.method == 'POST':
        action = (request.form.get('action') or 'analyze').strip().lower()
        assignment_form = get_assignment_form_from_request(request.form)
        raw_ai_response = (request.form.get('raw_ai_response') or '').strip()
        ai_provider = (request.form.get('ai_provider') or 'gemini').strip().lower()
        if ai_provider not in {'gemini', 'groq', 'ollama'}:
            ai_provider = 'gemini'

        if not assignment_form['source_text']:
            conn.close()
            flash(get_translation('messages.assignment_source_text_required'), 'error')
            return redirect(url_for('assignments'))

        if action == 'analyze':
            parsed_payload, model_raw_response, error = parse_assignment_with_ai(
                assignment_form['source_text'],
                ai_provider
            )

            if error:
                flash(f"{get_translation('messages.assignment_parse_failed')}: {error}", 'error')
            else:
                normalized = normalize_assignment_payload(parsed_payload)
                apply_normalized_assignment_to_form(assignment_form, normalized)
                raw_ai_response = model_raw_response or ''
                flash(get_translation('messages.assignment_parse_success'), 'success')

        elif action == 'save':
            normalized = {
                'title': assignment_form['title'],
                'description': assignment_form['description'],
                'reference_id': assignment_form['reference_id'],
                'hot_seat': assignment_form['hot_seat'],
                'hourly_rate_min': normalize_assignment_number(assignment_form['hourly_rate_min']),
                'hourly_rate_max': normalize_assignment_number(assignment_form['hourly_rate_max']),
                'hourly_rate': normalize_assignment_number(assignment_form['hourly_rate']),
                'knock_out_criteria': normalize_assignment_list(assignment_form['knock_out_criteria_text']),
                'nice_to_have_criteria': normalize_assignment_list(assignment_form['nice_to_have_criteria_text']),
                'competenties': normalize_assignment_list(assignment_form['competenties_text']),
                'deadline': normalize_iso_date(assignment_form['deadline']),
                'deadline_estimated': bool(assignment_form['deadline_estimated']),
                'start_date': normalize_iso_date(assignment_form['start_date']),
                'recruiter_name': assignment_form['recruiter_name'],
                'recruiter_email': assignment_form['recruiter_email'],
                'recruiter_phone': assignment_form['recruiter_phone']
            }

            if not normalized['deadline'] and normalized['start_date']:
                start_dt = datetime.strptime(normalized['start_date'], '%Y-%m-%d')
                normalized['deadline'] = (start_dt - timedelta(days=7)).strftime('%Y-%m-%d')
                normalized['deadline_estimated'] = True

            if not normalized['title'] and not normalized['description']:
                flash(get_translation('messages.assignment_title_or_description_required'), 'error')
            else:
                conn.execute(
                    '''
                        INSERT INTO assignments (
                            title, description, reference_id, source_text, hot_seat,
                            hourly_rate_min, hourly_rate_max, hourly_rate,
                            knock_out_criteria, nice_to_have_criteria, competenties,
                            deadline, deadline_estimated, start_date,
                            recruiter_name, recruiter_email, recruiter_phone,
                            parse_provider, raw_ai_response, created_by_user_id, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        normalized['title'],
                        normalized['description'],
                        normalized['reference_id'],
                        assignment_form['source_text'],
                        normalized['hot_seat'],
                        normalized['hourly_rate_min'],
                        normalized['hourly_rate_max'],
                        normalized['hourly_rate'],
                        json.dumps(normalized['knock_out_criteria'], ensure_ascii=False),
                        json.dumps(normalized['nice_to_have_criteria'], ensure_ascii=False),
                        json.dumps(normalized['competenties'], ensure_ascii=False),
                        normalized['deadline'],
                        1 if normalized['deadline_estimated'] else 0,
                        normalized['start_date'],
                        normalized['recruiter_name'],
                        normalized['recruiter_email'],
                        normalized['recruiter_phone'],
                        ai_provider,
                        raw_ai_response,
                        current_user.id,
                        datetime.now(UTC).isoformat()
                    )
                )
                conn.commit()
                conn.close()
                flash(get_translation('messages.assignment_saved'), 'success')
                return redirect(url_for('assignments'))

    assignment_rows = conn.execute(
        '''
            SELECT id, title, description, start_date, deadline, deadline_estimated,
                   recruiter_name, recruiter_email, created_at
            FROM assignments
            ORDER BY (deadline IS NULL) ASC, deadline DESC, created_at DESC, id DESC
        '''
    ).fetchall()
    conn.close()

    return render_template(
        'assignments.html',
        assignments=assignment_rows,
        assignment_form=assignment_form,
        ai_provider=ai_provider,
        raw_ai_response=raw_ai_response,
        has_groq=bool(GROQ_API_KEY and groq_client is not None),
        has_ollama=bool(OLLAMA_ENABLED)
    )


@app.route('/assignments/<int:assignment_id>')
@admin_required
def assignment_detail(assignment_id):
    """View a stored assignment with full structured details."""
    conn = get_db_connection()
    assignment = conn.execute(
        'SELECT * FROM assignments WHERE id = ?',
        (assignment_id,)
    ).fetchone()
    conn.close()

    if not assignment:
        flash(get_translation('messages.assignment_not_found'), 'error')
        return redirect(url_for('assignments'))

    assignment_data = dict(assignment)
    assignment_data['knock_out_criteria_list'] = parse_assignment_list_json(assignment_data.get('knock_out_criteria'))
    assignment_data['nice_to_have_criteria_list'] = parse_assignment_list_json(assignment_data.get('nice_to_have_criteria'))
    assignment_data['competenties_list'] = parse_assignment_list_json(assignment_data.get('competenties'))

    return render_template('assignment_detail.html', assignment=assignment_data)


@app.route('/assignments/delete/<int:assignment_id>', methods=['POST'])
@admin_required
def delete_assignment(assignment_id):
    """Delete a stored assignment."""
    conn = get_db_connection()
    assignment = conn.execute(
        'SELECT id FROM assignments WHERE id = ?',
        (assignment_id,)
    ).fetchone()

    if not assignment:
        conn.close()
        flash(get_translation('messages.assignment_not_found'), 'error')
        return redirect(url_for('assignments'))

    conn.execute('DELETE FROM assignments WHERE id = ?', (assignment_id,))
    conn.commit()
    conn.close()

    flash(get_translation('messages.assignment_deleted'), 'success')
    return redirect(url_for('assignments'))


@app.route('/assignment-match', methods=['GET', 'POST'])
@login_required
def assignment_match():
    """Match an assignment to one or more consultants using AI."""
    conn = get_db_connection()

    all_consultants = []
    selected_consultant_ids = []
    selected_consultant_names = []
    assignment_rows = conn.execute(
        'SELECT id, title, description, source_text, deadline, created_at FROM assignments ORDER BY created_at DESC, id DESC'
    ).fetchall()
    assignment_options = [
        dict(row) for row in assignment_rows
        if is_assignment_active(dict(row))
    ]
    selected_assignment_id = None
    assignment_description = ''
    ai_provider = 'gemini'
    match_result = None
    match_summary = None
    match_ranking = []
    recommended_names = []
    match_notes = []
    match_result_parse_error = False
    consultants_json_input = None

    if current_user.is_admin():
        all_consultants = conn.execute(
            'SELECT id, display_name FROM consultants ORDER BY display_name, id'
        ).fetchall()
        current_consultant_id = resolve_current_consultant_id(conn)
        if current_consultant_id is not None:
            selected_consultant_ids = [current_consultant_id]
    else:
        if current_user.consultant_id:
            selected_consultant_ids = [current_user.consultant_id]
            own_consultant = conn.execute(
                'SELECT display_name FROM consultants WHERE id = ?',
                (current_user.consultant_id,)
            ).fetchone()
            if own_consultant:
                selected_consultant_names = [own_consultant['display_name']]

    requested_assignment_id = request.args.get('assignment_id')
    if requested_assignment_id:
        try:
            selected_assignment_id = int(requested_assignment_id)
        except (TypeError, ValueError):
            selected_assignment_id = None

        if selected_assignment_id is not None:
            selected_assignment = get_active_assignment_for_matching(conn, selected_assignment_id)
            if selected_assignment:
                assignment_description = build_assignment_match_text(selected_assignment)
            else:
                selected_assignment_id = None

    if request.method == 'POST':
        assignment_description = (request.form.get('assignment_description') or '').strip()
        raw_assignment_id = (request.form.get('assignment_id') or '').strip()
        if raw_assignment_id:
            try:
                selected_assignment_id = int(raw_assignment_id)
            except (TypeError, ValueError):
                selected_assignment_id = None

        if selected_assignment_id and not assignment_description:
            selected_assignment = get_active_assignment_for_matching(conn, selected_assignment_id)
            if selected_assignment:
                assignment_description = build_assignment_match_text(selected_assignment)
            else:
                selected_assignment_id = None

        ai_provider = (request.form.get('ai_provider') or 'gemini').strip().lower()
        if ai_provider not in {'gemini', 'groq', 'ollama'}:
            ai_provider = 'gemini'

        if not assignment_description:
            conn.close()
            flash(get_translation('messages.assignment_description_required'), 'error')
            return redirect(url_for('assignment_match'))

        if current_user.is_admin():
            raw_ids = request.form.getlist('consultant_ids')
            selected_consultant_ids = []
            for raw_id in raw_ids:
                try:
                    consultant_id = int(raw_id)
                except (TypeError, ValueError):
                    continue
                if consultant_id not in selected_consultant_ids:
                    selected_consultant_ids.append(consultant_id)

            if not selected_consultant_ids:
                conn.close()
                flash(get_translation('messages.assignment_select_consultant_required'), 'error')
                return redirect(url_for('assignment_match'))
        else:
            if not current_user.consultant_id:
                conn.close()
                flash(get_translation('messages.user_no_consultant_access'), 'error')
                return redirect(url_for('index'))
            selected_consultant_ids = [current_user.consultant_id]

        consultant_payloads = []
        for consultant_id in selected_consultant_ids:
            payload = build_consultant_ai_payload(conn, consultant_id)
            if not payload:
                continue
            consultant_payloads.append(anonymize_consultant_payload_for_ai(payload))
            selected_consultant_names.append(payload['consultant']['display_name'])

        if not consultant_payloads:
            conn.close()
            flash(get_translation('messages.assignment_no_consultant_data'), 'error')
            return redirect(url_for('assignment_match'))

        match_result, consultants_json_input, error = match_assignment_with_ai(
            assignment_description,
            consultant_payloads,
            ai_provider
        )

        if error:
            conn.close()
            flash(f"{get_translation('messages.assignment_match_failed')}: {error}", 'error')
            return redirect(url_for('assignment_match'))

        if match_result:
            match_json_text = match_result.strip()
            if match_json_text.startswith('```json'):
                match_json_text = match_json_text[7:]
            elif match_json_text.startswith('```'):
                match_json_text = match_json_text[3:]

            if match_json_text.endswith('```'):
                match_json_text = match_json_text[:-3]

            match_json_text = match_json_text.strip()

            try:
                parsed_result = json.loads(match_json_text)
                if isinstance(parsed_result, dict):
                    match_summary = parsed_result.get('summary')
                    ranking_data = parsed_result.get('ranking')
                    if isinstance(ranking_data, list):
                        match_ranking = ranking_data
                    recommended_data = parsed_result.get('recommended_consultant_names')
                    if isinstance(recommended_data, list):
                        recommended_names = recommended_data
                    notes_data = parsed_result.get('notes')
                    if isinstance(notes_data, list):
                        match_notes = notes_data
                else:
                    match_result_parse_error = True
            except json.JSONDecodeError:
                match_result_parse_error = True

        flash(get_translation('messages.assignment_match_success'), 'success')

    conn.close()
    return render_template(
        'assignment_match.html',
        all_consultants=all_consultants,
        selected_consultant_ids=selected_consultant_ids,
        selected_consultant_names=selected_consultant_names,
        assignment_options=assignment_options,
        selected_assignment_id=selected_assignment_id,
        assignment_description=assignment_description,
        ai_provider=ai_provider,
        match_result=match_result,
        match_summary=match_summary,
        match_ranking=match_ranking,
        recommended_names=recommended_names,
        match_notes=match_notes,
        match_result_parse_error=match_result_parse_error,
        consultants_json_input=consultants_json_input,
        has_groq=bool(GROQ_API_KEY and groq_client is not None),
        has_ollama=bool(OLLAMA_ENABLED)
    )


@app.route('/consultants/delete/<int:consultant_id>', methods=['POST'])
@admin_required
def delete_consultant(consultant_id):
    """Delete a consultant."""
    conn = get_db_connection()
    
    # Check if consultant exists
    consultant = conn.execute(
        'SELECT id, display_name FROM consultants WHERE id = ?',
        (consultant_id,)
    ).fetchone()
    
    if not consultant:
        conn.close()
        flash(get_translation('messages.consultant_not_found'), 'error')
        return redirect(url_for('consultants_management'))
    
    # Prevent deleting if this is the only consultant
    consultant_count = conn.execute('SELECT COUNT(*) FROM consultants').fetchone()[0]
    if consultant_count <= 1:
        conn.close()
        flash(get_translation('messages.consultant_delete_last'), 'error')
        return redirect(url_for('consultants_management'))
    
    # If deleting current consultant, switch to another one
    current_consultant_id = session.get('consultant_id')
    if current_consultant_id == consultant_id:
        # Find another consultant to switch to
        other_consultant = conn.execute(
            'SELECT id FROM consultants WHERE id != ? ORDER BY id LIMIT 1',
            (consultant_id,)
        ).fetchone()
        if other_consultant:
            session['consultant_id'] = other_consultant['id']
        else:
            # This should not happen due to the count check above
            session.pop('consultant_id', None)
    
    # Delete all related data
    conn.execute('DELETE FROM users WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM personal_info WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM work_experience WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM education WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM skills WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM projects WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM certifications WHERE consultant_id = ?', (consultant_id,))
    
    # Delete the consultant
    conn.execute('DELETE FROM consultants WHERE id = ?', (consultant_id,))
    conn.commit()
    conn.close()
    
    flash(get_translation('messages.consultant_deleted'), 'success')
    return redirect(url_for('consultants_management'))


@app.route('/consultants/export/<int:consultant_id>')
@admin_required
def export_consultant(consultant_id):
    """Export a consultants data as JSON."""
    conn = get_db_connection()
    payload = build_consultant_ai_payload(conn, consultant_id)

    if not payload:
        conn.close()
        flash(get_translation('messages.consultant_not_found'), 'error')
        return redirect(url_for('admin_dashboard'))

    payload['version'] = 1

    conn.close()

    # Sanitize display name for filename
    safe_name = "".join([c if c.isalnum() else "_" for c in payload['consultant']['display_name']])
    filename = f"{safe_name}.json"
    
    response = Response(
        json.dumps(payload, indent=2),
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response


@app.route('/full-json-download')
def full_json_download():
    """Download anonymized JSON payload for consultants actively searching for assignment."""
    conn = get_db_connection()
    consultants = conn.execute(
        'SELECT id FROM consultants ORDER BY display_name, id'
    ).fetchall()

    anonymized_payloads = []
    for consultant in consultants:
        payload = build_consultant_ai_payload(conn, consultant['id'])
        if not payload:
            continue

        personal_info = payload.get('personal_info') or {}
        is_active_candidate = normalize_assignment_bool(
            personal_info.get('actively_searching_for_assignment', True)
        )
        if not is_active_candidate:
            continue

        anonymized_payloads.append(anonymize_consultant_payload_for_ai(payload))

    conn.close()

    response = Response(
        json.dumps(anonymized_payloads, indent=2, ensure_ascii=False),
        mimetype='application/json'
    )
    response.headers.set('Content-Disposition', 'attachment', filename='all_candidates_anonymized.json')
    return response


# ==================== Personal Info Routes ====================

@app.route('/personal-info')
@login_required
def view_personal_info():
    """View personal information."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    personal_info = conn.execute(
        'SELECT * FROM personal_info WHERE consultant_id = ? ORDER BY id DESC LIMIT 1',
        (consultant_id,)
    ).fetchone()
    conn.close()
    return render_template('personal_info.html', info=personal_info)


@app.route('/personal-info/edit', methods=['GET', 'POST'])
@login_required
def edit_personal_info():
    """Edit or create personal information."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    if request.method == 'POST':
        # Get form data
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'initials': request.form.get('initials', '').strip().upper(),
            'actively_searching_for_assignment': bool(request.form.get('actively_searching_for_assignment')),
            'available_from': normalize_iso_date(request.form.get('available_from')),
            'email': request.form['email'],
            'phone': request.form.get('phone', ''),
            'address': request.form.get('address', ''),
            'city': request.form.get('city', ''),
            'state': request.form.get('state', ''),
            'zip_code': request.form.get('zip_code', ''),
            'country': request.form.get('country', ''),
            'linkedin_url': request.form.get('linkedin_url', ''),
            'github_url': request.form.get('github_url', ''),
            'portfolio_url': request.form.get('portfolio_url', ''),
            'professional_summary': request.form.get('professional_summary', '')
        }
        
        # Check if record exists
        existing = conn.execute(
            'SELECT id FROM personal_info WHERE consultant_id = ? LIMIT 1',
            (consultant_id,)
        ).fetchone()
        
        if existing:
            # Update existing record
            conn.execute('''
                UPDATE personal_info SET
                    first_name = ?, last_name = ?, initials = ?, actively_searching_for_assignment = ?, available_from = ?, email = ?, phone = ?,
                    address = ?, city = ?, state = ?, zip_code = ?, country = ?,
                    linkedin_url = ?, github_url = ?, portfolio_url = ?,
                    professional_summary = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND consultant_id = ?
            ''', (data['first_name'], data['last_name'], data['initials'],
                  1 if data['actively_searching_for_assignment'] else 0, data['available_from'],
                  data['email'], data['phone'],
                  data['address'], data['city'], data['state'], data['zip_code'], data['country'],
                  data['linkedin_url'], data['github_url'], data['portfolio_url'],
                  data['professional_summary'], existing['id'], consultant_id))
            flash(get_translation('messages.personal_info_updated'), 'success')
        else:
            # Insert new record
            conn.execute('''
                INSERT INTO personal_info (
                    consultant_id, first_name, last_name, initials, actively_searching_for_assignment,
                    available_from, email, phone, address, city, state, zip_code,
                    country, linkedin_url, github_url, portfolio_url, professional_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                consultant_id,
                data['first_name'], data['last_name'], data['initials'],
                1 if data['actively_searching_for_assignment'] else 0,
                data['available_from'],
                data['email'], data['phone'],
                data['address'], data['city'], data['state'], data['zip_code'], data['country'],
                data['linkedin_url'], data['github_url'], data['portfolio_url'],
                data['professional_summary']
            ))
            flash(get_translation('messages.personal_info_saved'), 'success')

        display_name = f"{data['first_name']} {data['last_name']}".strip()
        if display_name:
            conn.execute(
                'UPDATE consultants SET display_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                (display_name, consultant_id)
            )
        
        conn.commit()
        conn.close()
        return redirect(url_for('view_personal_info'))
    
    # GET request - show form
    personal_info = conn.execute(
        'SELECT * FROM personal_info WHERE consultant_id = ? ORDER BY id DESC LIMIT 1',
        (consultant_id,)
    ).fetchone()
    conn.close()
    return render_template('edit_personal_info.html', info=personal_info)


# ==================== Work Experience Routes ====================

@app.route('/work-experience')
@login_required
def view_work_experience():
    """View all work experience entries."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    experiences_raw = conn.execute(
        '''
        SELECT * FROM work_experience
        WHERE consultant_id = ?
        ORDER BY
            CASE
                WHEN is_current = 1 OR end_date IS NULL OR end_date = '' THEN 0
                ELSE 1
            END,
            CASE
                WHEN is_current = 1 OR end_date IS NULL OR end_date = '' THEN start_date
                ELSE NULL
            END DESC,
            CASE
                WHEN is_current = 1 OR end_date IS NULL OR end_date = '' THEN NULL
                ELSE end_date
            END DESC,
            start_date DESC
        ''',
        (consultant_id,)
    ).fetchall()
    
    experiences = []
    for exp in experiences_raw:
        exp_dict = dict(exp)
        # Fetch skills for this experience
        skills = conn.execute('''
            SELECT s.skill_name 
            FROM skills s
            JOIN experience_skills es ON s.id = es.skill_id
            WHERE es.experience_id = ?
            ORDER BY s.category, s.skill_name
        ''', (exp['id'],)).fetchall()
        exp_dict['skills'] = [s['skill_name'] for s in skills]
        experiences.append(exp_dict)
        
    conn.close()
    return render_template('work_experience.html', experiences=experiences)


@app.route('/work-experience/add', methods=['GET', 'POST'])
@login_required
def add_work_experience():
    """Add new work experience."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    if request.method == 'POST':
        cursor = conn.execute('''
            INSERT INTO work_experience (
                consultant_id, company_name, position_title, location, start_date, end_date,
                is_current, description, achievements, star_situation, star_tasks, 
                star_actions, star_results
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            request.form['company_name'],
            request.form['position_title'],
            request.form.get('location', ''),
            request.form['start_date'],
            request.form.get('end_date', None) if not request.form.get('is_current') else None,
            1 if request.form.get('is_current') else 0,
            request.form.get('description', ''),
            request.form.get('achievements', ''),
            request.form.get('star_situation', ''),
            request.form.get('star_tasks', ''),
            request.form.get('star_actions', ''),
            request.form.get('star_results', '')
        ))
        
        experience_id = cursor.lastrowid
        
        # Handle linked skills
        skill_ids = filter_skill_ids_for_consultant(conn, consultant_id, request.form.getlist('skill_ids'))
        for skill_id in skill_ids:
            conn.execute(
                'INSERT INTO experience_skills (experience_id, skill_id) VALUES (?, ?)',
                (experience_id, skill_id)
            )
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.work_experience_added'), 'success')
        return redirect(url_for('view_work_experience'))
    
    skills = conn.execute('''
        SELECT s.id, s.skill_name, c.name as category_name
        FROM skills s
        LEFT JOIN skill_categories c ON s.category_id = c.id
        WHERE s.consultant_id = ?
        ORDER BY c.name, s.skill_name
    ''', (consultant_id,)).fetchall()
    conn.close()
    return render_template('edit_work_experience.html', experience=None, all_skills=skills)


@app.route('/work-experience/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_work_experience(id):
    """Edit existing work experience."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    experience = get_editable_record(
        conn,
        'work_experience',
        id,
        consultant_id,
        'messages.record_not_found'
    )

    if not experience:
        conn.close()
        return redirect(url_for('view_work_experience'))

    target_consultant_id = experience['consultant_id']
    
    if request.method == 'POST':
        if current_user.is_admin():
            conn.execute('''
                UPDATE work_experience SET
                    company_name = ?, position_title = ?, location = ?, start_date = ?,
                    end_date = ?, is_current = ?, description = ?, achievements = ?,
                    star_situation = ?, star_tasks = ?, star_actions = ?, star_results = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (
                request.form['company_name'],
                request.form['position_title'],
                request.form.get('location', ''),
                request.form['start_date'],
                request.form.get('end_date', None) if not request.form.get('is_current') else None,
                1 if request.form.get('is_current') else 0,
                request.form.get('description', ''),
                request.form.get('achievements', ''),
                request.form.get('star_situation', ''),
                request.form.get('star_tasks', ''),
                request.form.get('star_actions', ''),
                request.form.get('star_results', ''),
                id
            ))
        else:
            conn.execute('''
                UPDATE work_experience SET
                    company_name = ?, position_title = ?, location = ?, start_date = ?,
                    end_date = ?, is_current = ?, description = ?, achievements = ?,
                    star_situation = ?, star_tasks = ?, star_actions = ?, star_results = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND consultant_id = ?
            ''', (
                request.form['company_name'],
                request.form['position_title'],
                request.form.get('location', ''),
                request.form['start_date'],
                request.form.get('end_date', None) if not request.form.get('is_current') else None,
                1 if request.form.get('is_current') else 0,
                request.form.get('description', ''),
                request.form.get('achievements', ''),
                request.form.get('star_situation', ''),
                request.form.get('star_tasks', ''),
                request.form.get('star_actions', ''),
                request.form.get('star_results', ''),
                id,
                consultant_id
            ))
        
        # Update linked skills
        conn.execute('DELETE FROM experience_skills WHERE experience_id = ?', (id,))
        skill_ids = filter_skill_ids_for_consultant(conn, target_consultant_id, request.form.getlist('skill_ids'))
        for skill_id in skill_ids:
            conn.execute(
                'INSERT INTO experience_skills (experience_id, skill_id) VALUES (?, ?)',
                (id, skill_id)
            )
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.work_experience_updated'), 'success')
        return redirect(url_for('view_work_experience'))

    all_skills = conn.execute('''
        SELECT s.id, s.skill_name, c.name as category_name
        FROM skills s
        LEFT JOIN skill_categories c ON s.category_id = c.id
        WHERE s.consultant_id = ?
        ORDER BY c.name, s.skill_name
    ''', (target_consultant_id,)).fetchall()
    
    current_skill_ids = [row['skill_id'] for row in conn.execute(
        'SELECT skill_id FROM experience_skills WHERE experience_id = ?',
        (id,)
    ).fetchall()]
    
    conn.close()
    return render_template('edit_work_experience.html', 
                         experience=experience, 
                         all_skills=all_skills,
                         current_skill_ids=current_skill_ids)


@app.route('/work-experience/delete/<int:id>', methods=['POST'])
@login_required
def delete_work_experience(id):
    """Delete work experience."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    experience = get_editable_record(conn, 'work_experience', id, consultant_id, 'messages.record_not_found')
    if not experience:
        conn.close()
        return redirect(url_for('view_work_experience'))

    if current_user.is_admin():
        conn.execute('DELETE FROM work_experience WHERE id = ?', (id,))
    else:
        conn.execute(
            'DELETE FROM work_experience WHERE id = ? AND consultant_id = ?',
            (id, consultant_id)
        )
    conn.commit()
    conn.close()
    flash(get_translation('messages.work_experience_deleted'), 'success')
    return redirect(url_for('view_work_experience'))


# ==================== Education Routes ====================

@app.route('/education')
@login_required
def view_education():
    """View all education entries."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    education = conn.execute(
        'SELECT * FROM education WHERE consultant_id = ? ORDER BY start_date IS NULL, start_date DESC',
        (consultant_id,)
    ).fetchall()
    conn.close()
    return render_template('education.html', education=education)


@app.route('/education/add', methods=['GET', 'POST'])
@login_required
def add_education():
    """Add new education entry."""
    if request.method == 'POST':
        conn = get_db_connection()
        consultant_id = resolve_current_consultant_id(conn)
        
        conn.execute('''
            INSERT INTO education (
                consultant_id, institution_name, degree, field_of_study, location, start_date,
                end_date, gpa, honors, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            request.form['institution_name'],
            request.form['degree'],
            request.form.get('field_of_study', ''),
            request.form.get('location', ''),
            request.form.get('start_date', None),
            request.form.get('end_date', None),
            request.form.get('gpa', ''),
            request.form.get('honors', ''),
            request.form.get('description', '')
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.education_added'), 'success')
        return redirect(url_for('view_education'))
    
    return render_template('edit_education.html', education=None)


@app.route('/education/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_education(id):
    """Edit existing education entry."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    education = get_editable_record(conn, 'education', id, consultant_id, 'messages.record_not_found')
    if not education:
        conn.close()
        return redirect(url_for('view_education'))
    
    if request.method == 'POST':
        if current_user.is_admin():
            conn.execute('''
                UPDATE education SET
                    institution_name = ?, degree = ?, field_of_study = ?, location = ?,
                    start_date = ?, end_date = ?, gpa = ?, honors = ?, description = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (
                request.form['institution_name'],
                request.form['degree'],
                request.form.get('field_of_study', ''),
                request.form.get('location', ''),
                request.form.get('start_date', None),
                request.form.get('end_date', None),
                request.form.get('gpa', ''),
                request.form.get('honors', ''),
                request.form.get('description', ''),
                id
            ))
        else:
            conn.execute('''
                UPDATE education SET
                    institution_name = ?, degree = ?, field_of_study = ?, location = ?,
                    start_date = ?, end_date = ?, gpa = ?, honors = ?, description = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND consultant_id = ?
            ''', (
                request.form['institution_name'],
                request.form['degree'],
                request.form.get('field_of_study', ''),
                request.form.get('location', ''),
                request.form.get('start_date', None),
                request.form.get('end_date', None),
                request.form.get('gpa', ''),
                request.form.get('honors', ''),
                request.form.get('description', ''),
                id,
                consultant_id
            ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.education_updated'), 'success')
        return redirect(url_for('view_education'))
    
    conn.close()
    return render_template('edit_education.html', education=education)


@app.route('/education/delete/<int:id>', methods=['POST'])
@login_required
def delete_education(id):
    """Delete education entry."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    education = get_editable_record(conn, 'education', id, consultant_id, 'messages.record_not_found')
    if not education:
        conn.close()
        return redirect(url_for('view_education'))

    if current_user.is_admin():
        conn.execute('DELETE FROM education WHERE id = ?', (id,))
    else:
        conn.execute(
            'DELETE FROM education WHERE id = ? AND consultant_id = ?',
            (id, consultant_id)
        )
    conn.commit()
    conn.close()
    flash(get_translation('messages.education_deleted'), 'success')
    return redirect(url_for('view_education'))


# ==================== Skills Routes ====================

@app.route('/skills')
@login_required
def view_skills():
    """View all skills."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    skills = conn.execute('''
        SELECT s.*, c.name as category_name
        FROM skills s
        LEFT JOIN skill_categories c ON s.category_id = c.id
        WHERE s.consultant_id = ?
        ORDER BY c.name, s.skill_name
    ''', (consultant_id,)).fetchall()
    conn.close()
    return render_template('skills.html', skills=skills)


@app.route('/skills/add', methods=['GET', 'POST'])
@login_required
def add_skill():
    """Add new skill."""
    if request.method == 'POST':
        conn = get_db_connection()
        consultant_id = resolve_current_consultant_id(conn)
        
        conn.execute('''
            INSERT INTO skills (
                consultant_id, skill_name, category_id
            ) VALUES (?, ?, ?)
        ''', (
            consultant_id,
            request.form['skill_name'],
            request.form.get('category_id')
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.skill_added'), 'success')
        return redirect(url_for('view_skills'))
    
    categories = get_skill_categories()
    return render_template('edit_skill.html', skill=None, categories=categories)


@app.route('/skills/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_skill(id):
    """Edit existing skill."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    skill = get_editable_record(conn, 'skills', id, consultant_id, 'messages.record_not_found')
    if not skill:
        conn.close()
        return redirect(url_for('view_skills'))
    
    if request.method == 'POST':
        if current_user.is_admin():
            conn.execute('''
                UPDATE skills SET
                    skill_name = ?, category_id = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (
                request.form['skill_name'],
                request.form.get('category_id'),
                id
            ))
        else:
            conn.execute('''
                UPDATE skills SET
                    skill_name = ?, category_id = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND consultant_id = ?
            ''', (
                request.form['skill_name'],
                request.form.get('category_id'),
                id,
                consultant_id
            ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.skill_updated'), 'success')
        return redirect(url_for('view_skills'))
    
    categories = get_skill_categories()
    conn.close()
    return render_template('edit_skill.html', skill=skill, categories=categories)


@app.route('/skills/delete/<int:id>', methods=['POST'])
@login_required
def delete_skill(id):
    """Delete skill."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    skill = get_editable_record(conn, 'skills', id, consultant_id, 'messages.record_not_found')
    if not skill:
        conn.close()
        return redirect(url_for('view_skills'))

    if current_user.is_admin():
        conn.execute('DELETE FROM skills WHERE id = ?', (id,))
    else:
        conn.execute(
            'DELETE FROM skills WHERE id = ? AND consultant_id = ?',
            (id, consultant_id)
        )
    conn.commit()
    conn.close()
    flash(get_translation('messages.skill_deleted'), 'success')
    return redirect(url_for('view_skills'))


# ==================== Projects Routes ====================

@app.route('/projects')
@login_required
def view_projects():
    """View all projects."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    projects_raw = conn.execute(
        '''
        SELECT * FROM projects
        WHERE consultant_id = ?
        ORDER BY
            CASE
                WHEN end_date IS NULL OR end_date = '' THEN 0
                ELSE 1
            END,
            CASE
                WHEN end_date IS NULL OR end_date = '' THEN start_date
                ELSE NULL
            END DESC,
            CASE
                WHEN end_date IS NULL OR end_date = '' THEN NULL
                ELSE end_date
            END DESC,
            start_date DESC
        ''',
        (consultant_id,)
    ).fetchall()
    
    projects = []
    for proj in projects_raw:
        proj_dict = dict(proj)
        # Fetch skills for this project
        skills = conn.execute('''
            SELECT s.skill_name 
            FROM skills s
            JOIN project_skills ps ON s.id = ps.skill_id
            WHERE ps.project_id = ?
            ORDER BY s.skill_name
        ''', (proj['id'],)).fetchall()
        proj_dict['skills'] = [s['skill_name'] for s in skills]
        projects.append(proj_dict)
        
    conn.close()
    return render_template('projects.html', projects=projects)


@app.route('/projects/add', methods=['GET', 'POST'])
@login_required
def add_project():
    """Add new project."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    if request.method == 'POST':
        cursor = conn.execute('''
            INSERT INTO projects (
                consultant_id, project_name, description, start_date, end_date,
                project_url, github_url, role, achievements
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            request.form['project_name'],
            request.form.get('description', ''),
            request.form.get('start_date', None),
            request.form.get('end_date', None),
            request.form.get('project_url', ''),
            request.form.get('github_url', ''),
            request.form.get('role', ''),
            request.form.get('achievements', '')
        ))
        
        project_id = cursor.lastrowid
        
        # Handle linked skills
        skill_ids = filter_skill_ids_for_consultant(conn, consultant_id, request.form.getlist('skill_ids'))
        for skill_id in skill_ids:
            conn.execute(
                'INSERT INTO project_skills (project_id, skill_id) VALUES (?, ?)',
                (project_id, skill_id)
            )
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.project_added'), 'success')
        return redirect(url_for('view_projects'))
    
    all_skills = conn.execute('''
        SELECT s.id, s.skill_name, c.name as category_name
        FROM skills s
        LEFT JOIN skill_categories c ON s.category_id = c.id
        WHERE s.consultant_id = ?
        ORDER BY c.name, s.skill_name
    ''', (consultant_id,)).fetchall()
    conn.close()
    return render_template('edit_project.html', project=None, all_skills=all_skills)


@app.route('/projects/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_project(id):
    """Edit existing project."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    project = get_editable_record(conn, 'projects', id, consultant_id, 'messages.record_not_found')

    if not project:
        conn.close()
        return redirect(url_for('view_projects'))

    target_consultant_id = project['consultant_id']
    
    if request.method == 'POST':
        if current_user.is_admin():
            conn.execute('''
                UPDATE projects SET
                    project_name = ?, description = ?, start_date = ?,
                    end_date = ?, project_url = ?, github_url = ?, role = ?, achievements = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (
                request.form['project_name'],
                request.form.get('description', ''),
                request.form.get('start_date', None),
                request.form.get('end_date', None),
                request.form.get('project_url', ''),
                request.form.get('github_url', ''),
                request.form.get('role', ''),
                request.form.get('achievements', ''),
                id
            ))
        else:
            conn.execute('''
                UPDATE projects SET
                    project_name = ?, description = ?, start_date = ?,
                    end_date = ?, project_url = ?, github_url = ?, role = ?, achievements = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND consultant_id = ?
            ''', (
                request.form['project_name'],
                request.form.get('description', ''),
                request.form.get('start_date', None),
                request.form.get('end_date', None),
                request.form.get('project_url', ''),
                request.form.get('github_url', ''),
                request.form.get('role', ''),
                request.form.get('achievements', ''),
                id,
                consultant_id
            ))
        
        # Update linked skills
        conn.execute('DELETE FROM project_skills WHERE project_id = ?', (id,))
        skill_ids = filter_skill_ids_for_consultant(conn, target_consultant_id, request.form.getlist('skill_ids'))
        for skill_id in skill_ids:
            conn.execute(
                'INSERT INTO project_skills (project_id, skill_id) VALUES (?, ?)',
                (id, skill_id)
            )
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.project_updated'), 'success')
        return redirect(url_for('view_projects'))
    
    all_skills = conn.execute('''
        SELECT s.id, s.skill_name, c.name as category_name
        FROM skills s
        LEFT JOIN skill_categories c ON s.category_id = c.id
        WHERE s.consultant_id = ?
        ORDER BY c.name, s.skill_name
    ''', (target_consultant_id,)).fetchall()
    
    current_skill_ids = [row['skill_id'] for row in conn.execute(
        'SELECT skill_id FROM project_skills WHERE project_id = ?',
        (id,)
    ).fetchall()]
    
    conn.close()
    return render_template('edit_project.html', 
                         project=project, 
                         all_skills=all_skills,
                         current_skill_ids=current_skill_ids)


@app.route('/projects/delete/<int:id>', methods=['POST'])
@login_required
def delete_project(id):
    """Delete project."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    project = get_editable_record(conn, 'projects', id, consultant_id, 'messages.record_not_found')
    if not project:
        conn.close()
        return redirect(url_for('view_projects'))

    if current_user.is_admin():
        conn.execute('DELETE FROM projects WHERE id = ?', (id,))
    else:
        conn.execute(
            'DELETE FROM projects WHERE id = ? AND consultant_id = ?',
            (id, consultant_id)
        )
    conn.commit()
    conn.close()
    flash(get_translation('messages.project_deleted'), 'success')
    return redirect(url_for('view_projects'))


# ==================== Certifications Routes ====================

@app.route('/certifications')
@login_required
def view_certifications():
    """View all certifications."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    certifications_raw = conn.execute(
        'SELECT * FROM certifications WHERE consultant_id = ? ORDER BY issue_date IS NULL, issue_date DESC',
        (consultant_id,)
    ).fetchall()
    # Add issue_year to each certification
    certifications = []
    for cert in certifications_raw:
        cert_dict = dict(cert)
        if cert_dict.get('issue_date'):
            issue_date_str = str(cert_dict['issue_date'])
            if issue_date_str and len(issue_date_str) >= 4:
                cert_dict['issue_year'] = issue_date_str[:4]
        cert_dict['skills'] = [row['skill_name'] for row in conn.execute(
            '''
            SELECT s.skill_name
            FROM skills s
            JOIN certification_skills cs ON s.id = cs.skill_id
            WHERE cs.certification_id = ?
            ORDER BY s.skill_name
            ''',
            (cert['id'],)
        ).fetchall()]
        certifications.append(cert_dict)

    conn.close()
    
    return render_template('certifications.html', certifications=certifications)


@app.route('/certifications/add', methods=['GET', 'POST'])
@login_required
def add_certification():
    """Add new certification."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)

    if request.method == 'POST':
        cursor = conn.execute('''
            INSERT INTO certifications (
                consultant_id, certification_name, issuing_organization, issue_date, expiration_date,
                credential_id, credential_url, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            request.form['certification_name'],
            request.form['issuing_organization'],
            request.form.get('issue_date', None),
            request.form.get('expiration_date', None),
            request.form.get('credential_id', ''),
            request.form.get('credential_url', ''),
            request.form.get('description', '')
        ))

        certification_id = cursor.lastrowid
        skill_ids = filter_skill_ids_for_consultant(conn, consultant_id, request.form.getlist('skill_ids'))
        for skill_id in skill_ids:
            conn.execute(
                'INSERT INTO certification_skills (certification_id, skill_id) VALUES (?, ?)',
                (certification_id, skill_id)
            )
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.certification_added'), 'success')
        return redirect(url_for('view_certifications'))

    all_skills = conn.execute('''
        SELECT s.id, s.skill_name, c.name as category_name
        FROM skills s
        LEFT JOIN skill_categories c ON s.category_id = c.id
        WHERE s.consultant_id = ?
        ORDER BY c.name, s.skill_name
    ''', (consultant_id,)).fetchall()
    conn.close()
    
    return render_template('edit_certification.html', certification=None, all_skills=all_skills, current_skill_ids=[])


@app.route('/certifications/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_certification(id):
    """Edit existing certification."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    certification = get_editable_record(conn, 'certifications', id, consultant_id, 'messages.record_not_found')
    if not certification:
        conn.close()
        return redirect(url_for('view_certifications'))
    
    if request.method == 'POST':
        if current_user.is_admin():
            conn.execute('''
                UPDATE certifications SET
                    certification_name = ?, issuing_organization = ?, issue_date = ?,
                    expiration_date = ?, credential_id = ?, credential_url = ?, description = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (
                request.form['certification_name'],
                request.form['issuing_organization'],
                request.form.get('issue_date', None),
                request.form.get('expiration_date', None),
                request.form.get('credential_id', ''),
                request.form.get('credential_url', ''),
                request.form.get('description', ''),
                id
            ))
        else:
            conn.execute('''
                UPDATE certifications SET
                    certification_name = ?, issuing_organization = ?, issue_date = ?,
                    expiration_date = ?, credential_id = ?, credential_url = ?, description = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND consultant_id = ?
            ''', (
                request.form['certification_name'],
                request.form['issuing_organization'],
                request.form.get('issue_date', None),
                request.form.get('expiration_date', None),
                request.form.get('credential_id', ''),
                request.form.get('credential_url', ''),
                request.form.get('description', ''),
                id,
                consultant_id
            ))

        target_consultant_id = certification['consultant_id'] if current_user.is_admin() else consultant_id
        conn.execute('DELETE FROM certification_skills WHERE certification_id = ?', (id,))
        skill_ids = filter_skill_ids_for_consultant(conn, target_consultant_id, request.form.getlist('skill_ids'))
        for skill_id in skill_ids:
            conn.execute(
                'INSERT INTO certification_skills (certification_id, skill_id) VALUES (?, ?)',
                (id, skill_id)
            )
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.certification_updated'), 'success')
        return redirect(url_for('view_certifications'))

    target_consultant_id = certification['consultant_id'] if current_user.is_admin() else consultant_id
    all_skills = conn.execute('''
        SELECT s.id, s.skill_name, c.name as category_name
        FROM skills s
        LEFT JOIN skill_categories c ON s.category_id = c.id
        WHERE s.consultant_id = ?
        ORDER BY c.name, s.skill_name
    ''', (target_consultant_id,)).fetchall()
    current_skill_ids = [row['skill_id'] for row in conn.execute(
        'SELECT skill_id FROM certification_skills WHERE certification_id = ?',
        (id,)
    ).fetchall()]

    conn.close()
    return render_template('edit_certification.html', certification=certification, all_skills=all_skills, current_skill_ids=current_skill_ids)


@app.route('/certifications/delete/<int:id>', methods=['POST'])
@login_required
def delete_certification(id):
    """Delete certification."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    certification = get_editable_record(conn, 'certifications', id, consultant_id, 'messages.record_not_found')
    if not certification:
        conn.close()
        return redirect(url_for('view_certifications'))

    if current_user.is_admin():
        conn.execute('DELETE FROM certifications WHERE id = ?', (id,))
    else:
        conn.execute(
            'DELETE FROM certifications WHERE id = ? AND consultant_id = ?',
            (id, consultant_id)
        )
    conn.commit()
    conn.close()
    flash(get_translation('messages.certification_deleted'), 'success')
    return redirect(url_for('view_certifications'))


# ==================== CV Export Routes ====================

@app.route('/export-cv')
@login_required
def export_cv():
    """Display CV export page."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    # Check if there's any data to export
    personal_info = conn.execute(
        'SELECT * FROM personal_info WHERE consultant_id = ?',
        (consultant_id,)
    ).fetchone()
    
    work_count = conn.execute(
        'SELECT COUNT(*) as count FROM work_experience WHERE consultant_id = ?',
        (consultant_id,)
    ).fetchone()['count']
    
    conn.close()
    
    has_data = personal_info is not None or work_count > 0
    
    return render_template('export_cv.html', has_data=has_data)


def build_docx_cv(cv_data, avg_proof=False):
    """Build a native DOCX CV with consistent styling and structure."""
    from docx import Document
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt, Inches, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    HEADER_COLOR = RGBColor(245, 175, 2)
    FONT_COLOR = RGBColor(0, 0, 0)

    def tr(key):
        return get_translation(key, lang)

    def as_dict(record):
        if record is None:
            return {}
        if isinstance(record, dict):
            return record
        try:
            return dict(record)
        except Exception:
            return {}

    def clean_text(value):
        return str(value or '').strip()

    def add_bottom_border(paragraph, color, size='8', space='1'):
        p_pr = paragraph._p.get_or_add_pPr()
        p_borders = p_pr.find(qn('w:pBdr'))
        if p_borders is None:
            p_borders = OxmlElement('w:pBdr')
            p_pr.append(p_borders)

        bottom = p_borders.find(qn('w:bottom'))
        if bottom is None:
            bottom = OxmlElement('w:bottom')
            p_borders.append(bottom)

        bottom.set(qn('w:val'), 'single')
        bottom.set(qn('w:sz'), size)
        bottom.set(qn('w:space'), space)
        bottom.set(qn('w:color'), str(color))

    def add_section_heading(text):
        heading = doc.add_paragraph()
        heading.paragraph_format.space_before = Pt(6)
        heading.paragraph_format.space_after = Pt(2)
        run = heading.add_run(text)
        run.bold = True
        run.font.size = Pt(12)
        run.font.color.rgb = FONT_COLOR
        add_bottom_border(heading, HEADER_COLOR)

    def add_markdownish_text(text):
        lines = [line.rstrip() for line in clean_text(text).splitlines()]
        if not lines:
            return

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            if re.match(r'^[-*+]\s+', line) or re.match(r'^\d+[\.)]\s+', line):
                line = re.sub(r'^[-*+]\s+', '', line)
                line = re.sub(r'^\d+[\.)]\s+', '', line)
                paragraph = doc.add_paragraph(line, style='List Bullet')
            else:
                paragraph = doc.add_paragraph(line)
            paragraph.paragraph_format.space_after = Pt(0)

    def format_period(start_date, end_date, ongoing_label):
        start = clean_text(start_date)
        end = clean_text(end_date)
        if not start and not end:
            return ''
        if not start:
            return end or ongoing_label
        return f"{start} - {end or ongoing_label}"

    doc = Document()
    section = doc.sections[0]
    section.top_margin = Inches(0.6)
    section.bottom_margin = Inches(0.6)
    section.left_margin = Inches(0.7)
    section.right_margin = Inches(0.7)

    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(10)

    lang = cv_data.get('current_lang') or session.get('language', 'en')
    personal_info = as_dict(cv_data.get('personal_info'))

    if not avg_proof:
        logo_path = Path(app.root_path, 'static', 'ibs-logo-print.png')
        if logo_path.exists():
            logo_paragraph = doc.add_paragraph()
            logo_paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            logo_paragraph.add_run().add_picture(str(logo_path), width=Inches(1.6))

    if personal_info:
        full_name = f"{clean_text(personal_info.get('first_name'))} {clean_text(personal_info.get('last_name'))}".strip()
        if full_name:
            title = doc.add_paragraph()
            title.paragraph_format.space_after = Pt(1)
            run = title.add_run(full_name)
            run.bold = True
            run.font.size = Pt(20)
            run.font.color.rgb = HEADER_COLOR

        if not avg_proof and clean_text(personal_info.get('email')):
            doc.add_paragraph(clean_text(personal_info.get('email'))).paragraph_format.space_after = Pt(0)
        if not avg_proof and clean_text(personal_info.get('phone')):
            doc.add_paragraph(clean_text(personal_info.get('phone'))).paragraph_format.space_after = Pt(0)

        if avg_proof:
            city = clean_text(personal_info.get('city'))
            if city:
                doc.add_paragraph(city).paragraph_format.space_after = Pt(0)
        else:
            address_parts = []
            address = clean_text(personal_info.get('address'))
            zip_code = clean_text(personal_info.get('zip_code'))
            city = clean_text(personal_info.get('city'))
            state = clean_text(personal_info.get('state'))
            country = clean_text(personal_info.get('country'))

            if address:
                address_parts.append(address)
            city_part = f"{zip_code} {city}".strip() if (zip_code or city) else ''
            if city_part:
                address_parts.append(city_part)
            if state:
                address_parts.append(f"({state})")
            if country:
                address_parts.append(country)
            if address_parts:
                doc.add_paragraph(', '.join(address_parts)).paragraph_format.space_after = Pt(0)

        if not avg_proof:
            links = []
            linkedin = clean_text(personal_info.get('linkedin_url'))
            github = clean_text(personal_info.get('github_url'))
            portfolio = clean_text(personal_info.get('portfolio_url'))
            if linkedin:
                links.append(f"LinkedIn: {linkedin}")
            if github:
                links.append(f"GitHub: {github}")
            if portfolio:
                links.append(f"Portfolio: {portfolio}")
            if links:
                doc.add_paragraph(' | '.join(links)).paragraph_format.space_after = Pt(0)

        summary = clean_text(personal_info.get('professional_summary'))
        if summary:
            add_section_heading(tr('personal_info.professional_summary'))
            add_markdownish_text(summary)

    certifications = cv_data.get('certifications') or []
    if certifications:
        add_section_heading(tr('certifications.title'))
        for cert in certifications:
            cert_name = clean_text(cert.get('certification_name'))
            issuer = clean_text(cert.get('issuing_organization'))
            issue_year = clean_text(cert.get('issue_year'))
            cert_line = cert_name
            if issuer:
                cert_line = f"{cert_line}: {issuer}" if cert_line else issuer
            if issue_year:
                cert_line = f"{cert_line} ({issue_year})" if cert_line else f"({issue_year})"
            if cert_line:
                bullet = doc.add_paragraph(cert_line, style='List Bullet')
                bullet.paragraph_format.space_after = Pt(0)

            expiration = clean_text(cert.get('expiration_date'))
            if expiration:
                doc.add_paragraph(f"{tr('certifications.expires')}: {expiration}")

            credential_id = clean_text(cert.get('credential_id'))
            if credential_id:
                doc.add_paragraph(f"{tr('certifications.credential_id')}: {credential_id}")

            cert_desc = clean_text(cert.get('description'))
            if cert_desc:
                add_markdownish_text(cert_desc)

    work_experiences = cv_data.get('work_experiences') or []
    if work_experiences:
        add_section_heading(tr('work_experience.title'))
        for exp in work_experiences:
            company = clean_text(exp.get('company_name'))
            position = clean_text(exp.get('position_title'))
            start = clean_text(exp.get('start_date_display') or exp.get('start_date'))
            end = tr('work_experience.present') if exp.get('is_current') else clean_text(exp.get('end_date_display') or exp.get('end_date'))
            period = format_period(start, end, tr('work_experience.present'))

            heading = doc.add_paragraph()
            heading.paragraph_format.space_before = Pt(6)
            heading.paragraph_format.space_after = Pt(2)
            add_bottom_border(heading, FONT_COLOR, '2')

            title_text = company
            if position:
                title_text = f"{title_text} | {position}" if title_text else position
            heading_run = heading.add_run(title_text)
            heading_run.bold = True
            heading_run.font.size = Pt(11)
            if period:
                period_run = heading.add_run(f" ({period})")
                period_run.italic = True
                period_run.font.size = Pt(9)
                period_run.font.color.rgb = RGBColor(127, 140, 141)

            for field in ['description', 'achievements']:
                text = clean_text(exp.get(field))
                if text:
                    if field == 'achievements':
                        label = doc.add_paragraph()
                        label.add_run(f"{tr('work_experience.achievements')}: ").bold = True
                        label.paragraph_format.space_before = Pt(2)
                        label.paragraph_format.space_after = Pt(0)
                    add_markdownish_text(text)

            for key, label_key in [
                ('star_situation', 'work_experience.star_situation'),
                ('star_tasks', 'work_experience.star_tasks'),
                ('star_actions', 'work_experience.star_actions'),
                ('star_results', 'work_experience.star_results'),
            ]:
                text = clean_text(exp.get(key))
                if text:
                    label = doc.add_paragraph()
                    label.paragraph_format.space_after = Pt(0)
                    label.add_run(f"{tr(label_key)}: ").bold = True
                    add_markdownish_text(text)

            skills = exp.get('skills') or []
            if skills:
                line = doc.add_paragraph()
                line.add_run(f"{tr('skills.title')}: ").italic = True
                line.add_run(', '.join(str(skill) for skill in skills if str(skill).strip())).italic = True

    skills_by_category = cv_data.get('skills_by_category') or {}
    if skills_by_category:
        add_section_heading(tr('skills.title'))
        for category_name, category_skills in skills_by_category.items():
            names = []
            for skill in category_skills:
                if isinstance(skill, dict):
                    name = clean_text(skill.get('skill_name'))
                else:
                    try:
                        name = clean_text(skill['skill_name'])
                    except Exception:
                        name = clean_text(getattr(skill, 'skill_name', ''))
                if name:
                    names.append(name)
            names = [name for name in names if name]
            if names:
                line = doc.add_paragraph()
                line.add_run(f"{category_name}: ").bold = True
                line.add_run(', '.join(names))
                line.paragraph_format.space_after = Pt(0)

    projects = cv_data.get('projects') or []
    if projects:
        add_section_heading(tr('projects.title'))
        for project in projects:
            name = clean_text(project.get('project_name'))
            start = clean_text(project.get('start_date_display') or project.get('start_date'))
            end = clean_text(project.get('end_date_display') or project.get('end_date'))
            period = format_period(start, end, tr('projects.ongoing'))

            heading = doc.add_paragraph()
            heading.paragraph_format.space_before = Pt(6)
            heading.paragraph_format.space_after = Pt(2)
            add_bottom_border(heading, FONT_COLOR, '2')

            role = clean_text(project.get('role'))
            if role:
                role = f" | {role}"
            run = heading.add_run(f"{name}{role}")

            run.bold = True
            run.font.size = Pt(11)
            if period:
                date_run = heading.add_run(f" ({period})")
                date_run.italic = True
                date_run.font.size = Pt(9)
                date_run.font.color.rgb = RGBColor(127, 140, 141)

            description = clean_text(project.get('description'))
            if description:
                add_markdownish_text(description)

            achievements = clean_text(project.get('achievements'))
            if achievements:
                label = doc.add_paragraph()
                label.add_run(f"{tr('projects.achievements')}: ").bold = True
                label.paragraph_format.space_before = Pt(2)
                label.paragraph_format.space_after = Pt(0)
                add_markdownish_text(achievements)

            skills = [clean_text(skill) for skill in (project.get('skills') or [])]
            skills = [skill for skill in skills if skill]
            if skills:
                line = doc.add_paragraph()
                line.add_run(f"{tr('skills.title')}: ").bold = True
                line.add_run(', '.join(skills))

            project_url = clean_text(project.get('project_url'))
            github_url = clean_text(project.get('github_url'))
            if project_url or github_url:
                links = []
                if project_url:
                    links.append(f"{tr('projects.project_url_link')}: {project_url}")
                if github_url:
                    links.append(f"{tr('projects.github_repo')}: {github_url}")

                # doc.add_paragraph(' | '.join(links))

    education = cv_data.get('education') or []
    if education:
        add_section_heading(tr('education.title'))
        for edu in education:
            degree = clean_text(edu.get('degree'))
            field = clean_text(edu.get('field_of_study'))
            start_year = clean_text(edu.get('start_year'))
            end_year = clean_text(edu.get('end_year'))
            period = format_period(start_year, end_year, tr('education.in_progress'))

            heading = doc.add_paragraph()
            heading.paragraph_format.space_before = Pt(4)
            heading.paragraph_format.space_after = Pt(2)

            institution = clean_text(edu.get('institution_name'))
            location = clean_text(edu.get('location'))
            if institution or location:
                extra = f"[{institution}{', ' if institution and location else ''}{location}]"

            title = degree
            if field:
                title = f"{title} - {field} {extra}" if title else field
            run = heading.add_run(title)
            run.bold = True
            run.font.size = Pt(11)
            if period:
                period_run = heading.add_run(f" ({period})")
                period_run.italic = True
                period_run.font.size = Pt(9)
                period_run.font.color.rgb = RGBColor(127, 140, 141)

            gpa = clean_text(edu.get('gpa'))
            honors = clean_text(edu.get('honors'))
            if gpa:
                line = doc.add_paragraph()
                line.add_run(f"{tr('education.gpa')}: ").bold = True
                line.add_run(gpa)
            if honors:
                line = doc.add_paragraph()
                line.add_run(f"{tr('education.honors')}: ").bold = True
                line.add_run(honors)

            description = clean_text(edu.get('description'))
            if description:
                add_markdownish_text(description)

    out = io.BytesIO()
    doc.save(out)
    out.seek(0)
    return out.getvalue()


@app.route('/export-cv/preview')
@login_required
def preview_cv():
    """Preview CV in HTML format."""
    avg_proof = (request.args.get('avg_proof') or '').strip().lower() in {'1', 'true', 'on', 'yes'}
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    # Get all CV data
    cv_data = get_cv_data(conn, consultant_id)
    conn.close()
    
    return render_template('cv_template.html', avg_proof=avg_proof, **cv_data)


@app.route('/export-cv/download', methods=['POST'])
@login_required
def export_cv_download():
    """Download CV in selected format."""
    format_type = request.form.get('format', 'html')
    avg_proof = (request.form.get('avg_proof') or '').strip().lower() in {'1', 'true', 'on', 'yes'}
    
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    # Get all CV data
    cv_data = get_cv_data(conn, consultant_id)
    conn.close()
    
    # Get consultant name for filename
    if cv_data['personal_info']:
        raw_filename = f"CV_{cv_data['personal_info']['first_name']}_{cv_data['personal_info']['last_name']}"
    else:
        raw_filename = "CV_Export"

    # Build a header-safe filename to avoid invalid Content-Disposition parsing.
    filename = ''.join(c if c.isalnum() or c in {'-', '_'} else '_' for c in raw_filename).strip('_') or 'CV_Export'
    logo_src = Path(app.root_path, 'static', 'ibs-logo-print.png').as_uri()

    def build_download_response(data, mimetype, extension):
        response = Response(data, mimetype=mimetype)
        response.headers.set('Content-Disposition', 'attachment', filename=f'{filename}.{extension}')
        return response

    def build_export_error_response(message):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return Response(message, status=500, mimetype='text/plain')
        flash(message, 'error')
        return redirect(url_for('export_cv'))
    
    if format_type == 'html':
        html_content = render_template('cv_template.html', avg_proof=avg_proof, **cv_data)
        return build_download_response(html_content, 'text/html', 'html')
    
    elif format_type == 'pdf':
        try:
            from weasyprint import HTML
            html_content = render_template('cv_template.html', logo_src=logo_src, avg_proof=avg_proof, **cv_data)
            pdf = HTML(string=html_content, base_url=request.url_root).write_pdf()
            return build_download_response(pdf, 'application/pdf', 'pdf')
        except Exception as e:
            return build_export_error_response(
                f'PDF generation failed: {str(e)}. Please install WeasyPrint dependencies or use HTML export.'
            )
    
    elif format_type == 'docx':
        try:
            docx_content = build_docx_cv(cv_data, avg_proof=avg_proof)
            return build_download_response(
                docx_content,
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'docx'
            )
        except Exception as e:
            return build_export_error_response(f'Word document generation failed: {str(e)}')
    
    elif format_type == 'json':
        # Export as JSON (similar to export_consultant but for current consultant)
        conn = get_db_connection()
        consultant_id = resolve_current_consultant_id(conn)
        
        consultant = conn.execute(
            'SELECT id, display_name FROM consultants WHERE id = ?',
            (consultant_id,)
        ).fetchone()
        
        payload = {
            'version': 1,
            'consultant': {
                'display_name': consultant['display_name'] if consultant else 'Unknown'
            },
            'personal_info': None,
            'work_experience': [],
            'education': [],
            'skills': [],
            'projects': [],
            'certifications': []
        }

        personal_info = conn.execute(
            'SELECT * FROM personal_info WHERE consultant_id = ? ORDER BY id DESC LIMIT 1',
            (consultant_id,)
        ).fetchone()
        if personal_info:
            payload['personal_info'] = dict(personal_info)
            payload['personal_info'].pop('id', None)
            payload['personal_info'].pop('consultant_id', None)
            payload['personal_info'].pop('created_at', None)
            payload['personal_info'].pop('updated_at', None)
            if avg_proof:
                payload['personal_info']['email'] = ''
                payload['personal_info']['phone'] = ''
                payload['personal_info']['address'] = ''
                payload['personal_info']['zip_code'] = ''
                payload['personal_info']['state'] = ''
                payload['personal_info']['country'] = ''
                payload['personal_info']['linkedin_url'] = ''
                payload['personal_info']['github_url'] = ''
                payload['personal_info']['portfolio_url'] = ''

        for table, key in [
            ('work_experience', 'work_experience'),
            ('education', 'education'),
            ('skills', 'skills'),
            ('projects', 'projects'),
            ('certifications', 'certifications')
        ]:
            rows = conn.execute(
                f'SELECT * FROM {table} WHERE consultant_id = ? ORDER BY id',
                (consultant_id,)
            ).fetchall()
            payload[key] = []
            for row in rows:
                row_data = dict(row)
                
                # Special handling for skills to include category name
                if table == 'skills' and row_data.get('category_id'):
                    cat = conn.execute('SELECT name FROM skill_categories WHERE id = ?', (row_data['category_id'],)).fetchone()
                    if cat:
                        row_data['category_name'] = cat['name']

                # Special handling for experience and projects to include linked skills
                if table == 'work_experience':
                    skills = conn.execute('''
                        SELECT s.skill_name 
                        FROM skills s
                        JOIN experience_skills es ON s.id = es.skill_id
                        WHERE es.experience_id = ?
                    ''', (row['id'],)).fetchall()
                    row_data['skills'] = [s['skill_name'] for s in skills]
                
                if table == 'projects':
                    skills = conn.execute('''
                        SELECT s.skill_name 
                        FROM skills s
                        JOIN project_skills ps ON s.id = ps.skill_id
                        WHERE ps.project_id = ?
                    ''', (row['id'],)).fetchall()
                    row_data['skills'] = [s['skill_name'] for s in skills]

                if table == 'certifications':
                    skills = conn.execute('''
                        SELECT s.skill_name 
                        FROM skills s
                        JOIN certification_skills cs ON s.id = cs.skill_id
                        WHERE cs.certification_id = ?
                    ''', (row['id'],)).fetchall()
                    row_data['skills'] = [s['skill_name'] for s in skills]

                row_data.pop('id', None)
                row_data.pop('consultant_id', None)
                row_data.pop('created_at', None)
                row_data.pop('updated_at', None)
                row_data.pop('category', None)  # Remove old text category field if exists
                row_data.pop('years_of_experience', None)  # Remove legacy field if it exists
                payload[key].append(row_data)

        conn.close()
        
        return build_download_response(json.dumps(payload, indent=2), 'application/json', 'json')
    
    return build_export_error_response('Invalid format selected')


def get_cv_data(conn, consultant_id):
    """Helper function to retrieve all CV data for a consultant."""
    
    # Personal Info
    personal_info = conn.execute(
        'SELECT * FROM personal_info WHERE consultant_id = ?',
        (consultant_id,)
    ).fetchone()
    
    # Work Experience
    work_experience_rows = conn.execute(
        '''
        SELECT * FROM work_experience
        WHERE consultant_id = ?
        ORDER BY
            CASE
                WHEN is_current = 1 OR end_date IS NULL OR end_date = '' THEN 0
                ELSE 1
            END,
            CASE
                WHEN is_current = 1 OR end_date IS NULL OR end_date = '' THEN start_date
                ELSE NULL
            END DESC,
            CASE
                WHEN is_current = 1 OR end_date IS NULL OR end_date = '' THEN NULL
                ELSE end_date
            END DESC,
            start_date DESC
        ''',
        (consultant_id,)
    ).fetchall()

    work_experiences = []
    for row in work_experience_rows:
        exp_data = dict(row)
        skills = conn.execute('''
            SELECT s.skill_name
            FROM skills s
            JOIN experience_skills es ON s.id = es.skill_id
            WHERE es.experience_id = ?
            ORDER BY s.skill_name
        ''', (row['id'],)).fetchall()
        exp_data['skills'] = [s['skill_name'] for s in skills]
        exp_data['start_date_display'] = format_year_month(exp_data.get('start_date'))
        exp_data['end_date_display'] = format_year_month(exp_data.get('end_date'))
        work_experiences.append(exp_data)
    
    # Education
    education_rows = conn.execute(
        'SELECT * FROM education WHERE consultant_id = ? ORDER BY start_date IS NULL, start_date DESC',
        (consultant_id,)
    ).fetchall()

    education = []
    for row in education_rows:
        edu_data = dict(row)
        start_date = str(edu_data.get('start_date') or '').strip()
        end_date = str(edu_data.get('end_date') or '').strip()
        edu_data['start_year'] = start_date[:4] if len(start_date) >= 4 else ''
        edu_data['end_year'] = end_date[:4] if len(end_date) >= 4 else ''
        education.append(edu_data)
    
    # Certifications
    certifications_raw = conn.execute(
        'SELECT * FROM certifications WHERE consultant_id = ? ORDER BY issue_date IS NULL, issue_date DESC',
        (consultant_id,)
    ).fetchall()
    
    # Add issue_year to each certification
    certifications = []
    for cert in certifications_raw:
        cert_dict = dict(cert)
        if cert_dict.get('issue_date'):
            issue_date_str = str(cert_dict['issue_date'])
            if issue_date_str and len(issue_date_str) >= 4:
                cert_dict['issue_year'] = issue_date_str[:4]
        cert_dict['skills'] = [row['skill_name'] for row in conn.execute(
            '''
            SELECT s.skill_name
            FROM skills s
            JOIN certification_skills cs ON s.id = cs.skill_id
            WHERE cs.certification_id = ?
            ORDER BY s.skill_name
            ''',
            (cert['id'],)
        ).fetchall()]
        certifications.append(cert_dict)
    
    # Skills grouped by category
    skills = conn.execute('''
        SELECT s.*, c.name as category_name
        FROM skills s
        LEFT JOIN skill_categories c ON s.category_id = c.id
        WHERE s.consultant_id = ?
        ORDER BY c.name, s.skill_name
    ''', (consultant_id,)).fetchall()
    
    skills_by_category = {}
    for skill in skills:
        category = skill['category_name'] or get_translation('skills.uncategorized')
        if category not in skills_by_category:
            skills_by_category[category] = []
        skills_by_category[category].append(skill)
    
    # Projects
    project_rows = conn.execute(
        '''
        SELECT * FROM projects
        WHERE consultant_id = ?
        ORDER BY
            CASE
                WHEN end_date IS NULL OR end_date = '' THEN 0
                ELSE 1
            END,
            CASE
                WHEN end_date IS NULL OR end_date = '' THEN start_date
                ELSE NULL
            END DESC,
            CASE
                WHEN end_date IS NULL OR end_date = '' THEN NULL
                ELSE end_date
            END DESC,
            start_date DESC
        ''',
        (consultant_id,)
    ).fetchall()

    projects = []
    for row in project_rows:
        project_data = dict(row)
        skills = conn.execute('''
            SELECT s.skill_name
            FROM skills s
            JOIN project_skills ps ON s.id = ps.skill_id
            WHERE ps.project_id = ?
            ORDER BY s.skill_name
        ''', (row['id'],)).fetchall()
        project_data['skills'] = [s['skill_name'] for s in skills]
        project_data['start_date_display'] = format_year_month(project_data.get('start_date'))
        project_data['end_date_display'] = format_year_month(project_data.get('end_date'))
        projects.append(project_data)
    
    return {
        'personal_info': personal_info,
        'work_experiences': work_experiences,
        'education': education,
        'certifications': certifications,
        'skills_by_category': skills_by_category,
        'projects': projects,
        't': TRANSLATIONS.get(session.get('language', 'en'), TRANSLATIONS['en']),
        'current_lang': session.get('language', 'en')
    }


if __name__ == '__main__':
    init_database()
    app.run(debug=True, host='0.0.0.0', port=5000)

