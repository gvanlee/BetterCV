from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from database import get_db_connection, init_database, get_skill_categories
from datetime import datetime
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import json
import os
import uuid
import sqlite3
from google import genai
from groq import Groq
import PyPDF2
import docx
import io
import tempfile

# Import authentication modules
from auth import User, get_all_users, get_all_whitelist, add_to_whitelist, remove_from_whitelist, update_user_role, deactivate_user, get_all_consultants
from decorators import admin_required, consultant_or_admin_required, check_consultant_access

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'h9sdf696f34rhfvvhkxjvodfyg8yer89g7ye-8yhoiuver8v8erf98yyh34f')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'error'

# Initialize OAuth
oauth = OAuth(app)

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
    # authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    authorize_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize',
    authorize_params=None,
    # access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
    access_token_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
    access_token_params=None,
    refresh_token_url=None,
    client_kwargs={
        'scope': 'openid email profile',
         'validate_iss': False
    },
    jwks_uri="https://login.microsoftonline.com/common/discovery/v2.0/keys"    
    # server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration'
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
    return render_template('login.html')


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
        login_user(user)
        flash(get_translation('messages.login_success'), 'success')
        
        # Set consultant_id in session for consultants
        if user.consultant_id:
            session['consultant_id'] = user.consultant_id
        
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"OAuth error: {str(e)}")
        flash(get_translation('messages.oauth_error'), 'error')
        return redirect(url_for('login'))


@app.route('/auth/microsoft')
def auth_microsoft():
    """Initiate Microsoft OAuth"""
    # redirect_uri = url_for('auth_microsoft_callback', _external=True)
    redirect_uri = (os.getenv('BASE_URL') + os.getenv('MICROSOFT_OAUTH_REDIRECT_URI')) or url_for('auth_microsoft_callback', _external=True)
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
        login_user(user)
        flash(get_translation('messages.login_success'), 'success')
        
        # Set consultant_id in session for consultants
        if user.consultant_id:
            session['consultant_id'] = user.consultant_id
        
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"OAuth error: {str(e)}")
        flash(get_translation('messages.oauth_error'), 'error')
        return redirect(url_for('login'))


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
    consultants = get_all_consultants()
    return render_template('consultants_management.html',
                         all_consultants=consultants)


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
    return conn.execute(
        'SELECT id, display_name FROM consultants ORDER BY display_name, id'
    ).fetchall()


def resolve_current_consultant_id(conn):
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


@app.before_request
def ensure_consultant_selected():
    if request.endpoint in {
        'static',
        'set_language',
        'list_consultants',
        'add_consultant',
        'switch_consultant',
        'import_consultant',
        'export_consultant',
        'parse_cv',
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
        return extract_text_from_pdf(file_content)
    elif filename.endswith(('.docx', '.doc')):
        return extract_text_from_docx(file_content)
    elif filename.endswith('.txt'):
        return file_content.decode('utf-8', errors='ignore')
    else:
        return "Unsupported file type. Please upload PDF, DOCX, or TXT files."


def get_cv_parse_prompt(cv_text):
    """Generate the prompt for CV parsing."""
    return f"""
Analyze the following CV/resume text and extract structured information 
  in JSON format.
Keep in mind that the CV may have varying formats and may not explicitly 
  label sections, so you need to infer the structure based on the content.
Also, the CV may be in either Dutch or English, so be prepared to handle 
  both languages. Focus on extracting accurate information based on what 
  is explicitly mentioned in the CV, and do not make assumptions beyond 
  the provided text.
Dates may be provided in full or partially (e.g. "Okt 2023" or "Oct 2024").
  
The JSON should match this exact schema:

{{
  "consultant": {{
    "display_name": "Full Name from CV"
  }},
  "personal_info": {{
    "first_name": "First Name",
    "last_name": "Last Name", 
    "email": "email@example.com",
    "phone": "Phone Number",
    "address": "Full Address (street and number)",
    "zip_code": "Postal Code or Zip Code",
    "city": "City",
    "country": "Country",
    "summary": "Professional summary or objective"
  }},
  "work_experience": [
    {{
      "job_title": "Job Title",
      "company_name": "Company Name",
      "location": "City, Country",
      "start_date": "YYYY-MM-DD",
      "end_date": "YYYY-MM-DD or null for current",
      "star_situation": "The context and situation of the role/project",
      "star_tasks": "The specific tasks and responsibilities",
      "star_actions": "The specific actions taken to solve problems or deliver results",
      "star_results": "The quantifiable results and achievements",
      "description": "Any remaining details not captured in STAR"
    }}
  ],
  "education": [
    {{
      "degree": "Degree Type",
      "field_of_study": "Field of Study",
      "institution": "Institution Name",
      "location": "City, Country",
      "start_date": "YYYY-MM-DD",
      "end_date": "YYYY-MM-DD",
      "description": "Additional details"
    }}
  ],
  "skills": [
    {{
      "category": "Category (one of: 'Data Analytics', 'Data Engineering', 'Data Management', 'Data Modeling', 'Databases', 'Database Administration', 'Languages', 'Operating Systems', 'Programming Languages', 'Tools' or 'Various'), attempt to map as close as possible",
      "name": "Skill Name",
      "proficiency": "Proficiency Level",
      "description": "Optional description"
    }}
  ],
  "projects": [
    {{
      "name": "Project Name",
      "description": "Project description",
      "start_date": "YYYY-MM-DD",
      "end_date": "YYYY-MM-DD or null",
      "url": "Project URL if mentioned"
    }}
  ],
  "certifications": [
    {{
      "name": "Certification Name/Course Name or name of issuing organization if specific certification name is not mentioned",
      "issuing_organization": "Issuing Organization",
      "issue_date": "YYYY-MM-DD",
      "expiry_date": "YYYY-MM-DD or null",
      "credential_id": "Credential ID if mentioned",
      "description": "Description"
    }}
  ]
}}

Rules:
- Keep the end result in Dutch if the source is in Dutch, 
    Translate English CVs into Dutch. Do not translate English
    verbs if they are used in a Dutch CV.
- If bulletpoints are used in the CV, use markdown formatting in 
    the JSON output to preserve the bullet points in the description fields.
- Dates are normally formatted as European dates, so DD-MM-YYYY,
  if abbreviated they are usually in the format "Okt 2023" or "Oct 2023", 
  in this case, "Oct 2023" should be interpreted as "2023-10-01" 
  (use the first day of the month when day is not specified).
- Format dates as YYYY-MM-DD or YYYY-MM-01 if day is unknown, or YYYY-01-01 if only year
- Extract only information that is explicitly mentioned in the CV
- For skills, group similar skills into logical categories
- Return only valid JSON, no additional text or explanations
- If information is missing, use an empty string or omit the field, do not use "None" or Null

CV Text:
{cv_text}
"""


def parse_cv_with_ai(cv_text, provider='gemini'):
    """Parse CV text using chosen AI provider and return structured data."""
    prompt = get_cv_parse_prompt(cv_text)
    
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
    conn.execute('DELETE FROM personal_info WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM work_experience WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM education WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM skills WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM projects WHERE consultant_id = ?', (consultant_id,))
    conn.execute('DELETE FROM certifications WHERE consultant_id = ?', (consultant_id,))
    
    # Also clean up junction tables for this consultant's entities
    # Note: ON DELETE CASCADE handles this if the parent rows are deleted, 
    # but since we are re-inserting, we ensure a clean slate.

    personal_info = payload.get('personal_info')
    if isinstance(personal_info, dict):
        conn.execute('''
            INSERT INTO personal_info (
                consultant_id, first_name, last_name, email, phone, address, city,
                state, zip_code, country, linkedin_url, github_url, portfolio_url,
                professional_summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            personal_info.get('first_name', ''),
            personal_info.get('last_name', ''),
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
            personal_info.get('professional_summary', personal_info.get('summary', ''))
        ))

    for exp in payload.get('work_experience', []):
        conn.execute('''
            INSERT INTO work_experience (
                consultant_id, company_name, position_title, location, start_date,
                end_date, is_current, description, achievements, 
                star_situation, star_tasks, star_actions, star_results,
                display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            exp.get('star_results', ''),
            exp.get('display_order', 0)
        ))

    for edu in payload.get('education', []):
        conn.execute('''
            INSERT INTO education (
                consultant_id, institution_name, degree, field_of_study, location,
                start_date, end_date, gpa, honors, description, display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            edu.get('description', ''),
            edu.get('display_order', 0)
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

    for skill in payload.get('skills', []):
        cat_name = skill.get('category_name', skill.get('category', '')).strip()
        
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
                consultant_id, skill_name, category_id, proficiency_level,
                display_order
            ) VALUES (?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            skill.get('skill_name', skill.get('name', '')),
            category_id,
            skill.get('proficiency_level', skill.get('proficiency', '')),
            skill.get('display_order', 0)
        ))
        skill_name_to_id[skill.get('skill_name', skill.get('name', '')).lower()] = cursor.lastrowid

    for exp in payload.get('work_experience', []):
        cursor = conn.execute('''
            INSERT INTO work_experience (
                consultant_id, company_name, position_title, location, start_date,
                end_date, is_current, description, achievements, 
                star_situation, star_tasks, star_actions, star_results,
                display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            exp.get('star_results', ''),
            exp.get('display_order', 0)
        ))
        
        # Link skills to work experience
        exp_id = cursor.lastrowid
        for skill_name in exp.get('skills', []):
            skill_id = skill_name_to_id.get(skill_name.lower())
            if skill_id:
                conn.execute('INSERT INTO experience_skills (experience_id, skill_id) VALUES (?, ?)', (exp_id, skill_id))

    for edu in payload.get('education', []):
        conn.execute('''
            INSERT INTO education (
                consultant_id, institution_name, degree, field_of_study, location,
                start_date, end_date, gpa, honors, description, display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            edu.get('description', ''),
            edu.get('display_order', 0)
        ))

    for project in payload.get('projects', []):
        cursor = conn.execute('''
            INSERT INTO projects (
                consultant_id, project_name, description,
                start_date, end_date, project_url, github_url, role, achievements,
                display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            project.get('project_name', ''),
            project.get('description', ''),
            project.get('start_date', None),
            project.get('end_date', None),
            project.get('project_url', ''),
            project.get('github_url', ''),
            project.get('role', ''),
            project.get('achievements', ''),
            project.get('display_order', 0)
        ))
        
        # Link skills to projects
        proj_id = cursor.lastrowid
        for skill_name in project.get('skills', []):
            skill_id = skill_name_to_id.get(skill_name.lower())
            if skill_id:
                conn.execute('INSERT INTO project_skills (project_id, skill_id) VALUES (?, ?)', (proj_id, skill_id))

    for cert in payload.get('certifications', []):
        conn.execute('''
            INSERT INTO certifications (
                consultant_id, certification_name, issuing_organization, issue_date,
                expiration_date, credential_id, credential_url, description,
                display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            cert.get('certification_name', ''),
            cert.get('issuing_organization', ''),
            cert.get('issue_date', None),
            cert.get('expiration_date', None),
            cert.get('credential_id', ''),
            cert.get('credential_url', ''),
            cert.get('description', ''),
            cert.get('display_order', 0)
        ))


@app.route('/consultants/import', methods=['GET', 'POST'])
@admin_required
def import_consultant():
    """Import consultant data from JSON file or textarea."""
    conn = get_db_connection()
    consultants = get_consultants(conn)
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
    return render_template('import_consultant.html', consultants=consultants, prefilled_json=prefilled_json)


@app.route('/consultants/parse-cv', methods=['GET', 'POST'])
@admin_required
def parse_cv():
    """Parse CV using AI and import consultant data."""
    if request.method == 'POST':
        cv_file = request.files.get('cv_file')
        consultant_name = request.form.get('consultant_name', '').strip()
        ai_provider = request.form.get('ai_provider', 'gemini')
        
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
    
    return render_template('parse_cv.html', has_groq=bool(GROQ_API_KEY))


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
    consultant = conn.execute(
        'SELECT id, display_name FROM consultants WHERE id = ?',
        (consultant_id,)
    ).fetchone()

    if not consultant:
        conn.close()
        flash(get_translation('messages.consultant_not_found'), 'error')
        return redirect(url_for('admin_dashboard'))

    payload = {
        'version': 1,
        'consultant': {
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

            row_data.pop('id', None)
            row_data.pop('consultant_id', None)
            row_data.pop('created_at', None)
            row_data.pop('updated_at', None)
            row_data.pop('category', None) # Remove old text category field if exists
            row_data.pop('years_of_experience', None) # Remove legacy field if it exists in DB
            payload[key].append(row_data)

    conn.close()

    # Sanitize display name for filename
    safe_name = "".join([c if c.isalnum() else "_" for c in consultant['display_name']])
    filename = f"{safe_name}.json"
    
    response = Response(
        json.dumps(payload, indent=2),
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
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
                    first_name = ?, last_name = ?, email = ?, phone = ?,
                    address = ?, city = ?, state = ?, zip_code = ?, country = ?,
                    linkedin_url = ?, github_url = ?, portfolio_url = ?,
                    professional_summary = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND consultant_id = ?
            ''', (data['first_name'], data['last_name'], data['email'], data['phone'],
                  data['address'], data['city'], data['state'], data['zip_code'], data['country'],
                  data['linkedin_url'], data['github_url'], data['portfolio_url'],
                  data['professional_summary'], existing['id'], consultant_id))
            flash(get_translation('messages.personal_info_updated'), 'success')
        else:
            # Insert new record
            conn.execute('''
                INSERT INTO personal_info (
                    consultant_id, first_name, last_name, email, phone, address, city, state,
                    zip_code, country, linkedin_url, github_url, portfolio_url, professional_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                consultant_id,
                data['first_name'], data['last_name'], data['email'], data['phone'],
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
        'SELECT * FROM work_experience WHERE consultant_id = ? ORDER BY display_order, start_date DESC',
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
                star_actions, star_results, display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            request.form.get('star_results', ''),
            request.form.get('display_order', 0)
        ))
        
        experience_id = cursor.lastrowid
        
        # Handle linked skills
        skill_ids = request.form.getlist('skill_ids')
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
def edit_work_experience(id):
    """Edit existing work experience."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    if request.method == 'POST':
        conn.execute('''
            UPDATE work_experience SET
                company_name = ?, position_title = ?, location = ?, start_date = ?,
                end_date = ?, is_current = ?, description = ?, achievements = ?,
                star_situation = ?, star_tasks = ?, star_actions = ?, star_results = ?,
                display_order = ?, updated_at = CURRENT_TIMESTAMP
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
            request.form.get('display_order', 0),
            id,
            consultant_id
        ))
        
        # Update linked skills
        conn.execute('DELETE FROM experience_skills WHERE experience_id = ?', (id,))
        skill_ids = request.form.getlist('skill_ids')
        for skill_id in skill_ids:
            conn.execute(
                'INSERT INTO experience_skills (experience_id, skill_id) VALUES (?, ?)',
                (id, skill_id)
            )
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.work_experience_updated'), 'success')
        return redirect(url_for('view_work_experience'))
    
    experience = conn.execute(
        'SELECT * FROM work_experience WHERE id = ? AND consultant_id = ?',
        (id, consultant_id)
    ).fetchone()
    
    if not experience:
        conn.close()
        flash(get_translation('messages.work_experience_not_found'), 'error')
        return redirect(url_for('view_work_experience'))
        
    all_skills = conn.execute('''
        SELECT s.id, s.skill_name, c.name as category_name
        FROM skills s
        LEFT JOIN skill_categories c ON s.category_id = c.id
        WHERE s.consultant_id = ?
        ORDER BY c.name, s.skill_name
    ''', (consultant_id,)).fetchall()
    
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
def delete_work_experience(id):
    """Delete work experience."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
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
        'SELECT * FROM education WHERE consultant_id = ? ORDER BY display_order, end_date DESC',
        (consultant_id,)
    ).fetchall()
    conn.close()
    return render_template('education.html', education=education)


@app.route('/education/add', methods=['GET', 'POST'])
def add_education():
    """Add new education entry."""
    if request.method == 'POST':
        conn = get_db_connection()
        consultant_id = resolve_current_consultant_id(conn)
        
        conn.execute('''
            INSERT INTO education (
                consultant_id, institution_name, degree, field_of_study, location, start_date,
                end_date, gpa, honors, description, display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            request.form.get('description', ''),
            request.form.get('display_order', 0)
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.education_added'), 'success')
        return redirect(url_for('view_education'))
    
    return render_template('edit_education.html', education=None)


@app.route('/education/edit/<int:id>', methods=['GET', 'POST'])
def edit_education(id):
    """Edit existing education entry."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    if request.method == 'POST':
        conn.execute('''
            UPDATE education SET
                institution_name = ?, degree = ?, field_of_study = ?, location = ?,
                start_date = ?, end_date = ?, gpa = ?, honors = ?, description = ?,
                display_order = ?, updated_at = CURRENT_TIMESTAMP
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
            request.form.get('display_order', 0),
            id,
            consultant_id
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.education_updated'), 'success')
        return redirect(url_for('view_education'))
    
    education = conn.execute(
        'SELECT * FROM education WHERE id = ? AND consultant_id = ?',
        (id, consultant_id)
    ).fetchone()
    conn.close()
    return render_template('edit_education.html', education=education)


@app.route('/education/delete/<int:id>', methods=['POST'])
def delete_education(id):
    """Delete education entry."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
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
        ORDER BY c.name, s.display_order, s.skill_name
    ''', (consultant_id,)).fetchall()
    conn.close()
    return render_template('skills.html', skills=skills)


@app.route('/skills/add', methods=['GET', 'POST'])
def add_skill():
    """Add new skill."""
    if request.method == 'POST':
        conn = get_db_connection()
        consultant_id = resolve_current_consultant_id(conn)
        
        conn.execute('''
            INSERT INTO skills (
                consultant_id, skill_name, category_id, proficiency_level, display_order
            ) VALUES (?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            request.form['skill_name'],
            request.form.get('category_id'),
            request.form.get('proficiency_level', ''),
            request.form.get('display_order', 0)
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.skill_added'), 'success')
        return redirect(url_for('view_skills'))
    
    categories = get_skill_categories()
    return render_template('edit_skill.html', skill=None, categories=categories)


@app.route('/skills/edit/<int:id>', methods=['GET', 'POST'])
def edit_skill(id):
    """Edit existing skill."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    if request.method == 'POST':
        conn.execute('''
            UPDATE skills SET
                skill_name = ?, category_id = ?, proficiency_level = ?,
                display_order = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND consultant_id = ?
        ''', (
            request.form['skill_name'],
            request.form.get('category_id'),
            request.form.get('proficiency_level', ''),
            request.form.get('display_order', 0),
            id,
            consultant_id
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.skill_updated'), 'success')
        return redirect(url_for('view_skills'))
    
    skill = conn.execute(
        'SELECT * FROM skills WHERE id = ? AND consultant_id = ?',
        (id, consultant_id)
    ).fetchone()
    categories = get_skill_categories()
    conn.close()
    return render_template('edit_skill.html', skill=skill, categories=categories)


@app.route('/skills/delete/<int:id>', methods=['POST'])
def delete_skill(id):
    """Delete skill."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
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
        'SELECT * FROM projects WHERE consultant_id = ? ORDER BY display_order, start_date DESC',
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
def add_project():
    """Add new project."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    if request.method == 'POST':
        cursor = conn.execute('''
            INSERT INTO projects (
                consultant_id, project_name, description, start_date, end_date,
                project_url, github_url, role, achievements, display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            request.form['project_name'],
            request.form.get('description', ''),
            request.form.get('start_date', None),
            request.form.get('end_date', None),
            request.form.get('project_url', ''),
            request.form.get('github_url', ''),
            request.form.get('role', ''),
            request.form.get('achievements', ''),
            request.form.get('display_order', 0)
        ))
        
        project_id = cursor.lastrowid
        
        # Handle linked skills
        skill_ids = request.form.getlist('skill_ids')
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
def edit_project(id):
    """Edit existing project."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    if request.method == 'POST':
        conn.execute('''
            UPDATE projects SET
                project_name = ?, description = ?, start_date = ?,
                end_date = ?, project_url = ?, github_url = ?, role = ?, achievements = ?,
                display_order = ?, updated_at = CURRENT_TIMESTAMP
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
            request.form.get('display_order', 0),
            id,
            consultant_id
        ))
        
        # Update linked skills
        conn.execute('DELETE FROM project_skills WHERE project_id = ?', (id,))
        skill_ids = request.form.getlist('skill_ids')
        for skill_id in skill_ids:
            conn.execute(
                'INSERT INTO project_skills (project_id, skill_id) VALUES (?, ?)',
                (id, skill_id)
            )
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.project_updated'), 'success')
        return redirect(url_for('view_projects'))
    
    project = conn.execute(
        'SELECT * FROM projects WHERE id = ? AND consultant_id = ?',
        (id, consultant_id)
    ).fetchone()
    
    if not project:
        conn.close()
        flash(get_translation('messages.project_not_found'), 'error')
        return redirect(url_for('view_projects'))
        
    all_skills = conn.execute('''
        SELECT s.id, s.skill_name, c.name as category_name
        FROM skills s
        LEFT JOIN skill_categories c ON s.category_id = c.id
        WHERE s.consultant_id = ?
        ORDER BY c.name, s.skill_name
    ''', (consultant_id,)).fetchall()
    
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
def delete_project(id):
    """Delete project."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
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
    certifications = conn.execute(
        'SELECT * FROM certifications WHERE consultant_id = ? ORDER BY display_order, issue_date DESC',
        (consultant_id,)
    ).fetchall()
    conn.close()
    return render_template('certifications.html', certifications=certifications)


@app.route('/certifications/add', methods=['GET', 'POST'])
def add_certification():
    """Add new certification."""
    if request.method == 'POST':
        conn = get_db_connection()
        consultant_id = resolve_current_consultant_id(conn)
        
        conn.execute('''
            INSERT INTO certifications (
                consultant_id, certification_name, issuing_organization, issue_date, expiration_date,
                credential_id, credential_url, description, display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            request.form['certification_name'],
            request.form['issuing_organization'],
            request.form.get('issue_date', None),
            request.form.get('expiration_date', None),
            request.form.get('credential_id', ''),
            request.form.get('credential_url', ''),
            request.form.get('description', ''),
            request.form.get('display_order', 0)
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.certification_added'), 'success')
        return redirect(url_for('view_certifications'))
    
    return render_template('edit_certification.html', certification=None)


@app.route('/certifications/edit/<int:id>', methods=['GET', 'POST'])
def edit_certification(id):
    """Edit existing certification."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    if request.method == 'POST':
        conn.execute('''
            UPDATE certifications SET
                certification_name = ?, issuing_organization = ?, issue_date = ?,
                expiration_date = ?, credential_id = ?, credential_url = ?, description = ?,
                display_order = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND consultant_id = ?
        ''', (
            request.form['certification_name'],
            request.form['issuing_organization'],
            request.form.get('issue_date', None),
            request.form.get('expiration_date', None),
            request.form.get('credential_id', ''),
            request.form.get('credential_url', ''),
            request.form.get('description', ''),
            request.form.get('display_order', 0),
            id,
            consultant_id
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.certification_updated'), 'success')
        return redirect(url_for('view_certifications'))
    
    certification = conn.execute(
        'SELECT * FROM certifications WHERE id = ? AND consultant_id = ?',
        (id, consultant_id)
    ).fetchone()
    conn.close()
    return render_template('edit_certification.html', certification=certification)


@app.route('/certifications/delete/<int:id>', methods=['POST'])
def delete_certification(id):
    """Delete certification."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
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


@app.route('/export-cv/preview')
@login_required
def preview_cv():
    """Preview CV in HTML format."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    # Get all CV data
    cv_data = get_cv_data(conn, consultant_id)
    conn.close()
    
    return render_template('cv_template.html', **cv_data)


@app.route('/export-cv/download', methods=['POST'])
@login_required
def export_cv_download():
    """Download CV in selected format."""
    format_type = request.form.get('format', 'html')
    
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    # Get all CV data
    cv_data = get_cv_data(conn, consultant_id)
    conn.close()
    
    # Get consultant name for filename
    if cv_data['personal_info']:
        filename = f"CV_{cv_data['personal_info']['first_name']}_{cv_data['personal_info']['last_name']}"
    else:
        filename = "CV_Export"
    
    if format_type == 'html':
        html_content = render_template('cv_template.html', **cv_data)
        return Response(
            html_content,
            mimetype='text/html',
            headers={'Content-Disposition': f'attachment;filename={filename}.html'}
        )
    
    elif format_type == 'pdf':
        try:
            import pdfkit
            html_content = render_template('cv_template.html', **cv_data)
            pdf = pdfkit.from_string(html_content, False)
            return Response(
                pdf,
                mimetype='application/pdf',
                headers={'Content-Disposition': f'attachment;filename={filename}.pdf'}
            )
        except Exception as e:
            flash(f'PDF generation failed: {str(e)}. Please install wkhtmltopdf or use HTML export.', 'error')
            return redirect(url_for('export_cv'))
    
    elif format_type == 'docx':
        try:
            from docx import Document
            from docx.shared import Pt, RGBColor, Inches
            from docx.enum.text import WD_ALIGN_PARAGRAPH
            
            doc = Document()
            
            def add_formatted_text(text, label=None):
                """Add text with markdown support to Word document."""
                if not text:
                    return
                
                list_items, paragraphs = extract_list_items(text)
                
                # Add label if provided
                if label:
                    p = doc.add_paragraph()
                    p.add_run(f"{label}: ").bold = True
                    if paragraphs and not list_items:
                        p.add_run(paragraphs[0])
                        paragraphs = paragraphs[1:]
                
                # Add remaining paragraphs
                for para in paragraphs:
                    doc.add_paragraph(para)
                
                # Add bullet list items
                for item in list_items:
                    doc.add_paragraph(item, style='List Bullet')
            
            # Add personal info header
            if cv_data['personal_info']:
                pi = cv_data['personal_info']
                heading = doc.add_heading(f"{pi['first_name']} {pi['last_name']}", 0)
                heading.alignment = WD_ALIGN_PARAGRAPH.CENTER
                
                contact_lines = []
                if pi['email']:
                    contact_lines.append(pi['email'])
                if pi['phone']:
                    contact_lines.append(pi['phone'])
                
                address_parts = []
                if pi['address']:
                    address_parts.append(pi['address'])
                if pi['city']:
                    address_parts.append(pi['city'])
                if pi['state']:
                    address_parts.append(pi['state'])
                if pi['zip_code']:
                    address_parts.append(pi['zip_code'])
                if pi['country']:
                    address_parts.append(pi['country'])
                
                if address_parts:
                    contact_lines.append(', '.join(address_parts))
                
                for line in contact_lines:
                    p = doc.add_paragraph(line)
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                
                # Links
                links = []
                if pi['linkedin_url']:
                    links.append(f"LinkedIn: {pi['linkedin_url']}")
                if pi['github_url']:
                    links.append(f"GitHub: {pi['github_url']}")
                if pi['portfolio_url']:
                    links.append(f"Portfolio: {pi['portfolio_url']}")
                
                if links:
                    p = doc.add_paragraph(' | '.join(links))
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                
                doc.add_paragraph()  # Space
                
                # Professional summary
                if pi['professional_summary']:
                    doc.add_heading(get_translation('personal_info.professional_summary'), 1)
                    doc.add_paragraph(pi['professional_summary'])
            
            # Work Experience
            if cv_data['work_experiences']:
                doc.add_heading(get_translation('work_experience.title'), 1)
                for exp in cv_data['work_experiences']:
                    doc.add_heading(exp['position_title'], 2)
                    company_para = doc.add_paragraph()
                    company_para.add_run(exp['company_name']).bold = True
                    
                    date_str = f"{exp['start_date']} - "
                    if exp['is_current']:
                        date_str += get_translation('work_experience.present')
                    else:
                        date_str += exp['end_date'] or get_translation('common.na')
                    
                    if exp['location']:
                        date_str = f"{exp['location']} | {date_str}"
                    
                    doc.add_paragraph(date_str)
                    
                    if exp['description']:
                        add_formatted_text(exp['description'])
                    
                    if exp['achievements']:
                        add_formatted_text(exp['achievements'], get_translation('work_experience.achievements'))
                    
                    if exp['star_situation'] or exp['star_tasks'] or exp['star_actions'] or exp['star_results']:
                        if exp['star_situation']:
                            add_formatted_text(exp['star_situation'], get_translation('work_experience.star_situation'))
                        if exp['star_tasks']:
                            add_formatted_text(exp['star_tasks'], get_translation('work_experience.star_tasks'))
                        if exp['star_actions']:
                            add_formatted_text(exp['star_actions'], get_translation('work_experience.star_actions'))
                        if exp['star_results']:
                            add_formatted_text(exp['star_results'], get_translation('work_experience.star_results'))
            
            # Education
            if cv_data['education']:
                doc.add_heading(get_translation('education.title'), 1)
                for edu in cv_data['education']:
                    degree_str = edu['degree']
                    if edu['field_of_study']:
                        degree_str += f" - {edu['field_of_study']}"
                    doc.add_heading(degree_str, 2)
                    
                    inst_para = doc.add_paragraph()
                    inst_para.add_run(edu['institution_name']).bold = True
                    
                    date_str = ""
                    if edu['start_date']:
                        date_str = f"{edu['start_date']} - "
                    date_str += edu['end_date'] or get_translation('education.in_progress')
                    
                    if edu['location']:
                        date_str = f"{edu['location']} | {date_str}"
                    
                    doc.add_paragraph(date_str)
                    
                    if edu['gpa']:
                        p = doc.add_paragraph()
                        p.add_run(f"{get_translation('education.gpa')}: ").bold = True
                        p.add_run(edu['gpa'])
                    
                    if edu['honors']:
                        p = doc.add_paragraph()
                        p.add_run(f"{get_translation('education.honors')}: ").bold = True
                        p.add_run(edu['honors'])
                    
                    if edu['description']:
                        add_formatted_text(edu['description'])
            
            # Certifications
            if cv_data['certifications']:
                doc.add_heading(get_translation('certifications.title'), 1)
                for cert in cv_data['certifications']:
                    doc.add_heading(cert['certification_name'], 2)
                    
                    org_para = doc.add_paragraph()
                    org_para.add_run(cert['issuing_organization']).bold = True
                    
                    date_str = f"{get_translation('certifications.issued')}: {cert['issue_date']}"
                    if cert['expiration_date']:
                        date_str += f" | {get_translation('certifications.expires')}: {cert['expiration_date']}"
                    
                    doc.add_paragraph(date_str)
                    
                    if cert['credential_id']:
                        p = doc.add_paragraph()
                        p.add_run(f"{get_translation('certifications.credential_id')}: ").bold = True
                        p.add_run(cert['credential_id'])
                    
                    if cert['credential_url']:
                        doc.add_paragraph(cert['credential_url'])
                    
                    if cert['description']:
                        add_formatted_text(cert['description'])
            
            # Skills
            if cv_data['skills_by_category']:
                doc.add_heading(get_translation('skills.title'), 1)
                for category_name, skills in cv_data['skills_by_category'].items():
                    p = doc.add_paragraph()
                    p.add_run(f"{category_name}: ").bold = True
                    skill_names = []
                    for skill in skills:
                        skill_str = skill['skill_name']
                        if skill['proficiency_level']:
                            skill_str += f" ({skill['proficiency_level']})"
                        skill_names.append(skill_str)
                    p.add_run(', '.join(skill_names))
            
            # Projects
            if cv_data['projects']:
                doc.add_heading(get_translation('projects.title'), 1)
                for project in cv_data['projects']:
                    doc.add_heading(project['project_name'], 2)
                    
                    if project['role']:
                        role_para = doc.add_paragraph()
                        role_para.add_run(project['role']).bold = True
                    
                    date_str = ""
                    if project['start_date']:
                        date_str = f"{project['start_date']} - "
                    date_str += project['end_date'] or get_translation('projects.ongoing')
                    doc.add_paragraph(date_str)
                    
                    if project['description']:
                        add_formatted_text(project['description'])
                    
                    if project['achievements']:
                        add_formatted_text(project['achievements'], get_translation('projects.achievements'))
                    
                    if project['project_url'] or project['github_url']:
                        links = []
                        if project['project_url']:
                            links.append(f"{get_translation('projects.project_url_link')}: {project['project_url']}")
                        if project['github_url']:
                            links.append(f"{get_translation('projects.github_repo')}: {project['github_url']}")
                        doc.add_paragraph(' | '.join(links))
            
            # Save to BytesIO
            from io import BytesIO
            doc_io = BytesIO()
            doc.save(doc_io)
            doc_io.seek(0)
            
            return Response(
                doc_io.getvalue(),
                mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                headers={'Content-Disposition': f'attachment;filename={filename}.docx'}
            )
            
        except Exception as e:
            flash(f'Word document generation failed: {str(e)}', 'error')
            return redirect(url_for('export_cv'))
    
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

                row_data.pop('id', None)
                row_data.pop('consultant_id', None)
                row_data.pop('created_at', None)
                row_data.pop('updated_at', None)
                row_data.pop('category', None)  # Remove old text category field if exists
                row_data.pop('years_of_experience', None)  # Remove legacy field if it exists
                payload[key].append(row_data)

        conn.close()
        
        return Response(
            json.dumps(payload, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment;filename={filename}.json'}
        )
    
    flash('Invalid format selected', 'error')
    return redirect(url_for('export_cv'))


def get_cv_data(conn, consultant_id):
    """Helper function to retrieve all CV data for a consultant."""
    
    # Personal Info
    personal_info = conn.execute(
        'SELECT * FROM personal_info WHERE consultant_id = ?',
        (consultant_id,)
    ).fetchone()
    
    # Work Experience
    work_experiences = conn.execute(
        'SELECT * FROM work_experience WHERE consultant_id = ? ORDER BY display_order, start_date DESC',
        (consultant_id,)
    ).fetchall()
    
    # Education
    education = conn.execute(
        'SELECT * FROM education WHERE consultant_id = ? ORDER BY display_order, start_date DESC',
        (consultant_id,)
    ).fetchall()
    
    # Certifications
    certifications = conn.execute(
        'SELECT * FROM certifications WHERE consultant_id = ? ORDER BY display_order, issue_date DESC',
        (consultant_id,)
    ).fetchall()
    
    # Skills grouped by category
    skills = conn.execute('''
        SELECT s.*, c.name as category_name
        FROM skills s
        LEFT JOIN skill_categories c ON s.category_id = c.id
        WHERE s.consultant_id = ?
        ORDER BY c.name, s.display_order, s.skill_name
    ''', (consultant_id,)).fetchall()
    
    skills_by_category = {}
    for skill in skills:
        category = skill['category_name'] or get_translation('skills.uncategorized')
        if category not in skills_by_category:
            skills_by_category[category] = []
        skills_by_category[category].append(skill)
    
    # Projects
    projects = conn.execute(
        'SELECT * FROM projects WHERE consultant_id = ? ORDER BY display_order, start_date DESC',
        (consultant_id,)
    ).fetchall()
    
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

