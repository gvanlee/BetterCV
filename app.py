from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from database import get_db_connection
from datetime import datetime
from database import init_database
import json
import os

app = Flask(__name__)
app.secret_key = 'h9sdf696f34rhfvvhkxjvodfyg8yer89g7ye-8yhoiuver8v8erf98yyh34f'

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
        'consultants': consultants,
        'current_consultant': current_consultant,
        'available_languages': {
            'en': 'English',
            'nl': 'Nederlands'
        }
    }

@app.route('/set-language/<lang>')
def set_language(lang):
    """Set the user's language preference."""
    if lang in TRANSLATIONS:
        session['language'] = lang
    return redirect(request.referrer or url_for('index'))


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
        'export_consultant'
    }:
        return None

    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    conn.close()

    if consultant_id is None:
        return redirect(url_for('list_consultants'))

    return None


@app.route('/')
def index():
    """Home page with navigation to all sections."""
    return render_template('index.html')


# ==================== Consultant Routes ====================

@app.route('/consultants')
def list_consultants():
    """List consultants and allow creation/import/export."""
    conn = get_db_connection()
    consultants = get_consultants(conn)
    conn.close()
    return render_template('consultants.html', consultants=consultants)


@app.route('/consultants/add', methods=['POST'])
def add_consultant():
    """Add a new consultant."""
    display_name = request.form.get('display_name', '').strip()
    if not display_name:
        flash(get_translation('messages.consultant_name_required'), 'error')
        return redirect(url_for('list_consultants'))

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
    return redirect(url_for('view_personal_info'))


@app.route('/consultants/switch/<int:consultant_id>')
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
        return redirect(url_for('list_consultants'))

    session['consultant_id'] = consultant_id
    return redirect(request.referrer or url_for('index'))


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
            personal_info.get('professional_summary', '')
        ))

    for exp in payload.get('work_experience', []):
        conn.execute('''
            INSERT INTO work_experience (
                consultant_id, company_name, position_title, location, start_date,
                end_date, is_current, description, achievements, display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            exp.get('company_name', ''),
            exp.get('position_title', ''),
            exp.get('location', ''),
            exp.get('start_date', ''),
            exp.get('end_date', None),
            1 if exp.get('is_current') else 0,
            exp.get('description', ''),
            exp.get('achievements', ''),
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
            edu.get('institution_name', ''),
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

    for skill in payload.get('skills', []):
        conn.execute('''
            INSERT INTO skills (
                consultant_id, skill_name, category, proficiency_level,
                years_of_experience, display_order
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            skill.get('skill_name', ''),
            skill.get('category', ''),
            skill.get('proficiency_level', ''),
            skill.get('years_of_experience', None),
            skill.get('display_order', 0)
        ))

    for project in payload.get('projects', []):
        conn.execute('''
            INSERT INTO projects (
                consultant_id, project_name, description, technologies_used,
                start_date, end_date, project_url, github_url, role, achievements,
                display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            project.get('project_name', ''),
            project.get('description', ''),
            project.get('technologies_used', ''),
            project.get('start_date', None),
            project.get('end_date', None),
            project.get('project_url', ''),
            project.get('github_url', ''),
            project.get('role', ''),
            project.get('achievements', ''),
            project.get('display_order', 0)
        ))

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
def import_consultant():
    """Import consultant data from JSON."""
    conn = get_db_connection()
    consultants = get_consultants(conn)

    if request.method == 'POST':
        json_file = request.files.get('json_file')
        import_mode = request.form.get('import_mode')
        if not json_file:
            conn.close()
            flash(get_translation('messages.import_file_required'), 'error')
            return redirect(url_for('import_consultant'))

        try:
            payload = json.load(json_file)
        except json.JSONDecodeError:
            conn.close()
            flash(get_translation('messages.import_invalid_json'), 'error')
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
        flash(get_translation('messages.import_success'), 'success')
        return redirect(url_for('view_personal_info'))

    conn.close()
    return render_template('import_consultant.html', consultants=consultants)


@app.route('/consultants/delete/<int:consultant_id>', methods=['POST'])
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
        return redirect(url_for('list_consultants'))
    
    # Prevent deleting if this is the only consultant
    consultant_count = conn.execute('SELECT COUNT(*) FROM consultants').fetchone()[0]
    if consultant_count <= 1:
        conn.close()
        flash(get_translation('messages.consultant_delete_last'), 'error')
        return redirect(url_for('list_consultants'))
    
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
    return redirect(url_for('list_consultants'))


@app.route('/consultants/export/<int:consultant_id>')
def export_consultant(consultant_id):
    """Export a consultant's data as JSON."""
    conn = get_db_connection()
    consultant = conn.execute(
        'SELECT id, display_name FROM consultants WHERE id = ?',
        (consultant_id,)
    ).fetchone()

    if not consultant:
        conn.close()
        flash(get_translation('messages.consultant_not_found'), 'error')
        return redirect(url_for('list_consultants'))

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
            row_data.pop('id', None)
            row_data.pop('consultant_id', None)
            row_data.pop('created_at', None)
            row_data.pop('updated_at', None)
            payload[key].append(row_data)

    conn.close()

    filename = f"consultant_{consultant_id}_export.json"
    response = Response(
        json.dumps(payload, indent=2),
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response


# ==================== Personal Info Routes ====================

@app.route('/personal-info')
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
def view_work_experience():
    """View all work experience entries."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    experiences = conn.execute(
        'SELECT * FROM work_experience WHERE consultant_id = ? ORDER BY display_order, start_date DESC',
        (consultant_id,)
    ).fetchall()
    conn.close()
    return render_template('work_experience.html', experiences=experiences)


@app.route('/work-experience/add', methods=['GET', 'POST'])
def add_work_experience():
    """Add new work experience."""
    if request.method == 'POST':
        conn = get_db_connection()
        consultant_id = resolve_current_consultant_id(conn)
        
        conn.execute('''
            INSERT INTO work_experience (
                consultant_id, company_name, position_title, location, start_date, end_date,
                is_current, description, achievements, display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            request.form.get('display_order', 0)
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.work_experience_added'), 'success')
        return redirect(url_for('view_work_experience'))
    
    return render_template('edit_work_experience.html', experience=None)


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
            request.form.get('display_order', 0),
            id,
            consultant_id
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.work_experience_updated'), 'success')
        return redirect(url_for('view_work_experience'))
    
    experience = conn.execute(
        'SELECT * FROM work_experience WHERE id = ? AND consultant_id = ?',
        (id, consultant_id)
    ).fetchone()
    conn.close()
    return render_template('edit_work_experience.html', experience=experience)


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
def view_skills():
    """View all skills."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    skills = conn.execute(
        'SELECT * FROM skills WHERE consultant_id = ? ORDER BY category, display_order, skill_name',
        (consultant_id,)
    ).fetchall()
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
                consultant_id, skill_name, category, proficiency_level, years_of_experience, display_order
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            request.form['skill_name'],
            request.form.get('category', ''),
            request.form.get('proficiency_level', ''),
            request.form.get('years_of_experience', None),
            request.form.get('display_order', 0)
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.skill_added'), 'success')
        return redirect(url_for('view_skills'))
    
    return render_template('edit_skill.html', skill=None)


@app.route('/skills/edit/<int:id>', methods=['GET', 'POST'])
def edit_skill(id):
    """Edit existing skill."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    if request.method == 'POST':
        conn.execute('''
            UPDATE skills SET
                skill_name = ?, category = ?, proficiency_level = ?,
                years_of_experience = ?, display_order = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND consultant_id = ?
        ''', (
            request.form['skill_name'],
            request.form.get('category', ''),
            request.form.get('proficiency_level', ''),
            request.form.get('years_of_experience', None),
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
    conn.close()
    return render_template('edit_skill.html', skill=skill)


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
def view_projects():
    """View all projects."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    projects = conn.execute(
        'SELECT * FROM projects WHERE consultant_id = ? ORDER BY display_order, start_date DESC',
        (consultant_id,)
    ).fetchall()
    conn.close()
    return render_template('projects.html', projects=projects)


@app.route('/projects/add', methods=['GET', 'POST'])
def add_project():
    """Add new project."""
    if request.method == 'POST':
        conn = get_db_connection()
        consultant_id = resolve_current_consultant_id(conn)
        
        conn.execute('''
            INSERT INTO projects (
                consultant_id, project_name, description, technologies_used, start_date, end_date,
                project_url, github_url, role, achievements, display_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            consultant_id,
            request.form['project_name'],
            request.form.get('description', ''),
            request.form.get('technologies_used', ''),
            request.form.get('start_date', None),
            request.form.get('end_date', None),
            request.form.get('project_url', ''),
            request.form.get('github_url', ''),
            request.form.get('role', ''),
            request.form.get('achievements', ''),
            request.form.get('display_order', 0)
        ))
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.project_added'), 'success')
        return redirect(url_for('view_projects'))
    
    return render_template('edit_project.html', project=None)


@app.route('/projects/edit/<int:id>', methods=['GET', 'POST'])
def edit_project(id):
    """Edit existing project."""
    conn = get_db_connection()
    consultant_id = resolve_current_consultant_id(conn)
    
    if request.method == 'POST':
        conn.execute('''
            UPDATE projects SET
                project_name = ?, description = ?, technologies_used = ?, start_date = ?,
                end_date = ?, project_url = ?, github_url = ?, role = ?, achievements = ?,
                display_order = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND consultant_id = ?
        ''', (
            request.form['project_name'],
            request.form.get('description', ''),
            request.form.get('technologies_used', ''),
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
        
        conn.commit()
        conn.close()
        flash(get_translation('messages.project_updated'), 'success')
        return redirect(url_for('view_projects'))
    
    project = conn.execute(
        'SELECT * FROM projects WHERE id = ? AND consultant_id = ?',
        (id, consultant_id)
    ).fetchone()
    conn.close()
    return render_template('edit_project.html', project=project)


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


if __name__ == '__main__':
    init_database()
    app.run(debug=True, host='0.0.0.0', port=5000)
