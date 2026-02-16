import sqlite3
import os
from datetime import datetime

# Use data directory for database if it exists, otherwise use current directory
DATABASE_DIR = os.path.join(os.path.dirname(__file__), 'data')
if os.path.exists(DATABASE_DIR):
    DATABASE_NAME = os.path.join(DATABASE_DIR, 'resume.db')
else:
    DATABASE_NAME = 'resume.db'


def get_db_connection():
    """Create and return a database connection."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_database():
    """Initialize the database with all required tables."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Consultants Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS consultants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Users Table (for authentication)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            oauth_provider TEXT,
            oauth_id TEXT,
            role TEXT NOT NULL DEFAULT 'consultant',
            consultant_id INTEGER,
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (consultant_id) REFERENCES consultants(id)
        )
    ''')
    
    # User Whitelist Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL DEFAULT 'consultant',
            invited_by INTEGER,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (invited_by) REFERENCES users(id)
        )
    ''')

    # Personal Information Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS personal_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            consultant_id INTEGER,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            city TEXT,
            state TEXT,
            zip_code TEXT,
            country TEXT,
            linkedin_url TEXT,
            github_url TEXT,
            portfolio_url TEXT,
            professional_summary TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Work Experience Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS work_experience (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            consultant_id INTEGER,
            company_name TEXT NOT NULL,
            position_title TEXT NOT NULL,
            location TEXT,
            start_date DATE NOT NULL,
            end_date DATE,
            is_current BOOLEAN DEFAULT 0,
            description TEXT,
            achievements TEXT,
            star_situation TEXT,
            star_tasks TEXT,
            star_actions TEXT,
            star_results TEXT,
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Migration: Add STAR columns and description/achievements to work_experience if they don't exist
    # This is for existing databases created before these fields were added
    cursor.execute("PRAGMA table_info(work_experience)")
    columns = [column[1] for column in cursor.fetchall()]
    
    potential_columns = [
        ('description', 'TEXT'),
        ('achievements', 'TEXT'),
        ('star_situation', 'TEXT'),
        ('star_tasks', 'TEXT'),
        ('star_actions', 'TEXT'),
        ('star_results', 'TEXT'),
        ('display_order', 'INTEGER DEFAULT 0')
    ]
    
    for col_name, col_type in potential_columns:
        if col_name not in columns:
            cursor.execute(f"ALTER TABLE work_experience ADD COLUMN {col_name} {col_type}")
    
    # Education Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS education (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            consultant_id INTEGER,
            institution_name TEXT NOT NULL,
            degree TEXT NOT NULL,
            field_of_study TEXT,
            location TEXT,
            start_date DATE,
            end_date DATE,
            gpa TEXT,
            honors TEXT,
            description TEXT,
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Skills Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS skills (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            consultant_id INTEGER,
            skill_name TEXT NOT NULL,
            category TEXT,
            category_id INTEGER,
            proficiency_level TEXT,
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (category_id) REFERENCES skill_categories(id)
        )
    ''')

    # Skill Categories Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS skill_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Seed default categories
    default_categories = [
        'Data Analytics',
        'Data Engineering',
        'Data Management',
        'Data Modeling',
        'Databases',
        'Database Administration',
        'Languages',
        'Operating Systems',
        'Programming Languages',
        'Tools',
        'Various'
    ]
    
    for cat_name in default_categories:
        cursor.execute('''
            INSERT OR IGNORE INTO skill_categories (name)
            VALUES (?)
        ''', (cat_name,))

    # Migration: Add category_id to skills if it doesn't exist
    cursor.execute("PRAGMA table_info(skills)")
    skills_columns = [column[1] for column in cursor.fetchall()]
    if 'category_id' not in skills_columns:
        cursor.execute("ALTER TABLE skills ADD COLUMN category_id INTEGER REFERENCES skill_categories(id)")

    # Migration: Map text categories to category_id
    cursor.execute("SELECT id, name FROM skill_categories")
    categories = cursor.fetchall()
    cat_map = {c['name'].lower(): c['id'] for c in categories}
    
    cursor.execute("SELECT id, category FROM skills WHERE category_id IS NULL AND category IS NOT NULL")
    skills_to_update = cursor.fetchall()
    for skill in skills_to_update:
        if skill['category'] and skill['category'].lower() in cat_map:
            cursor.execute(
                "UPDATE skills SET category_id = ? WHERE id = ?",
                (cat_map[skill['category'].lower()], skill['id'])
            )

    # Experience-Skills Link Table (Many-to-Many)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS experience_skills (
            experience_id INTEGER,
            skill_id INTEGER,
            PRIMARY KEY (experience_id, skill_id),
            FOREIGN KEY (experience_id) REFERENCES work_experience(id) ON DELETE CASCADE,
            FOREIGN KEY (skill_id) REFERENCES skills(id) ON DELETE CASCADE
        )
    ''')

    # Project-Skills Link Table (Many-to-Many)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS project_skills (
            project_id INTEGER,
            skill_id INTEGER,
            PRIMARY KEY (project_id, skill_id),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY (skill_id) REFERENCES skills(id) ON DELETE CASCADE
        )
    ''')
    
    # Projects Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            consultant_id INTEGER,
            project_name TEXT NOT NULL,
            description TEXT,
            start_date DATE,
            end_date DATE,
            project_url TEXT,
            github_url TEXT,
            role TEXT,
            achievements TEXT,
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Certifications Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            consultant_id INTEGER,
            certification_name TEXT NOT NULL,
            issuing_organization TEXT NOT NULL,
            issue_date DATE,
            expiration_date DATE,
            credential_id TEXT,
            credential_url TEXT,
            description TEXT,
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    def ensure_column(table_name, column_name, column_definition):
        columns = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        column_names = {column['name'] for column in columns}
        if column_name not in column_names:
            conn.execute(
                f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
            )

    # Backfill consultant_id columns for existing databases
    for table in [
        'personal_info',
        'work_experience',
        'education',
        'skills',
        'projects',
        'certifications'
    ]:
        ensure_column(table, 'consultant_id', 'INTEGER')

    existing_consultant = conn.execute(
        'SELECT id FROM consultants ORDER BY id LIMIT 1'
    ).fetchone()
    if existing_consultant:
        default_consultant_id = existing_consultant['id']
    else:
        result = conn.execute(
            'INSERT INTO consultants (display_name) VALUES (?)',
            ('Default Consultant',)
        )
        default_consultant_id = result.lastrowid

    for table in [
        'personal_info',
        'work_experience',
        'education',
        'skills',
        'projects',
        'certifications'
    ]:
        conn.execute(
            f"UPDATE {table} SET consultant_id = ? WHERE consultant_id IS NULL",
            (default_consultant_id,)
        )

    # Create default admin in whitelist if no users exist
    whitelist_count = conn.execute('SELECT COUNT(*) FROM user_whitelist').fetchone()[0]
    if whitelist_count == 0:
        # Add a placeholder admin email to whitelist
        default_admin_email = os.getenv('DEFAULT_ADMIN', 'admin@example.com')

        conn.execute('''
                INSERT INTO user_whitelist (email, role, notes)
                VALUES (?, 'admin', 'Default admin - CHANGE THIS EMAIL in user_whitelist table')
            ''', (default_admin_email,))

    conn.commit()
    conn.close()
    print("Database initialized successfully!")


def get_skill_categories():
    """Get all skill categories with usage statistics."""
    conn = get_db_connection()
    categories = conn.execute('''
        SELECT sc.*,
               (SELECT COUNT(*) FROM skills WHERE category_id = sc.id) as skill_count,
               (SELECT COUNT(*) 
                FROM experience_skills es 
                JOIN skills s ON es.skill_id = s.id 
                WHERE s.category_id = sc.id) as experience_count
        FROM skill_categories sc
        ORDER BY sc.name
    ''').fetchall()
    conn.close()
    return categories


if __name__ == "__main__":
    init_database()
