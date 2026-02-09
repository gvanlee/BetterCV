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
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
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
            proficiency_level TEXT,
            years_of_experience INTEGER,
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Projects Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            consultant_id INTEGER,
            project_name TEXT NOT NULL,
            description TEXT,
            technologies_used TEXT,
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
        # Add a placeholder admin email to whitelist - CHANGE THIS!
        conn.execute('''
            INSERT INTO user_whitelist (email, role, notes)
            VALUES ('admin@example.com', 'admin', 'Default admin - CHANGE THIS EMAIL in user_whitelist table')
        ''')

    conn.commit()
    conn.close()
    print("Database initialized successfully!")


if __name__ == "__main__":
    init_database()
