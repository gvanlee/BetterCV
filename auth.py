"""
Authentication module for BetterCV
Handles OAuth, user management, and access control
"""

from flask_login import UserMixin
from database import get_db_connection
from datetime import datetime
import os
import sqlite3


class User(UserMixin):
    """User model for Flask-Login"""
    
    def __init__(self, id, email, name, role, consultant_id, oauth_provider):
        self.id = id
        self.email = email
        self.name = name
        self.role = role
        self.consultant_id = consultant_id
        self.oauth_provider = oauth_provider
    
    def is_admin(self):
        """Check if user has admin role"""
        return self.role == 'admin'
    
    def is_consultant(self):
        """Check if user has consultant role"""
        return self.role == 'consultant'
    
    def can_edit_consultant(self, consultant_id):
        """Check if user can edit a specific consultant's data"""
        if self.is_admin():
            return True
        return self.consultant_id == consultant_id
    
    @staticmethod
    def get_by_id(user_id):
        """Get user by ID"""
        conn = get_db_connection()
        user_data = conn.execute(
            'SELECT * FROM users WHERE id = ? AND is_active = 1',
            (user_id,)
        ).fetchone()
        conn.close()
        
        if user_data:
            return User(
                id=user_data['id'],
                email=user_data['email'],
                name=user_data['name'],
                role=user_data['role'],
                consultant_id=user_data['consultant_id'],
                oauth_provider=user_data['oauth_provider']
            )
        return None
    
    @staticmethod
    def get_by_email(email):
        """Get user by email"""
        conn = get_db_connection()
        user_data = conn.execute(
            'SELECT * FROM users WHERE email = ? AND is_active = 1',
            (email,)
        ).fetchone()
        conn.close()
        
        if user_data:
            return User(
                id=user_data['id'],
                email=user_data['email'],
                name=user_data['name'],
                role=user_data['role'],
                consultant_id=user_data['consultant_id'],
                oauth_provider=user_data['oauth_provider']
            )
        return None
    
    @staticmethod
    def _get_auto_whitelist_domains():
        raw_domains = os.getenv('AUTO_WHITELIST_DOMAINS', '')
        if not raw_domains:
            return set()

        domains = set()
        for item in raw_domains.split(','):
            domain = item.strip().lower()
            if domain:
                domains.add(domain)
        return domains

    @staticmethod
    def _get_email_domain(email):
        if not email or '@' not in email:
            return None
        return email.split('@', 1)[1].strip().lower()

    @staticmethod
    def is_whitelisted(email):
        """Check if email is in whitelist"""
        conn = get_db_connection()
        result = conn.execute(
            'SELECT role FROM user_whitelist WHERE email = ?',
            (email,)
        ).fetchone()
        conn.close()
        return result
    
    @staticmethod
    def create_user(email, name, oauth_provider, oauth_id):
        """Create a new user from OAuth login"""
        # Check whitelist for role
        whitelist_entry = User.is_whitelisted(email)
        if not whitelist_entry:
            domain = User._get_email_domain(email)
            auto_domains = User._get_auto_whitelist_domains()
            if domain and domain in auto_domains:
                add_to_whitelist(email, 'consultant', notes='Auto-whitelisted by domain')
                whitelist_entry = User.is_whitelisted(email)

        if not whitelist_entry:
            return None
        
        role = whitelist_entry['role']
        
        conn = get_db_connection()
        
        # If consultant role, create a consultant record
        consultant_id = None
        if role == 'consultant':
            # Create consultant with user's name
            cursor = conn.execute(
                'INSERT INTO consultants (display_name) VALUES (?)',
                (name or email.split('@')[0],)
            )
            consultant_id = cursor.lastrowid
            
            # Create personal_info entry for the consultant
            conn.execute('''
                INSERT INTO personal_info (consultant_id, first_name, last_name, email)
                VALUES (?, ?, ?, ?)
            ''', (consultant_id, name.split()[0] if name and ' ' in name else name or '',
                  name.split()[-1] if name and ' ' in name else '', email))
        
        # Create user
        cursor = conn.execute('''
            INSERT INTO users (email, name, oauth_provider, oauth_id, role, consultant_id, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (email, name, oauth_provider, oauth_id, role, consultant_id, datetime.now()))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return User.get_by_id(user_id)
    
    @staticmethod
    def update_last_login(user_id):
        """Update user's last login timestamp"""
        conn = get_db_connection()
        conn.execute(
            'UPDATE users SET last_login = ? WHERE id = ?',
            (datetime.now(), user_id)
        )
        conn.commit()
        conn.close()


def get_all_users():
    """Get all users for admin dashboard"""
    conn = get_db_connection()
    users = conn.execute('''
        SELECT u.*, c.display_name as consultant_name
        FROM users u
        LEFT JOIN consultants c ON u.consultant_id = c.id
        ORDER BY u.created_at DESC
    ''').fetchall()
    conn.close()
    return users


def get_all_whitelist():
    """Get all whitelist entries"""
    conn = get_db_connection()
    whitelist = conn.execute('''
        SELECT w.*, u.email as invited_by_email
        FROM user_whitelist w
        LEFT JOIN users u ON w.invited_by = u.id
        ORDER BY w.created_at DESC
    ''').fetchall()
    conn.close()
    return whitelist


def add_to_whitelist(email, role, invited_by=None, notes=None):
    """Add an email to the whitelist"""
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO user_whitelist (email, role, invited_by, notes)
            VALUES (?, ?, ?, ?)
        ''', (email.lower().strip(), role, invited_by, notes))
        conn.commit()
        conn.close()
        return True, "Email added to whitelist successfully"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Email already exists in whitelist"
    except Exception as e:
        conn.close()
        return False, str(e)


def remove_from_whitelist(whitelist_id):
    """Remove an entry from whitelist"""
    conn = get_db_connection()
    conn.execute('DELETE FROM user_whitelist WHERE id = ?', (whitelist_id,))
    conn.commit()
    conn.close()


def update_user_role(user_id, new_role):
    """Update a user's role"""
    conn = get_db_connection()
    conn.execute(
        'UPDATE users SET role = ?, updated_at = ? WHERE id = ?',
        (new_role, datetime.now(), user_id)
    )
    conn.commit()
    conn.close()


def deactivate_user(user_id):
    """Deactivate a user account"""
    conn = get_db_connection()
    conn.execute(
        'UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?',
        (datetime.now(), user_id)
    )
    conn.commit()
    conn.close()


def get_all_consultants():
    """Get all consultants for admin dropdown"""
    conn = get_db_connection()
    consultants = conn.execute('''
        SELECT c.id, c.display_name, p.email
        FROM consultants c
        LEFT JOIN personal_info p ON c.id = p.consultant_id
        ORDER BY c.display_name
    ''').fetchall()
    conn.close()
    return consultants
