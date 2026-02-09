"""
Access control decorators for route protection
"""

from functools import wraps
from flask import redirect, url_for, flash, abort
from flask_login import current_user


def login_required(f):
    """Require user to be logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Require user to have admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if not current_user.is_admin():
            flash('You do not have permission to access this page.', 'error')
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def consultant_or_admin_required(f):
    """Require user to be consultant or admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        # Check if accessing own consultant data or is admin
        consultant_id = kwargs.get('consultant_id')
        if consultant_id and not current_user.can_edit_consultant(consultant_id):
            flash('You do not have permission to access this data.', 'error')
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function


def check_consultant_access(consultant_id):
    """Check if current user can access consultant data"""
    if not current_user.is_authenticated:
        return False
    return current_user.can_edit_consultant(consultant_id)
