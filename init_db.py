"""
Database initialization script for BetterCV
Run this script to create the database and tables.
"""

from database import init_database

if __name__ == "__main__":
    print("Initializing BetterCV database...")
    init_database()
    print("Database setup complete!")
