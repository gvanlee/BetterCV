# BetterCV - Resume Management System

A Python application for managing and maintaining resume data using SQLite database.

## Features
- Store all resume data in a structured database
- Web-based forms for easy data entry and editing
- Manage personal info, work experience, education, skills, projects, and certifications
- **Multi-language support** (English and Dutch) with easy language switching
- Docker support for easy deployment

## Setup Options

### Option 1: Docker (Recommended)

1. Build and run with Docker Compose:
   ```bash
   docker-compose up -d
   ```

2. Open your browser to: http://localhost:5000

3. To stop the application:
   ```bash
   docker-compose down
   ```

The database will be persisted in the `./data` directory.

### Option 2: Manual Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Initialize the database:
   ```bash
   python init_db.py
   ```

3. Run the application:
   ```bash
   python app.py
   ```

4. Open your browser to: http://localhost:5000

## Docker Commands

**Build the image:**
```bash
docker build -t bettercv .
```

**Run the container:**
```bash
docker run -d -p 5000:5000 -v $(pwd)/data:/app/data --name bettercv bettercv
```

**View logs:**
```bash
docker logs bettercv
```

**Stop the container:**
```bash
docker stop bettercv
```

**Remove the container:**
```bash
docker rm bettercv
```
