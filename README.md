# BetterCV - Resume Management System

A Python application for managing and maintaining resume data using SQLite database.

## Features
- Store all resume data in a structured database
- Web-based forms for easy data entry and editing
- Manage personal info, work experience, education, skills, projects, and certifications
- **AI-powered CV parsing** using Google Gemini - automatically extract data from existing CVs (PDF, DOCX, TXT)
- **Multi-consultant support** - manage multiple consultant profiles with easy switching
- **Multi-language support** (English and Dutch) with easy language switching
- Import/export consultant data in JSON format
- Docker support for easy deployment

## AI-Powered CV Parsing

The application includes an AI-powered feature that can automatically parse existing CVs and extract structured information using Google's Gemini AI.

### Supported File Formats
- PDF files (.pdf)
- Microsoft Word documents (.docx, .doc) 
- Plain text files (.txt)

### Setup AI Features
1. Get a Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Set the environment variable:
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key-here"
   ```
3. The "Parse CV with AI" button will appear on the consultants page

### How it works
1. Upload your CV file via the web interface
2. The AI analyzes the content and extracts:
   - Personal information (name, contact details)
   - Work experience with dates and descriptions
   - Education history
   - Skills categorized by type
   - Projects with technologies used
   - Certifications with issue dates
3. Review the extracted data before importing
4. Create a new consultant profile with the structured data

**Note**: The AI parsing feature is optional. All manual features work without an API key.

## Authentication & Security

The application includes OAuth 2.0 authentication with role-based access control to secure your resume data when exposing the application to the internet.

### Features
- **OAuth 2.0 Integration**: Login with Google or Microsoft accounts
- **Whitelist-based Access**: Only pre-approved emails can access the system
- **Role-based Authorization**: 
  - **Admin**: Full access to all features, user management, and whitelist control
  - **Consultant**: Can only edit their own personal resume data
- **Admin Dashboard**: Manage users, roles, and whitelist entries

### Initial Setup

1. **Configure OAuth Providers**

   Copy the environment template:
   ```bash
   cp env.template .env
   ```

2. **Set up Google OAuth** (Optional)
   
   a. Go to [Google Cloud Console](https://console.cloud.google.com/)
   
   b. Create a new project or select existing
   
   c. Enable Google+ API
   
   d. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
   
   e. Set application type to "Web application"
   
   f. Add authorized redirect URI: `http://localhost:5000/auth/google/callback` (or your domain)
   
   g. Copy Client ID and Client Secret to `.env`:
   ```bash
   GOOGLE_CLIENT_ID=your-client-id-here
   GOOGLE_CLIENT_SECRET=your-client-secret-here
   ```

3. **Set up Microsoft OAuth** (Optional)
   
   a. Go to [Azure Portal](https://portal.azure.com/)
   
   b. Navigate to "Azure Active Directory" → "App registrations"
   
   c. Click "New registration"
   
   d. Set redirect URI: `http://localhost:5000/auth/microsoft/callback` (or your domain)
   
   e. Go to "Certificates & secrets" → Create new client secret
   
   f. Copy Application (client) ID and client secret to `.env`:
   ```bash
   MICROSOFT_CLIENT_ID=your-client-id-here
   MICROSOFT_CLIENT_SECRET=your-client-secret-here
   ```

4. **Generate Secret Key**
   
   Generate a secure random secret key:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
   
   Add it to `.env`:
   ```bash
   SECRET_KEY=your-generated-secret-key-here
   ```

5. **Set Base URL**
   
   For production deployment, set your domain:
   ```bash
   BASE_URL=https://yourdomain.com
   ```

### User Management

1. **Initial Admin Setup**
   
   Before first login, add your email to the whitelist:
   
   a. Edit `database.py` and modify the default admin email:
   ```python
   INSERT OR IGNORE INTO user_whitelist (email, role, notes) 
   VALUES ('your-email@example.com', 'admin', 'Initial admin user')
   ```
   
   b. Initialize/reinitialize the database:
   ```bash
   python init_db.py
   ```

2. **Adding More Users**
   
   After logging in as admin:
   - Go to the Admin Dashboard (Admin link in navigation)
   - Use "Whitelist Management" to add approved emails
   - Assign roles (admin or consultant)
   - Users can then log in using OAuth providers

3. **Role Permissions**
   - **Admin**: 
     - Access all consultant profiles
     - Edit any resume data
     - Manage users and whitelist
     - Access admin dashboard
   - **Consultant**:
     - View only their own profile
     - Edit only their personal information
     - Cannot access other consultants' data

### Security Best Practices

- **Never commit `.env` file** to version control (already in `.gitignore`)
- **Use HTTPS in production** for secure OAuth callbacks
- **Rotate secrets regularly**, especially if exposed
- **Review whitelist periodically** to remove inactive users
- **Use strong secret keys** (minimum 32 characters)
- **Configure OAuth apps** with minimal required scopes
- **Set appropriate redirect URIs** in OAuth provider settings (no wildcards)

### Docker Deployment with Authentication

Update `docker-compose.yml` with your environment variables or use `.env` file:

```yaml
services:
  bettercv:
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
      - MICROSOFT_CLIENT_ID=${MICROSOFT_CLIENT_ID}
      - MICROSOFT_CLIENT_SECRET=${MICROSOFT_CLIENT_SECRET}
      - BASE_URL=https://yourdomain.com
    env_file:
      - .env
```

Then run:
```bash
docker-compose up -d
```

## Setup Options

### Option 1: Docker (Recommended)

1. Build and run with Docker Compose:
   ```bash
   docker-compose up -d
   ```

2. **For AI features**: Set the Gemini API key in your environment:
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key-here"
   docker-compose down
   docker-compose up -d
   ```
   
   Or add it directly to the docker-compose.yml file:
   ```yaml
   environment:
     - GEMINI_API_KEY=your-gemini-api-key-here
   ```

3. Open your browser to: http://localhost:5000

4. To stop the application:
   ```bash
   docker-compose down
   ```

The database will be persisted in the `./data` directory.

### Option 2: Manual Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. **For AI features**: Set the Gemini API key:
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key-here"
   ```

3. Initialize the database:
   ```bash
   python init_db.py
   ```

4. Run the application:
   ```bash
   python app.py
   ```

5. Open your browser to: http://localhost:5000

## Docker Commands

**Build the image:**
```bash
docker build -t bettercv .
```

**Run the container:**
```bash
# Basic run (without authentication)
docker run -d -p 5000:5000 -v $(pwd)/data:/app/data --name bettercv bettercv

# With AI features (include Gemini API key)
docker run -d -p 5000:5000 -v $(pwd)/data:/app/data \
  -e GEMINI_API_KEY="your-api-key-here" \
  --name bettercv bettercv

# With authentication (include OAuth credentials)
docker run -d -p 5000:5000 -v $(pwd)/data:/app/data \
  -e SECRET_KEY="your-secret-key-here" \
  -e GOOGLE_CLIENT_ID="your-google-client-id" \
  -e GOOGLE_CLIENT_SECRET="your-google-client-secret" \
  -e MICROSOFT_CLIENT_ID="your-microsoft-client-id" \
  -e MICROSOFT_CLIENT_SECRET="your-microsoft-client-secret" \
  -e BASE_URL="http://localhost:5000" \
  --name bettercv bettercv

# Full setup with all features
docker run -d -p 5000:5000 -v $(pwd)/data:/app/data \
  -e SECRET_KEY="your-secret-key-here" \
  -e GOOGLE_CLIENT_ID="your-google-client-id" \
  -e GOOGLE_CLIENT_SECRET="your-google-client-secret" \
  -e MICROSOFT_CLIENT_ID="your-microsoft-client-id" \
  -e MICROSOFT_CLIENT_SECRET="your-microsoft-client-secret" \
  -e GEMINI_API_KEY="your-gemini-api-key" \
  -e BASE_URL="http://localhost:5000" \
  --name bettercv bettercv
```

**Or use docker-compose (recommended):**
```bash
# Make sure you have .env file configured first
docker-compose up -d
```

**View logs:**
```bash
docker logs bettercv
# or with docker-compose:
docker-compose logs -f
```

**Stop the container:**
```bash
docker stop bettercv
# or with docker-compose:
docker-compose down
