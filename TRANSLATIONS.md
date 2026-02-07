# BetterCV Translation System

## Overview
The application now supports multiple languages with a complete translation system.

## Supported Languages
- **English (en)** - Default language
- **Nederlands (nl)** - Dutch translation

## How It Works

### Translation Files
Translation strings are stored in JSON files:
- `translations/en.json` - English translations
- `translations/nl.json` - Dutch translations

### Usage in Templates
All templates have access to the translation object `t`:

```html
<!-- Accessing translations -->
{{ t.app_name }}
{{ t.nav.home }}
{{ t.buttons.save }}
{{ t.personal_info.title }}
```

### Language Switcher
A dropdown menu in the navigation bar allows users to switch languages. The selected language is stored in the session and persists across pages.

### Adding New Languages

1. Create a new JSON file in `translations/` folder (e.g., `fr.json` for French)
2. Copy the structure from `en.json` and translate all values
3. Update `app.py` to include the new language in `available_languages` dict:
```python
'available_languages': {
    'en': 'English',
    'nl': 'Nederlands',
    'fr': 'Français'  # Add new language
}
```

### Translation Structure

The JSON files are organized by section:
- `app_name`, `app_tagline` - Application branding
- `nav` - Navigation menu items
- `home` - Homepage content
- `buttons` - Common button labels
- `personal_info` - Personal information section
- `work_experience` - Work experience section
- `education` - Education section
- `skills` - Skills section
- `projects` - Projects section
- `certifications` - Certifications section
- `messages` - Success/error messages
- `common` - Shared terms
- `footer` - Footer content

## Technical Implementation

### Flask App (`app.py`)
- Loads all translation files on startup
- Provides `inject_translations()` context processor
- `set_language()` route handles language switching
- `get_translation()` helper function for Python code
- All flash messages use translations

### Templates
- All hardcoded text replaced with translation keys
- Language dropdown in navigation
- `lang` attribute on HTML tag reflects current language

### CSS (`static/style.css`)
- Styled language selector in navigation
- Responsive design for language dropdown

## Benefits
- Easy to maintain and update text
- Simple to add new languages
- Centralized translation management
- User preference persists in session
- No database changes required
