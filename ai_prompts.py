"""Centralized prompt templates for AI features."""

CV_PARSE_PROMPT_TEMPLATE = """
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
  translate English CVs into Dutch. Do not translate English verbs if they
  are used in a Dutch CV. Especially, do not translate certificates,
  educational degrees, project names, company names, skill names, etc. that
  are in English in the original CV.
- Experience: if you find a list of points under results for experience, make
  sure to capture those in the STAR results field, and if there are remaining
  details not captured in STAR, put those in the description field.
- Certifications: if a location for the organization is mentioned,
  add that to the organization field. Make sure to extract the name of the
  certification or course if mentioned.
- If bullet points are used in the CV, use markdown formatting in
  the JSON output to preserve the bullet points in description fields.
- Dates are normally formatted as European dates, so DD-MM-YYYY.
  If abbreviated they are usually in the format "Okt 2023" or "Oct 2023".
  In this case, "Oct 2023" should be interpreted as "2023-10-01"
  (use the first day of the month when day is not specified).
- Format dates as YYYY-MM-DD or YYYY-MM-01 if day is unknown,
  or YYYY-01-01 if only year is known.
- Extract only information that is explicitly mentioned in the CV.
- For skills, group similar skills into logical categories and match them to
  existing categories as closely as possible; use "Various" if unsure.
- Return only valid JSON, no additional text or explanations.
- If information is missing, use an empty string or omit the field;
  do not use "None" or null.

CV Text:
{cv_text}
""".strip()


ASSIGNMENT_MATCH_PROMPT_TEMPLATE = """
Je bent een coorporate recruiter, je bent voor een opdrachtgever op zoek naar de 
    perfecte kandidaat. Bijgevoegd is de data uit een aantal CV's en een opdrachtbeschrijving. 

Je bent gespecialiseerd in exacte matching. Analyseer de geleverde vacaturetekst grondig en 
    extraheer alle harde eisen (must-haves waar zonder niet wordt uitgenodigd), 
    wenselijke competenties, ervaring (nice-to-have) en soft skills/competenties 
    die expliciet of impliciet genoemd worden. Gebruik hiervoor uitsluitend de vacaturetekst.

Let op: soms staat er in een opdracht dat het gaat om een warme stoel, met andere woorden: 
    de opdracht staat niet echt uit voor selectie, maar de huidige invulling wordt gehandhaafd. 
    In zo'n geval mag je de analyse meteen stoppen en dit melden in de summary.

Bekijk vervolgens de CV's, geef als output een tabel met daarin de naam van de kandidaat, 
het percentage slagingskans en in 1 alinea waarom dat zo is. Sorteer de tabel van 
meeste kans naar minste kans.

Return format:
- Alleen valide JSON (no markdown, no extra text).
- Gebruik deze exacte top-level structuur:

{{
  "summary": "Short overall summary of the best fit and notable trade-offs",
  "ranking": [
    {{
      "rank": 1,
      "consultant_name": "Display Name",
      "fit_score": 0,
      "strengths": ["..."],
      "gaps": ["..."],
      "rationale": "Short explanation for this rank"
    }}
  ],
  "recommended_consultant_names": ["Display Name"],
  "notes": ["Optional caveats, assumptions, or data-quality notes"]
}}

Assignment description:
{assignment_description}

Candidate data (JSON array):
{consultants_json}
""".strip()


def get_cv_parse_prompt(cv_text):
    return CV_PARSE_PROMPT_TEMPLATE.format(cv_text=cv_text)


def get_assignment_match_prompt(assignment_description, consultants_json):
    return ASSIGNMENT_MATCH_PROMPT_TEMPLATE.format(
        assignment_description=assignment_description,
        consultants_json=consultants_json
    )
