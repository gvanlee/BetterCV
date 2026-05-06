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
      "project_name": "Project Name",
      "description": "Project description",
      "start_date": "YYYY-MM-DD",
      "end_date": "YYYY-MM-DD or null",
      "url": "Project URL if mentioned"
    }}
  ],
  "certifications": [
    {{
      "certification_name": "Certification Name/Course Name or name of issuing organization if specific certification or course name is not mentioned",
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
- Skills: if you find a list of skills (e.g. comma separated or bullet points), 
  make sure to capture those as individual skill entries in the skills array.
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
You are a corporate recruiter; you are looking for the perfect candidate for a client. 
  Attached are data from a number of CVs and a job description.

You specialize in exact matching. Thoroughly analyze the provided job description 
  and extract all hard requirements (must-haves without which candidates will not 
  be invited), desirable competencies, experience (nice-to-have), and soft 
  skills/competencies that are explicitly or implicitly mentioned. Use the job 
  description exclusively for this. 

Note: sometimes a job description states that it concerns a "hot seat"; in other words, 
  the assignment is not actually open for selection, but the current staffing is being 
  maintained. In such a case, you may stop the analysis immediately and mention this 
  in the summary.

Next, review the CVs and provide a table as output containing the candidate's name, 
  the success rate percentage, and in one paragraph the reason why this is the case. 
  Sort the table from highest chance to lowest chance. In the event that this is not 
  clearly evident from the CV, the candidate is employed by Isatis Business Solutions. 
  Therefore, this does not involve a self-employed person or freelancer. 
  
Be exact in your matching. If a requirement is not explicitly mentioned in the CV, do 
  not assume it is met but rather consider it as a gap. If a knock-out criterion is not 
  met, the candidate should be ranked lower than any candidate who meets all knock-out 
  criteria, regardless of how many desirable competencies they have.

Show a maximum of 5 candidates; if there are more than 5 candidates, show only the top 5.

Return format:

- Only valid JSON (no markdown, no extra text).
- Use this exact top-level structure:

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


ASSIGNMENT_PARSE_PROMPT_TEMPLATE = """
Analyze the assignment text below and return only valid JSON using this exact structure:

{{
  "assignment": {{
    "title": "string",
    "description": "string",
    "location": "string",
    "reference_id": "string",
    "hot_seat": "bool",
    "hot_seat_context": "string",
    "hourly_rate_min": "number",
    "hourly_rate_max": "number",
    "hourly_rate": "number",
    "knock_out_criteria": ["string"],
    "nice_to_have_criteria": ["string"],
    "competenties": ["string"],
    "deadline": "YYYY-MM-DD",
    "deadline_estimated": "bool",
    "start_date": "YYYY-MM-DD"
  }},
  "contact": {{
    "recruiter_name": "string",
    "recruiter_email": "string",
    "recruiter_phone": "string"
  }}
}}

Prompt:
    You are an experienced recruiter specializing in exact matching. Your task is to convert the
    assignment description below into a structured JSON file.

    ### Instructions:
    1. Analyse this assignment text thoroughly, do not make up things, do not assume information 
      that is not explicitly stated. Set the description field to the assignment description 
      (leave out information that is extracted to other fields), set the location field to 
      information about the company where the assignment will be performed. Keep as much of the 
      original wording as possible when filling in the fields, do not rephrase or translate the 
      detected information, keep it as in the source text.
    2. Extract all hard requirements (must-haves), desirable competencies (nice-to-haves), 
      and other soft skills or competencies that are explicitly mentioned.
    3. If there is a "hot seat" situation (the assignment is not really open for selection, but 
      the current placement will be maintained), mention this in the "hot_seat_context" field, 
      set the hot_seat field to true in this case. Otherwise, set the hot_seat field to false 
      and leave the "hot_seat_context" field empty.
    4. Fill in the rate fields numerically. If a range is mentioned, provide the full range using 
      minumum and maxium rates. If no rate information is available, leave the fields empty.
    5. Fill in the "deadline" field as a date string in the format `YYYY-MM-DD`.
      If deadline is missing and start_date is present, set deadline to one week before start_date 
      and set deadline_estimated to true. Use false for deadline_estimated when deadline is explicitly 
      found. If both deadline and start_date are missing, set deadline to empty string and deadline_estimated 
      to true.
    6. Extract contact information for the recruiter if mentioned, otherwise leave those fields empty.
    7. Return only JSON, no markdown and no explanatory text. 
    8. Keep extracted language as in source text.
    9. Use empty string for unknown text fields.
   10. Use empty arrays for unknown list fields.
   11. Use empty string for unknown numeric fields.
   12. Normalize detected dates to YYYY-MM-DD.

Assignment text:
{assignment_text}
""".strip()


def get_cv_parse_prompt(cv_text):
    return CV_PARSE_PROMPT_TEMPLATE.format(cv_text=cv_text)


def get_assignment_match_prompt(assignment_description, consultants_json):
    return ASSIGNMENT_MATCH_PROMPT_TEMPLATE.format(
        assignment_description=assignment_description,
        consultants_json=consultants_json
    )


def get_assignment_parse_prompt(assignment_text):
  return ASSIGNMENT_PARSE_PROMPT_TEMPLATE.format(assignment_text=assignment_text)
