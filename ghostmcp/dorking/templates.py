"""Predefined Google dork templates for common OSINT queries.

Each template is a format string supporting these placeholders:
    {domain}  — target domain (e.g. example.com)
    {keyword} — specific keyword to search for
    {ext}     — file extension (e.g. pdf, env, sql)
"""

from __future__ import annotations

TEMPLATES: dict[str, str] = {
    # Configuration files exposed on the web
    "exposed_configs": (
        'site:{domain} (filetype:env OR filetype:yml OR filetype:yaml OR filetype:ini '
        'OR filetype:conf OR filetype:cfg) -github.com'
    ),

    # Login pages (admin panels, dashboards)
    "login_pages": (
        'site:{domain} (inurl:login OR inurl:admin OR inurl:signin OR inurl:auth '
        'OR intitle:"login" OR intitle:"admin panel")'
    ),

    # Open directory listings
    "directory_listing": (
        'site:{domain} intitle:"index of" (inurl:admin OR inurl:backup OR inurl:config '
        'OR inurl:data OR inurl:uploads)'
    ),

    # Exposed .git directories
    "git_exposed": (
        'site:{domain} (inurl:".git" OR intitle:"index of /.git" '
        'OR inurl:".gitignore" OR inurl:".git/config")'
    ),

    # Environment files with credentials
    "env_files": (
        'site:{domain} (filetype:env OR inurl:.env OR intitle:".env") '
        '("DB_PASSWORD" OR "API_KEY" OR "SECRET" OR "TOKEN")'
    ),

    # API documentation pages
    "api_docs": (
        'site:{domain} (inurl:api OR inurl:swagger OR inurl:docs OR inurl:graphql '
        'OR intitle:"API documentation" OR inurl:openapi)'
    ),

    # Error messages revealing stack traces / versions
    "error_messages": (
        'site:{domain} ("fatal error" OR "stack trace" OR "SQL syntax" '
        'OR "Warning:" OR "Exception" OR "Traceback") -stackoverflow.com'
    ),

    # Technology stack identification
    "tech_stack": (
        'site:{domain} (inurl:wp-content OR inurl:wp-admin OR "powered by" '
        'OR "built with" OR inurl:node_modules OR inurl:vendor)'
    ),

    # Database dumps and SQL files
    "database_dumps": (
        'site:{domain} (filetype:sql OR filetype:db OR filetype:sqlite '
        'OR filetype:mdb OR filetype:bak) -github.com'
    ),

    # Sensitive documents
    "sensitive_docs": (
        'site:{domain} (filetype:pdf OR filetype:xlsx OR filetype:docx) '
        '("confidential" OR "internal" OR "restricted" OR "password")'
    ),

    # Subdomains via certificate transparency
    "subdomains": (
        'site:*.{domain} -www.{domain}'
    ),

    # Exposed backup files
    "backup_files": (
        'site:{domain} (filetype:bak OR filetype:old OR filetype:backup '
        'OR filetype:zip OR filetype:tar OR filetype:gz) (inurl:backup OR inurl:dump)'
    ),
}


def get_template_names() -> list[str]:
    """Return sorted list of available template names."""
    return sorted(TEMPLATES.keys())


def get_template_info() -> dict[str, str]:
    """Return dict of template names to their format strings."""
    return dict(TEMPLATES)
