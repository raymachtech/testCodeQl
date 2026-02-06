import os
from pathlib import Path
from dotenv import load_dotenv

SCRIPTS_ROOT = Path(__file__).parent.parent.parent
ENV_FILE = SCRIPTS_ROOT / '.env'

if not ENV_FILE.exists():
    raise FileNotFoundError(f".env file not found at {ENV_FILE}. Please create .env file with required variables.")

load_dotenv(ENV_FILE)
print(f"Loaded .env from: {ENV_FILE}")

def get_required_env(key: str) -> str:
    value = os.getenv(key)
    if not value:
        raise ValueError(f"Required environment variable {key} is missing in .env file")
    return value

def get_optional_env(key: str, default: str) -> str:
    return os.getenv(key, default)

HOST = get_optional_env('HOST', '0.0.0.0')
PORT = int(get_optional_env('PORT', '50300'))
WAITRESS_THREADS = int(get_optional_env('WAITRESS_THREADS', '16'))
WAITRESS_CHANNEL_TIMEOUT = int(get_optional_env('WAITRESS_CHANNEL_TIMEOUT', '120'))

EGCA_AIX_SERVER = get_required_env('EGCA_AIX_SERVER')
EGCA_AIX_DATABASE = get_required_env('EGCA_AIX_DATABASE')
EGCA_AIX_USERNAME = get_required_env('EGCA_AIX_USERNAME')
EGCA_AIX_PASSWORD = get_required_env('EGCA_AIX_PASSWORD')

MULTITHREADING = get_optional_env('MULTITHREADING', 'False').lower() == 'true'

AZURE_CLIENT_ID = get_required_env('AZURE_AD_CLIENT_ID')
AZURE_CLIENT_SECRET = get_required_env('AZURE_AD_CLIENT_SECRET')
AZURE_TENANT_ID = get_required_env('AZURE_AD_TENANT_ID')
AZURE_REDIRECT_URI = get_required_env('AZURE_AD_REDIRECT_URI')
azure_scope_str = get_optional_env('AZURE_AD_SCOPE', 'User.Read')
AZURE_SCOPE = azure_scope_str.split(',') if azure_scope_str else ['User.Read']

JWT_SECRET = get_required_env('JWT_SECRET')
if len(JWT_SECRET) < 32:
    raise ValueError("JWT_SECRET must be at least 32 characters long for security")
JWT_EXP_MINUTES = int(get_optional_env('JWT_EXP_MINUTES', '60'))

FRONTEND_REDIRECT_URL = get_required_env('FRONTEND_REDIRECT_URL')
allowed_origins_str = get_required_env('ALLOWED_ORIGINS')
ALLOWED_ORIGINS = [origin.strip() for origin in allowed_origins_str.split(',') if origin.strip()] if allowed_origins_str else []
if not ALLOWED_ORIGINS:
    raise ValueError("ALLOWED_ORIGINS must contain at least one origin")

VAPID_PUBLIC_KEY = get_required_env('VAPID_PUBLIC_KEY')
VAPID_PRIVATE_KEY = get_required_env('VAPID_PRIVATE_KEY')
VAPID_CLAIM = get_required_env('VAPID_CLAIM')

if EGCA_AIX_SERVER and EGCA_AIX_DATABASE:
    EGCA_AIX_DB_STRING = (
        f'Driver={{ODBC Driver 17 for SQL Server}}; '
        f'Server={EGCA_AIX_SERVER}; '
        f'Database={EGCA_AIX_DATABASE}; '
        f'UID={EGCA_AIX_USERNAME}; '
        f'PWD={EGCA_AIX_PASSWORD};'
    )
else:
    EGCA_AIX_DB_STRING = None
