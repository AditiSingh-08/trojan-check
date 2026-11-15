"""Central configuration, read from environment variables.

Set these in your shell, a local `.env` file (see .env.example) or your
hosting provider's dashboard. Nothing secret lives in the source code.
"""
import logging
import os
import secrets

try:  # optional: load backend/.env during local development
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv is not required in production
    pass

logger = logging.getLogger(__name__)

APP_ENV = os.getenv("APP_ENV", "development").lower()
IS_PRODUCTION = APP_ENV == "production"

# --- JWT ---------------------------------------------------------------
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    if IS_PRODUCTION:
        raise RuntimeError("SECRET_KEY must be set when APP_ENV=production")
    # Development fallback: random per process, so tokens stop working on restart.
    SECRET_KEY = secrets.token_urlsafe(32)
    logger.warning("SECRET_KEY not set; using a temporary random key (development only).")

# --- Demo user (there is no user database yet) -------------------------
DEMO_USERNAME = os.getenv("DEMO_USERNAME", "johndoe")
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD")
if not DEMO_PASSWORD:
    if IS_PRODUCTION:
        raise RuntimeError("DEMO_PASSWORD must be set when APP_ENV=production")
    DEMO_PASSWORD = "secret"  # development default only

# --- CORS --------------------------------------------------------------
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]

# --- Uploads -----------------------------------------------------------
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE_MB", "10")) * 1024 * 1024

# --- VirusTotal (optional) ---------------------------------------------
VT_API_KEY = os.getenv("VT_API_KEY") or None
VT_TIMEOUT_SECONDS = 8
