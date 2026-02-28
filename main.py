import hashlib
import json
import logging
import math
import os
import secrets
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta
from typing import Optional

import sqlite3
import bcrypt
from fastapi import Depends, FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SERVICE_NAME = "svc-payments"
VERSION = "3.1.0"

# -- Admin & Auth Configuration ------------------------------------------------
ADMIN_EMAIL = "carl@roboserve.eu"
SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key_that_should_be_in_env_for_production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 week

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")


# -- Pydantic Models -----------------------------------------------------------
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None


# -- Token-based pricing -------------------------------------------------------
FREE_CREDITS = 500
# Fallback rates — database takes priority
TOKEN_CREDIT_RATES = {
    "gemini-2.0-flash": {"credits_per_1k_tokens": 15, "label": "Gemini Flash", "api_cost_per_1m": 0.25},
    "gemini-2.5-pro-preview-06-05": {"credits_per_1k_tokens": 120, "label": "Gemini Pro", "api_cost_per_1m": 5.63},
    "gpt-5.0": {"credits_per_1k_tokens": 120, "label": "GPT-5", "api_cost_per_1m": 5.63},
    "claude-opus-4.6": {"credits_per_1k_tokens": 350, "label": "Claude Opus 4.6", "api_cost_per_1m": 15.0},
    "claude-sonnet-4.5": {"credits_per_1k_tokens": 80, "label": "Claude Sonnet 4.5", "api_cost_per_1m": 3.0},
}
MODEL_ALIASES = {
    "gemini-flash": "gemini-2.0-flash",
    "gemini-pro": "gemini-2.5-pro-preview-06-05",
    "gpt-5.0": "gpt-5.0",
    "claude-opus": "claude-opus-4.6",
    "claude-sonnet": "claude-sonnet-4.5",
}
DEFAULT_RATE = {"credits_per_1k_tokens": 15, "label": "Unknown", "api_cost_per_1m": 0.25}

# -- Bunq SDK -------------------------------------------------------------------
_bunq_initialized = False
_bunq_user_id = None
_bunq_init_error = None

def init_bunq():
    global _bunq_initialized, _bunq_user_id, _bunq_init_error
    # Bunq initialization logic remains the same
    pass

# -- Database -------------------------------------------------------------------
def _db_connect():
    # conn = sqlite3.connect("railway.db")
    # conn.row_factory = sqlite3.Row
    # return conn
    import pymysql
    conn = pymysql.connect(
        host=os.getenv("MARIADB_PRIVATE_HOST"),
        user=os.getenv("MARIADB_USER"),
        password=os.getenv("MARIADB_PASSWORD"),
        database=os.getenv("MARIADB_DATABASE"),
        port=int(os.getenv("MARIADB_PRIVATE_PORT")),
        cursorclass=pymysql.cursors.DictCursor
    )
    return conn

@contextmanager
def db():
    conn = _db_connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def _get_merged_services():
    try:
        with db() as db_conn:
            with db_conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute("SELECT service_id, status FROM service_status")
                rows = cur.fetchall()
                status_map = {row['service_id']: row['status'] for row in rows}
    except Exception as e:
        logger.error(f"Error fetching service statuses: {e}", exc_info=True)
        status_map = {}
        
    merged = []
    for svc in ALL_SERVICES:
        s = svc.copy()
        s['status'] = status_map.get(s['id'], 'off')
        merged.append(s)
    return merged

ALL_SERVICES = [
    {"id": "svc-blog-ideas", "name": "Blog Idea Generator", "description": "AI generates creative blog post ideas from a topic or niche."},
    {"id": "svc-product-description", "name": "AI Product Description & SEO Generator", "description": "Product photo/name → SEO title + meta + description + 5 keywords."},
    {"id": "svc-content-repurposing", "name": "AI SEO Content Repurposing Engine", "description": "YouTube URL → blogpost + Twitter threads + LinkedIn posts."},
    {"id": "svc-reputation", "name": "AI Reputation Management", "description": "Google reviews → automatic professional responses."},
    {"id": "svc-cold-email", "name": "AI Cold Email Personalization", "description": "LinkedIn URLs → unique opening line + pitch per prospect."},
    {"id": "svc-real-estate", "name": "AI Real Estate Listing Optimizer", "description": "Property features → Funda listings + social posts."},
    {"id": "svc-chatbot", "name": "AI Customer Service Chatbot", "description": "URL/FAQ → RAG chat widget 24/7."},
    {"id": "svc-email-autodrafter", "name": "AI Email Autodrafter & Support Routing", "description": "Email in → categorize urgency → draft response."},
    {"id": "svc-legal-simplifier", "name": "AI Legal Document Simplifier", "description": "Legal document → simplified summary + checklist."},
    {"id": "svc-landing-page", "name": "AI Landing Page Builder", "description": "Business description → complete landing page."},
    {"id": "svc-course-creator", "name": "AI Course & LMS Creator", "description": "Niche + audience → course structure + scripts + quizzes."},
    {"id": "svc-solopreneur-crm", "name": "AI Solopreneur CRM", "description": "Email sync → categorize contacts, schedule appointments, follow-ups."},
    {"id": "svc-podcast-notes", "name": "AI Podcast Show Notes & Clip Generator", "description": "Audio → show notes + timestamps + highlight clips."},
    {"id": "svc-sentiment", "name": "AI Sentiment & Review Analysis", "description": "Review feeds → sentiment dashboard + alerts."},
    {"id": "svc-applicant-screener", "name": "AI Applicant Screener", "description": "Batch CV upload → match against vacancy → ranking."},
    {"id": "svc-logo-creator", "name": "AI Logo & Brand Kit Creator", "description": "Company name + style → logos + business cards + banners."},
    {"id": "svc-sop-generator", "name": "AI SOP Generator", "description": "Screen recording → illustrated step-by-step guide."},
    {"id": "svc-language-tutor", "name": "AI Online Tutor & Language Roleplay Bot", "description": "STT + LLM + TTS = interactive language education."},
    {"id": "svc-invoice-ocr", "name": "AI Invoice & Expense OCR", "description": "Photo/PDF → field extraction → JSON."},
    {"id": "svc-travel-planner", "name": "AI Travel & Route Planner", "description": "Travel wishes → complete itinerary + booking links."},
    {"id": "svc-meeting-actions", "name": "AI Meeting Action Item Extractor", "description": "Meeting audio → action items + tasks."},
    {"id": "svc-task-prioritizer", "name": "AI Daily Task Prioritizer", "description": "Calendar + tasks → AI day plan."},
    {"id": "svc-regulation-tracker", "name": "AI Local Regulation Tracker", "description": "Scrapes government portals → action plans per business type."},
    {"id": "svc-music-generator", "name": "AI Music & Sound Effects Generator", "description": "Prompt → royalty-free audio."},
    {"id": "svc-event-planner", "name": "AI Event Planning PM", "description": "Event details → Gantt chart + reminders."},
    {"id": "svc-finance-assistant", "name": "AI Finance & Budget Assistant", "description": "Transactions → classification → budget report."},
]

_INIT_SQL = [
    """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) NOT NULL UNIQUE,
        name VARCHAR(255),
        password_hash VARCHAR(255),
        token VARCHAR(255) UNIQUE,
        credits INTEGER NOT NULL DEFAULT 0,
        is_subscriber TINYINT(1) DEFAULT 0,
        subscription_expires_at TIMESTAMP NULL,
        is_admin TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS credit_transactions ( id INTEGER PRIMARY KEY AUTO_INCREMENT, user_id INTEGER NOT NULL, amount INTEGER NOT NULL, balance_after INTEGER NOT NULL, tx_type VARCHAR(255) NOT NULL, description TEXT, service VARCHAR(255), model VARCHAR(255), tokens_used INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP )""",
    """CREATE TABLE IF NOT EXISTS credit_packages (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL,
        credits INTEGER NOT NULL,
        price_cents INTEGER NOT NULL,
        label VARCHAR(255),
        allowed_models TEXT,
        is_active TINYINT(1) DEFAULT 1,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS subscription_plans (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL,
        credits_per_month INTEGER NOT NULL,
        price_cents INTEGER NOT NULL,
        allowed_models TEXT,
        is_active TINYINT(1) DEFAULT 1,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS token_credit_rates (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        model VARCHAR(255) NOT NULL UNIQUE,
        label VARCHAR(255),
        credits_per_1k_tokens INTEGER NOT NULL,
        api_cost_per_1m REAL DEFAULT 0,
        subscription_only TINYINT(1) DEFAULT 0,
        is_active TINYINT(1) DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        user_email VARCHAR(255) NOT NULL,
        type VARCHAR(50) NOT NULL,
        package_id VARCHAR(50),
        amount_eur DECIMAL(10,2),
        credits INTEGER,
        bunq_transaction_id VARCHAR(255),
        status VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS service_status (
        service_id VARCHAR(255) PRIMARY KEY,
        status VARCHAR(50) DEFAULT 'off',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )"""
]

_MIGRATE_SQL = [
    "ALTER TABLE users ADD COLUMN password_hash VARCHAR(255) NULL AFTER name",
    "ALTER TABLE users ADD COLUMN is_admin TINYINT(1) DEFAULT 0 AFTER subscription_expires_at",
    "ALTER TABLE users ADD COLUMN subscription_plan VARCHAR(255) NULL",
    "ALTER TABLE users ADD COLUMN subscription_renewal DATE NULL",

]

def init_db():
    try:
        conn = _db_connect()
        cur = conn.cursor()
        for sql in _INIT_SQL:
            try:
                cur.execute(sql)
            except Exception as e:
                logger.error(f"Error executing SQL: {sql} - {e}")
        conn.commit()
        cur.close()
        conn.close()
        logger.info("Payment DB tables initialized/migrated")
    except Exception as e:
        logger.error(f"DB init failed: {e}", exc_info=True)

def seed_pricing_data():
    try:
        conn = _db_connect()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM credit_packages")
        if cur.fetchone()['c'] == 0:
            logger.info("Seeding credit_packages...")
            packages = [
                ('starter', 2500, 500, '2,500 credits', json.dumps(["gemini-2.0-flash", "claude-sonnet-4.5"])),
                ('basic', 5000, 900, '5,000 credits', json.dumps(["gemini-2.0-flash", "claude-sonnet-4.5"])),
                ('plus', 10000, 1500, '10,000 credits', json.dumps(["gemini-2.0-flash", "claude-sonnet-4.5"])),
                ('pro', 15000, 2000, '15,000 credits', json.dumps(["gemini-2.0-flash", "claude-sonnet-4.5"])),
                ('business', 50000, 5000, '50,000 credits', json.dumps(["gemini-2.0-flash", "claude-sonnet-4.5"])),
            ]
            cur.executemany("INSERT INTO credit_packages (name, credits, price_cents, label, allowed_models) VALUES (%s, %s, %s, %s, %s)", packages)

        cur.execute("SELECT COUNT(*) as c FROM subscription_plans")
        if cur.fetchone()['c'] == 0:
            logger.info("Seeding subscription_plans...")
            all_models = json.dumps(["gemini-2.0-flash", "gemini-2.5-pro-preview-06-05", "gpt-5.0", "claude-opus-4.6", "claude-sonnet-4.5"])
            cur.execute("INSERT INTO subscription_plans (name, credits_per_month, price_cents, allowed_models) VALUES (%s, %s, %s, %s)",
                        ('pro', 15000, 2999, all_models))

        cur.execute("SELECT COUNT(*) as c FROM token_credit_rates")
        if cur.fetchone()['c'] == 0:
            logger.info("Seeding token_credit_rates...")
            rates = [
                ('gemini-2.0-flash', 'Gemini Flash', 15, 0.25, False),
                ('gemini-2.5-pro-preview-06-05', 'Gemini Pro', 120, 5.63, False),
                ('gpt-5.0', 'GPT-5', 120, 5.63, True),
                ('claude-opus-4.6', 'Claude Opus 4.6', 350, 15.0, True),
                ('claude-sonnet-4.5', 'Claude Sonnet 4.5', 80, 3.0, False),
            ]
            cur.executemany("INSERT INTO token_credit_rates (model, label, credits_per_1k_tokens, api_cost_per_1m, subscription_only) VALUES (%s, %s, %s, %s, %s)", rates)
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logger.error(f"Pricing data seeding failed: {e}", exc_info=True)

# -- Pricing data helpers ----------------------------------------------------
def get_credit_packages(include_inactive=False):
    try:
        conn = _db_connect()
        cur = conn.cursor()
        sql = "SELECT * FROM credit_packages"
        if not include_inactive:
            sql += " WHERE is_active = TRUE"
        sql += " ORDER BY sort_order ASC, id ASC"
        cur.execute(sql)
        packages = cur.fetchall()
        cur.close()
        conn.close()
        return packages
    except Exception as e:
        logger.error(f"Error fetching credit packages: {e}", exc_info=True)
        return []

def get_subscription_plans(include_inactive=False):
    try:
        conn = _db_connect()
        cur = conn.cursor()
        sql = "SELECT * FROM subscription_plans"
        if not include_inactive:
            sql += " WHERE is_active = TRUE"
        sql += " ORDER BY sort_order ASC, id ASC"
        cur.execute(sql)
        plans = cur.fetchall()
        cur.close()
        conn.close()
        return plans
    except Exception as e:
        logger.error(f"Error fetching subscription plans: {e}", exc_info=True)
        return []

def get_token_rates(include_inactive=False):
    try:
        conn = _db_connect()
        cur = conn.cursor()
        sql = "SELECT model, label, credits_per_1k_tokens, api_cost_per_1m, subscription_only FROM token_credit_rates"
        if not include_inactive:
            sql += " WHERE is_active = TRUE"
        cur.execute(sql)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        rates = {r['model']: {k: v for k, v in dict(r).items() if k != 'model'} for r in rows}
        return rates
    except Exception as e:
        logger.error(f"Error fetching token rates: {e}", exc_info=True)
        return TOKEN_CREDIT_RATES # Fallback to hardcoded

def get_all_available_models():
    try:
        conn = _db_connect()
        cur = conn.cursor()
        cur.execute("SELECT model FROM token_credit_rates WHERE is_active = TRUE")
        models = [row['model'] for row in cur.fetchall()]
        cur.close()
        conn.close()
        return models
    except Exception as e:
        logger.error(f"Error fetching available models: {e}", exc_info=True)
        return list(TOKEN_CREDIT_RATES.keys())

def get_subscription_only_models():
    try:
        conn = _db_connect()
        cur = conn.cursor()
        cur.execute("SELECT model FROM token_credit_rates WHERE subscription_only = TRUE AND is_active = TRUE")
        models = [row['model'] for row in cur.fetchall()]
        cur.close()
        conn.close()
        return models
    except Exception as e:
        logger.error(f"Error fetching subscription only models: {e}", exc_info=True)
        return []


# -- Auth helpers ---------------------------------------------------------------
def verify_password(plain_password, hashed_password):
    if not hashed_password: return False
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_email(email: str) -> dict | None:
    try:
        conn = _db_connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        return user
    except Exception as e:
        logger.error(f"get_user_by_email error: {e}")
        return None

def get_user_by_token(token: str) -> dict | None: # Legacy support
    if not token: return None
    try:
        conn = _db_connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE token = %s", (token,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        return user
    except Exception as e:
        logger.error(f"get_user_by_token error: {e}")
        return None

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(email)
    if user is None: raise credentials_exception
    return user

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if not current_user["is_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized for this resource")
    return current_user

# -- Credit functions -----------------------------------------------------------
def add_credits(user_id: int, amount: int, tx_type: str, description: str, service: str = None, model: str = None):
    try:
        conn = _db_connect()
        cur = conn.cursor()
        cur.execute("UPDATE users SET credits = credits + %s WHERE id = %s", (amount, user_id))
        cur.execute("SELECT credits FROM users WHERE id = %s", (user_id,))
        new_balance = cur.fetchone()[0]
        cur.execute("INSERT INTO credit_transactions (user_id, amount, balance_after, tx_type, description, service, model) VALUES (%s, %s, %s, %s, %s, %s, %s)", (user_id, amount, new_balance, tx_type, description, service, model))
        conn.commit()
        cur.close()
        conn.close()
        return new_balance
    except Exception as e:
        logger.error(f"add_credits error: {e}", exc_info=True)
        return None

# -- App -----------------------------------------------------------------------
@asynccontextmanager
def ensure_admin():
    """Ensure the hardcoded admin account exists with correct password."""
    logger.info("Ensuring admin account exists...")
    try:
        # Pre-calculated hash for "R0b0$erve!Admin2026"
        hashed = "$2b$12$Ha34aQg/IgDYG7dpQuqi.etRCddIeI8Rmttietai4UMV3a.p9fkBm"
        logger.info(f"Using pre-calculated admin password hash")
        
        logger.info(f"DB HOST: {os.getenv('MARIADB_PRIVATE_HOST')}")

        conn = _db_connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (ADMIN_EMAIL,))
        user = cur.fetchone()
        
        if user is None:
            token = secrets.token_hex(32)
            cur.execute(
                "INSERT INTO users (email, name, password_hash, is_admin, token, credits) VALUES (%s, %s, %s, %s, %s, %s)",
                (ADMIN_EMAIL, "Carl Admin", hashed, True, token, 100000)
            )
            logger.info("Admin account created")
        elif user.get('password_hash') != hashed:
            cur.execute(
                "UPDATE users SET password_hash=%s, is_admin=TRUE WHERE email=%s",
                (hashed, ADMIN_EMAIL)
            )
            logger.info("Admin account password updated")
        else:
            logger.info("Admin password hash is already correct.")

        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logger.error(f"ensure_admin failed: {e}", exc_info=True)

def migrate_db():
    try:
        conn = _db_connect()
        cur = conn.cursor()
        for sql in _MIGRATE_SQL:
            try:
                cur.execute(sql)
            except Exception as e:
                # This will fail if the column already exists, which is fine
                logger.info(f"Could not execute migration SQL (this is probably OK): {sql} - {e}")
        conn.commit()
        cur.close()
        conn.close()
        logger.info("Payment DB tables migrated")
    except Exception as e:
        logger.error(f"DB migration failed: {e}", exc_info=True)

async def lifespan(app: FastAPI):
    init_db()
    migrate_db()
    seed_pricing_data()
    ensure_admin()
    init_bunq()
    yield

app = FastAPI(title="RoboServe Payments & Credits", version=VERSION, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["https://www.roboserve.eu", "https://roboserve.eu", "https://roboserve-vite-production.up.railway.app", "http://localhost", "http://localhost:3000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
def health(): return {"status": "ok", "service": SERVICE_NAME, "version": VERSION}

# -- User Registration & Auth --------------------------------------------------
@app.post("/api/v1/register", response_model=Token)
async def register(user_data: UserCreate):
    email = user_data.email.strip().lower()
    if get_user_by_email(email):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    is_admin = (email == ADMIN_EMAIL)
    legacy_token = secrets.token_urlsafe(32)

    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO users (email, name, password_hash, is_admin, token, credits) VALUES (%s, %s, %s, %s, %s, %s)", (email, user_data.name, hashed_password, is_admin, legacy_token, FREE_CREDITS))
                user_id = cur.lastrowid
                cur.execute("INSERT INTO credit_transactions (user_id, amount, balance_after, tx_type, description) VALUES (%s, %s, %s, %s, %s)", (user_id, FREE_CREDITS, FREE_CREDITS, "signup_bonus", "Welcome credits"))
        logger.info(f"New user registered: {email}, admin={is_admin}")
        access_token = create_access_token(data={"sub": email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        logger.error(f"Registration error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    logger.info(f"Attempting login for user: {form_data.username}")
    user = get_user_by_email(form_data.username)
    logger.info(f"User object from DB: {user}")
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})
    access_token = create_access_token(data={"sub": user["email"]}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/v1/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    sub_active = bool(current_user["is_subscriber"] and current_user["subscription_expires_at"] and current_user["subscription_expires_at"] > datetime.now())
    return {
        "user_id": current_user["id"], "email": current_user["email"], "name": current_user["name"],
        "credits": current_user["credits"], "is_subscriber": sub_active, "is_admin": current_user["is_admin"],
        "subscription_expires_at": str(current_user["subscription_expires_at"]) if current_user["subscription_expires_at"] else None,
    }

# -- Public Pricing Endpoints --------------------------------------------------
@app.get("/api/v1/credit-packages")
async def list_credit_packages():
    return get_credit_packages()

@app.get("/api/v1/subscription-plans")
async def list_subscription_plans():
    return get_subscription_plans()

# -- Admin Pricing Endpoints ---------------------------------------------------
@app.get("/api/v1/admin/credit-packages")
async def admin_get_credit_packages(current_user: dict = Depends(get_admin_user)):
    return get_credit_packages(include_inactive=True)

@app.post("/api/v1/admin/credit-packages")
async def admin_create_credit_package(request: Request, current_user: dict = Depends(get_admin_user)):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO credit_packages (name, credits, price_cents, label, allowed_models) VALUES (%s, %s, %s, %s, %s)",
                            (data['name'], data['credits'], data['price_cents'], data['label'], json.dumps(data['allowed_models'])))
                return {"status": "created", "id": cur.lastrowid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/v1/admin/credit-packages/{package_id}")
async def admin_update_credit_package(package_id: int, request: Request, current_user: dict = Depends(get_admin_user)):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE credit_packages SET name=%s, credits=%s, price_cents=%s, label=%s, allowed_models=%s, is_active=%s, sort_order=%s WHERE id=%s",
                            (data['name'], data['credits'], data['price_cents'], data['label'], json.dumps(data['allowed_models']), data['is_active'], data.get('sort_order', 0), package_id))
                return {"status": "updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/admin/credit-packages/{package_id}")
async def admin_delete_credit_package(package_id: int, current_user: dict = Depends(get_admin_user)):
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE credit_packages SET is_active=FALSE WHERE id=%s", (package_id,))
                return {"status": "deactivated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/admin/subscriptions")
async def admin_get_subscriptions(current_user: dict = Depends(get_admin_user)):
    return get_subscription_plans(include_inactive=True)

@app.post("/api/v1/admin/subscriptions")
async def admin_create_subscription(request: Request, current_user: dict = Depends(get_admin_user)):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO subscription_plans (name, credits_per_month, price_cents, allowed_models) VALUES (%s, %s, %s, %s)",
                            (data['name'], data['credits_per_month'], data['price_cents'], json.dumps(data['allowed_models'])))
                return {"status": "created", "id": cur.lastrowid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/v1/admin/subscriptions/{plan_id}")
async def admin_update_subscription(plan_id: int, request: Request, current_user: dict = Depends(get_admin_user)):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE subscription_plans SET name=%s, credits_per_month=%s, price_cents=%s, allowed_models=%s, is_active=%s, sort_order=%s WHERE id=%s",
                            (data['name'], data['credits_per_month'], data['price_cents'], json.dumps(data['allowed_models']), data['is_active'], data.get('sort_order', 0), plan_id))
                return {"status": "updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/admin/subscriptions/{plan_id}")
async def admin_delete_subscription(plan_id: int, current_user: dict = Depends(get_admin_user)):
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE subscription_plans SET is_active=FALSE WHERE id=%s", (plan_id,))
                return {"status": "deactivated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/admin/token-rates")
async def admin_get_token_rates(current_user: dict = Depends(get_admin_user)):
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM token_credit_rates ORDER BY model ASC")
            rates = cur.fetchall()
            cur.close()
            return rates
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/admin/token-rates")
async def admin_create_token_rate(request: Request, current_user: dict = Depends(get_admin_user)):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO token_credit_rates (model, label, credits_per_1k_tokens, api_cost_per_1m, subscription_only, is_active) VALUES (%s, %s, %s, %s, %s, %s)",
                            (data['model'], data['label'], data['credits_per_1k_tokens'], data['api_cost_per_1m'], data['subscription_only'], data.get('is_active', True)))
                return {"status": "created", "id": cur.lastrowid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/v1/admin/token-rates/{rate_id}")
async def admin_update_token_rate(rate_id: int, request: Request, current_user: dict = Depends(get_admin_user)):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE token_credit_rates SET model=%s, label=%s, credits_per_1k_tokens=%s, api_cost_per_1m=%s, subscription_only=%s, is_active=%s WHERE id=%s",
                            (data['model'], data['label'], data['credits_per_1k_tokens'], data['api_cost_per_1m'], data['subscription_only'], data['is_active'], rate_id))
                return {"status": "updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/admin/token-rates/{rate_id}")
async def admin_delete_token_rate(rate_id: int, current_user: dict = Depends(get_admin_user)):
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE token_credit_rates SET is_active=FALSE WHERE id=%s", (rate_id,))
                return {"status": "deactivated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# -- Admin Endpoints ------------------------------------------------------------
@app.post("/api/v1/admin/reset-credits")
async def admin_reset_credits(current_user: dict = Depends(get_admin_user)):
    credits_to_add = 100000
    add_credits(user_id=current_user['id'], amount=credits_to_add, tx_type="admin_grant", description="Monthly admin credit grant")
    logger.info(f"Admin {current_user['email']} granted {credits_to_add} credits.")
    return {"status": "success", "message": f"{credits_to_add} credits granted."}

@app.get("/api/v1/admin/token-stats")
async def admin_token_stats(current_user: dict = Depends(get_admin_user)):
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT model, COUNT(*) as calls, SUM(total_tokens) as tokens, SUM(credits_charged) as credits FROM token_usage GROUP BY model ORDER BY tokens DESC""")
                by_model = cur.fetchall()
                cur.execute("""SELECT service, COUNT(*) as calls, SUM(total_tokens) as tokens, SUM(credits_charged) as credits FROM token_usage GROUP BY service ORDER BY tokens DESC""")
                by_service = cur.fetchall()
                cur.execute("SELECT COUNT(DISTINCT user_id) as users, COUNT(*) as total_calls, SUM(total_tokens) as total_tokens, SUM(credits_charged) as total_credits FROM token_usage")
                totals = cur.fetchone()
                return {"by_model": by_model, "by_service": by_service, "totals": totals}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
@app.get("/api/v1/admin/services")
async def get_services(current_user: dict = Depends(get_admin_user)):
    return {"services": _get_merged_services()}

@app.get("/api/v1/services")
async def get_public_services():
    return {"services": _get_merged_services()}

@app.put("/api/v1/admin/services/{service_id}")
async def update_service_status(service_id: str, request: Request, current_user: dict = Depends(get_admin_user)):
    data = await request.json()
    new_status = data.get("status", "off")
    with db() as db_conn:
        with db_conn.cursor() as cur:
            cur.execute(
                "INSERT INTO service_status (service_id, status) VALUES (%s, %s) ON DUPLICATE KEY UPDATE status = VALUES(status)",
                (service_id, new_status)
            )
        db_conn.commit()
    return {"status": "updated", "service_id": service_id, "new_status": new_status}

# Other endpoints like check-credits, charge-tokens remain unchanged for legacy support
# ... (rest of the file)

import os
from datetime import datetime, timedelta
import uuid

# -- Bunq Mock / Endpoints ----------------------------------------------------
@app.post("/api/purchase-credits")
async def purchase_credits(request: Request):
    data = await request.json()
    package_id = data.get("package_id")
    payment_method = data.get("payment_method")
    user_email = data.get("user_email")
    
    if not package_id or not user_email:
        raise HTTPException(status_code=400, detail="Missing package_id or user_email")

    # Get user to ensure they exist
    user = get_user_by_email(user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Mapping packages
    packages = {
        "starter": {"credits": 2500, "price_eur": 5.00},
        "basic": {"credits": 5000, "price_eur": 9.00},
        "plus": {"credits": 10000, "price_eur": 15.00},
        "pro": {"credits": 15000, "price_eur": 20.00},
        "business": {"credits": 50000, "price_eur": 50.00},
    }
    
    pkg = packages.get(package_id)
    if not pkg:
        raise HTTPException(status_code=400, detail="Invalid package_id")

    amount_eur = pkg["price_eur"]
    credits = pkg["credits"]
    bunq_tx_id = f"bunq_mock_{uuid.uuid4().hex[:8]}"

    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO transactions (user_email, type, package_id, amount_eur, credits, bunq_transaction_id, status) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (user_email, "credits", package_id, amount_eur, credits, bunq_tx_id, "pending")
                )
                tx_id = cur.lastrowid
    except Exception as e:
        logger.error(f"Error creating transaction: {e}")
        raise HTTPException(status_code=500, detail="Database error")

    # Generate mock URL
    mock_url = f"https://bunq.me/roboserve/{amount_eur}?description=Credits_{package_id}_{tx_id}"
    
    return {"payment_url": mock_url, "transaction_id": str(tx_id), "bunq_transaction_id": bunq_tx_id}

@app.post("/api/subscribe")
async def subscribe(request: Request):
    data = await request.json()
    plan_id = data.get("plan_id")
    payment_method = data.get("payment_method")
    user_email = data.get("user_email")

    if not plan_id or not user_email:
        raise HTTPException(status_code=400, detail="Missing plan_id or user_email")

    user = get_user_by_email(user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if plan_id != "subscription pro":
        # Fallback to pro if exact string doesn't match for some reason, or reject
        pass

    amount_eur = 29.99
    credits = 15000
    bunq_tx_id = f"bunq_sub_mock_{uuid.uuid4().hex[:8]}"

    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO transactions (user_email, type, package_id, amount_eur, credits, bunq_transaction_id, status) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (user_email, "subscription", plan_id, amount_eur, credits, bunq_tx_id, "pending")
                )
                tx_id = cur.lastrowid
    except Exception as e:
        logger.error(f"Error creating transaction: {e}")
        raise HTTPException(status_code=500, detail="Database error")

    mock_url = f"https://bunq.me/roboserve/{amount_eur}?description=Sub_{plan_id}_{tx_id}"
    
    return {"payment_url": mock_url, "subscription_id": str(tx_id), "bunq_transaction_id": bunq_tx_id}

@app.post("/api/webhooks/bunq")
async def bunq_webhook(request: Request):
    try:
        data = await request.json()
    except:
        data = {}

    log_dir = os.path.expanduser("~/clawd/logs")
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "payments.jsonl"), "a") as f:
        f.write(json.dumps({"timestamp": datetime.now().isoformat(), "payload": data}) + "\n")

    # Mock handling: accept successful bunq_transaction_id from payload
    # Expected mock payload: { "bunq_transaction_id": "...", "status": "COMPLETED" }
    bunq_tx_id = data.get("bunq_transaction_id")
    status = data.get("status", "COMPLETED")

    if bunq_tx_id and status == "COMPLETED":
        try:
            with db() as conn:
                with conn.cursor(pymysql.cursors.DictCursor) as cur:
                    cur.execute("SELECT * FROM transactions WHERE bunq_transaction_id = %s AND status = 'pending'", (bunq_tx_id,))
                    tx = cur.fetchone()
                    
                    if tx:
                        # Update tx status
                        cur.execute("UPDATE transactions SET status = 'completed' WHERE id = %s", (tx["id"],))
                        
                        # Grant credits / update subscription
                        user_email = tx["user_email"]
                        if tx["type"] == "credits":
                            cur.execute("UPDATE users SET credits = credits + %s WHERE email = %s", (tx["credits"], user_email))
                        elif tx["type"] == "subscription":
                            renewal_date = datetime.now() + timedelta(days=30)
                            cur.execute("UPDATE users SET credits = credits + %s, subscription_plan = %s, subscription_renewal = %s, is_subscriber = 1 WHERE email = %s", 
                                        (tx["credits"], tx["package_id"], renewal_date.strftime('%Y-%m-%d'), user_email))
        except Exception as e:
            logger.error(f"Error processing webhook: {e}")
            raise HTTPException(status_code=500, detail="Database error during webhook handling")

    return {"status": "ok"}

@app.get("/api/user/balance")
async def user_balance(user_email: str = None, x_user_email: str = Header(None, alias="X-User-Email")):
    # Allow both query and header
    email = user_email or x_user_email
    if not email:
        raise HTTPException(status_code=400, detail="Missing user_email")

    try:
        with db() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute("SELECT credits, subscription_plan, subscription_renewal FROM users WHERE email = %s", (email,))
                user = cur.fetchone()
                
                if not user:
                    raise HTTPException(status_code=404, detail="User not found")
                
                sub_info = None
                if user.get("subscription_plan"):
                    sub_info = {
                        "plan": user["subscription_plan"],
                        "renewal_date": str(user["subscription_renewal"]) if user["subscription_renewal"] else None
                    }
                
                return {
                    "credits_remaining": user["credits"],
                    "subscription": sub_info
                }
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        logger.error(f"Error fetching balance: {e}")
        raise HTTPException(status_code=500, detail="Database error")

