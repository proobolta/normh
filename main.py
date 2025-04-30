import os
import json
import re
import smtplib
import dns.resolver
import logging
import concurrent.futures
import time
import uuid
import asyncio
from pathlib import Path
from typing import List, Dict, Optional, Any, Union
from enum import Enum
import certifi
from datetime import datetime, timedelta
from bson import ObjectId

import aiofiles
from dotenv import load_dotenv
from pymongo import MongoClient, IndexModel, ASCENDING, DESCENDING
from fastapi import FastAPI, File, UploadFile, BackgroundTasks, HTTPException, Depends, Query, Form, status, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, field_validator
from passlib.context import CryptContext
import jwt
from starlette.requests import Request

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("email_validator_api.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("email_validator_api")
cer = certifi.where() #access certi:
# App configuration
APP_NAME = "Email Validator API"
VERSION = "1.0.0"
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

# MongoDB Setup
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb+srv://username:password@cluster.mongodb.net/email_validator")
client = MongoClient(MONGODB_URI, tlsCAFile = cer, connect=False, tls=True) #connect mongo:
db = client.email_validator
users_collection = db.users
rate_limits_collection = db.rate_limits
jobs_collection = db.jobs
verification_collection = db.verifications
cached_domains_collection = db.cached_domains

# Create indexes for performance
users_collection.create_index("email", unique=True)
rate_limits_collection.create_index([("user_id", ASCENDING), ("timestamp", DESCENDING)])
jobs_collection.create_index("user_id")
jobs_collection.create_index("status")
jobs_collection.create_index("created_at")
verification_collection.create_index("token", unique=True)
verification_collection.create_index("expires_at")
cached_domains_collection.create_index("domain", unique=True)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# Disposable domains list
DISPOSABLE_DOMAINS = [
    "mailinator.com", "trashmail.com", "yopmail.com", "10minutemail.com",
    "guerrillamail.com", "temporarymail.com", "dispostable.com", "throwawaymail.com",
    "fakeinbox.com", "mailnesia.com", "mailcatch.com", "tempmail.net"
]

# Create FastAPI app
app = FastAPI(
    title=APP_NAME,
    description="API for validating email addresses in bulk with user signup and premium features",
    version=VERSION
)

origins = [
    "http://localhost:3000",
    "https://localhost:5000",
    "http://localhost",
    "https://normil.vercel.app",
]

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create data directory for uploads and results
DATA_DIR = Path("data")
UPLOADS_DIR = DATA_DIR / "uploads"
RESULTS_DIR = DATA_DIR / "results"

for directory in [DATA_DIR, UPLOADS_DIR, RESULTS_DIR]:
    directory.mkdir(exist_ok=True, parents=True)

# Plan and User Models
class PlanType(str, Enum):
    FREE = "free"
    STANDARD = "standard"
    PREMIUM = "premium"
class Role(str, Enum):
    USER = "user"
    ADMIN = "admin"

# Plan limits
PLAN_LIMITS = {
    PlanType.FREE: {
        "hourly_limit": 1000,
        "concurrent_jobs": 2,
        "max_file_size_mb": 5,
        "history_days": 7,
        "features": ["Basic validation", "Email format check", "Disposable email detection"]
    },
    PlanType.STANDARD: {
        "hourly_limit": 5000,
        "concurrent_jobs": 5,
        "max_file_size_mb": 20,
        "history_days": 30,
        "features": ["Advanced validation", "MX record check", "SMTP verification", "Export to CSV/Excel"]
    },
    PlanType.PREMIUM: {
        "hourly_limit": 20000,
        "concurrent_jobs": 10,
        "max_file_size_mb": 50,
        "history_days": 90, 
        "features": ["Premium validation", "Catch-all detection", "Role account detection", "API access", "Premium text conversion"]
    }
}

class ValidationStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class ValidationReason(str, Enum):
    VALID = "valid"
    INVALID_FORMAT = "invalid_format"
    DISPOSABLE = "disposable_email"
    NO_MX_RECORD = "no_mx_record"
    NO_RESPONSE = "no_response"
    CATCH_ALL = "catch_all"
    ROLE_ACCOUNT = "role_account"
    OTHER = "other"

# User models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None
    
    @field_validator('password')
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

class User(BaseModel):
    id: str
    email: EmailStr
    name: Optional[str] = None
    email_verified: bool
    role: Role = Role.USER
    created_at: datetime
    plan: PlanType
    plan_expires_at: Optional[datetime] = None

class UserInDB(BaseModel):
    id: str
    email: EmailStr
    name: Optional[str] = None
    hashed_password: str
    email_verified: bool = False
    role: Role = Role.USER
    disabled: bool = False
    created_at: datetime
    updated_at: datetime
    plan: PlanType = PlanType.FREE
    plan_expires_at: Optional[datetime] = None
    
    class Config:
        from_attribute = True

class UserResponse(BaseModel):
    user: User
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime

class EmailResult(BaseModel):
    email: str
    is_valid: bool
    reason: ValidationReason = ValidationReason.VALID
    details: Optional[str] = None
    checked_at: datetime = Field(default_factory=datetime.utcnow)

class ValidationJob(BaseModel):
    id: str
    user_id: str
    status: ValidationStatus
    progress: float = 0
    total_emails: int
    valid_count: int = 0
    invalid_count: int = 0
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    file_name: Optional[str] = None
    error: Optional[str] = None

class ValidationRequest(BaseModel):
    emails: List[str]

class ValidationResponse(BaseModel):
    job_id: str
    status: ValidationStatus
    progress: float = 0
    total_emails: int
    valid_count: Optional[int] = None
    invalid_count: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    download_links: Optional[Dict[str, str]] = None

class UserStats(BaseModel):
    total_jobs: int
    total_validations: int
    valid_emails: int
    invalid_emails: int
    hourly_usage: List[Dict[str, Any]]
    quota_remaining: int
    plan_details: Dict[str, Any]

class TextConversionRequest(BaseModel):
    text: str
    style: str = "standard"  # standard, premium, bold

# Authentication Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_email(email: str) -> Optional[UserInDB]:
    user_dict = users_collection.find_one({"email": email})
    if user_dict:
        return UserInDB(
            id=str(user_dict["_id"]),
            email=user_dict["email"],
            name=user_dict.get("name"),
            hashed_password=user_dict["hashed_password"],
            email_verified=user_dict.get("email_verified", False),
            disabled=user_dict.get("disabled", False),
            created_at=user_dict["created_at"],
            updated_at=user_dict["updated_at"],
            role=user_dict.get("role", Role.USER),
            plan=user_dict.get("plan", PlanType.FREE),
            plan_expires_at=user_dict.get("plan_expires_at")
        )
    return None

def get_user_by_id(user_id: str) -> Optional[UserInDB]:
    if not ObjectId.is_valid(user_id):
        return None
        
    user_dict = users_collection.find_one({"_id": ObjectId(user_id)})
    if user_dict:
        return UserInDB(
            id=str(user_dict["_id"]),
            email=user_dict["email"],
            name=user_dict.get("name"),
            hashed_password=user_dict["hashed_password"],
            email_verified=user_dict.get("email_verified", False),
            disabled=user_dict.get("disabled", False),
            created_at=user_dict["created_at"],
            updated_at=user_dict["updated_at"],
            role=user_dict.get("user", Role.USER),
            plan=user_dict.get("plan", PlanType.FREE),
            plan_expires_at=user_dict.get("plan_expires_at")
        )
    return None

def authenticate_user(email: str, password: str) -> Optional[UserInDB]:
    user = get_user_by_email(email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict) -> tuple[str, datetime]:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, expire

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session expired or invalid. Please log in again.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
        
    user = get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
        
    # Update last login time
    users_collection.update_one(
        {"_id": ObjectId(user.id)}, 
        {"$set": {"last_login": datetime.utcnow()}}
    )
        
    return user

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    if current_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )
    return current_user

# Email validation functions
def is_valid_email_format(email: str) -> bool:
    """Validate the format of the email address."""
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

def is_disposable_email(email: str) -> bool:
    """Check if the email domain is disposable."""
    try:
        domain = email.split('@')[-1].lower()
        return domain in DISPOSABLE_DOMAINS
    except Exception as e:
        logger.error(f"Error checking disposable email: {e}")
        return False

def is_role_account(email: str) -> bool:
    """Check if the email is a role account."""
    try:
        local_part = email.split('@')[0].lower()
        role_accounts = [
            "admin", "administrator", "webmaster", "hostmaster", "postmaster",
            "info", "support", "sales", "contact", "hello", "marketing", "team",
            "help", "mail", "office", "hr", "jobs", "noreply", "no-reply"
        ]
        return local_part in role_accounts
    except Exception as e:
        logger.error(f"Error checking role account: {e}")
        return False

def check_mx_records(domain: str) -> bool:
    """Check if the domain has MX records."""
    # Check cache first
    cached_domain = cached_domains_collection.find_one({"domain": domain})
    
    if cached_domain and (datetime.utcnow() - cached_domain["updated_at"]).days < 7:
        return cached_domain["has_mx"]
    
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        has_mx = len(mx_records) > 0
        
        # Update cache
        cached_domains_collection.update_one(
            {"domain": domain},
            {
                "$set": {
                    "has_mx": has_mx,
                    "mx_records": [str(r.exchange) for r in mx_records] if has_mx else [],
                    "updated_at": datetime.utcnow()
                }
            },
            upsert=True
        )
        
        return has_mx
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        # Update cache with negative result
        cached_domains_collection.update_one(
            {"domain": domain},
            {"$set": {"has_mx": False, "updated_at": datetime.utcnow()}},
            upsert=True
        )
        return False
    except Exception as e:
        logger.error(f"Error checking MX records for {domain}: {e}")
        return False

def check_smtp_connection(email: str, domain: str, timeout: int = 5) -> tuple[bool, str]:
    """Check if the email exists using SMTP connection."""
    try:
        # Get MX records from cache
        cached_domain = cached_domains_collection.find_one({"domain": domain})
        if not cached_domain or not cached_domain.get("has_mx", False):
            return False, "No MX records"
            
        mx_host = cached_domain.get("mx_records", [])[0] if cached_domain.get("mx_records") else None
        if not mx_host:
            # Try to resolve directly
            mx_records = dns.resolver.resolve(domain, 'MX')
            if not mx_records:
                return False, "No MX records"
            mx_host = str(mx_records[0].exchange)
        
        # Connect with timeout
        server = smtplib.SMTP(timeout=timeout)
        server.connect(mx_host, 25)
        server.helo()
        server.mail('validator@example.com')
        code, message = server.rcpt(email)
        server.quit()
        
        if code == 250:
            return True, "Valid"
        elif code == 550:
            return False, "Mailbox does not exist"
        else:
            return False, f"SMTP error: {code}"
            
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False, "No MX records"
    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, smtplib.SMTPResponseException):
        return False, "SMTP connection error"
    except TimeoutError:
        return False, "Connection timeout"
    except Exception as e:
        logger.error(f"Error checking SMTP for {email}: {e}")
        return False, str(e)

def validate_email(email: str) -> EmailResult:
    """Validate an email and return detailed results."""
    if not email or not isinstance(email, str):
        return EmailResult(
            email=email if isinstance(email, str) else str(email),
            is_valid=False,
            reason=ValidationReason.INVALID_FORMAT,
            details="Invalid input"
        )
    
    email = email.strip().lower()
    
    # Format validation
    if not is_valid_email_format(email):
        return EmailResult(
            email=email,
            is_valid=False,
            reason=ValidationReason.INVALID_FORMAT,
            details="Email format is invalid"
        )
    
    # Disposable email check
    if is_disposable_email(email):
        return EmailResult(
            email=email,
            is_valid=False,
            reason=ValidationReason.DISPOSABLE,
            details="Disposable email address"
        )
    
    # Role account check
    if is_role_account(email):
        return EmailResult(
            email=email,
            is_valid=False,
            reason=ValidationReason.ROLE_ACCOUNT,
            details="Role-based email address"
        )
    
    # Extract domain
    domain = email.split('@')[-1]
    
    # MX record check
    if not check_mx_records(domain):
        return EmailResult(
            email=email,
            is_valid=False,
            reason=ValidationReason.NO_MX_RECORD,
            details="Domain has no mail server (MX) records"
        )
    
    # SMTP check
    smtp_valid, smtp_message = check_smtp_connection(email, domain)
    if not smtp_valid:
        return EmailResult(
            email=email,
            is_valid=False,
            reason=ValidationReason.NO_RESPONSE,
            details=smtp_message
        )
    
    # If we got here, the email is valid
    return EmailResult(
        email=email,
        is_valid=True,
        reason=ValidationReason.VALID,
        details="Email is valid"
    )

async def validate_emails_batch(job_id: str, emails: List[str], batch_size: int = 100):
    """Process a batch of emails with progress tracking."""
    try:
        # Get job
        job = jobs_collection.find_one({"_id": job_id})
        if not job or job["status"] not in ["queued", "processing"]:
            logger.error(f"Invalid job status for {job_id}")
            return False
            
        # Update job status to processing
        jobs_collection.update_one(
            {"_id": job_id},
            {"$set": {"status": "processing", "updated_at": datetime.utcnow()}}
        )
        
        total = len(emails)
        valid_count = 0
        invalid_count = 0
        results = []
        
        # Process in batches
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for i in range(0, total, batch_size):
                batch = emails[i:i+batch_size]
                
                # Submit batch for processing
                future_results = list(executor.map(validate_email, batch))
                
                # Process results
                for result in future_results:
                    results.append(result.dict())
                    if result.is_valid:
                        valid_count += 1
                    else:
                        invalid_count += 1
                
                # Update progress
                progress = min(100, (i + len(batch)) / total * 100)
                jobs_collection.update_one(
                    {"_id": job_id},
                    {
                        "$set": {
                            "progress": progress,
                            "valid_count": valid_count,
                            "invalid_count": invalid_count,
                            "updated_at": datetime.utcnow()
                        }
                    }
                )
                
                # Brief pause to avoid overwhelming the system
                await asyncio.sleep(0.1)
        
        # Save results
        result_path = RESULTS_DIR / job_id
        result_path.mkdir(exist_ok=True)
        
        # Save valid emails
        valid_emails = [r["email"] for r in results if r["is_valid"]]
        with open(result_path / "valid_emails.txt", "w") as f:
            f.write("\n".join(valid_emails))
            
        # Save invalid emails with reasons
        invalid_emails = [f"{r['email']} - {r['reason']} - {r['details']}" for r in results if not r["is_valid"]]
        with open(result_path / "invalid_emails.txt", "w") as f:
            f.write("\n".join(invalid_emails))
            
        # Save all results as JSON
        with open(result_path / "results.json", "w") as f:
            json.dump(results, f, indent=2, default=str)
            
        # Update job as completed
        jobs_collection.update_one(
            {"_id": job_id},
            {
                "$set": {
                    "status": "completed",
                    "progress": 100,
                    "valid_count": valid_count,
                    "invalid_count": invalid_count,
                    "completed_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        return True
        
    except Exception as e:
        logger.error(f"Error processing job {job_id}: {str(e)}")
        # Update job as failed
        jobs_collection.update_one(
            {"_id": job_id},
            {
                "$set": {
                    "status": "failed",
                    "error": str(e),
                    "updated_at": datetime.utcnow()
                }
            }
        )
        return False

# Rate limiting function
async def check_rate_limit(user: UserInDB, count: int = 1) -> tuple[bool, int]:
    """
    Check if user has exceeded their rate limit
    Returns: (is_allowed, remaining_quota)
    """
    current_time = datetime.utcnow()
    one_hour_ago = current_time - timedelta(hours=1)
    
    # Get plan limits
    plan_limits = PLAN_LIMITS.get(user.plan, PLAN_LIMITS[PlanType.FREE])
    hourly_limit = plan_limits["hourly_limit"]
    
    # Get current usage in the last hour
    pipeline = [
        {"$match": {"user_id": user.id, "timestamp": {"$gte": one_hour_ago}}},
        {"$group": {"_id": None, "total": {"$sum": "$count"}}}
    ]
    
    result = list(rate_limits_collection.aggregate(pipeline))
    current_usage = result[0]["total"] if result else 0
    
    # Check if adding this count would exceed limit
    remaining = max(0, hourly_limit - current_usage)
    if current_usage + count > hourly_limit:
        return False, remaining
    
    # Record this usage
    rate_limits_collection.insert_one({
        "user_id": user.id,
        "count": count,
        "timestamp": current_time
    })
    
    return True, hourly_limit - current_usage - count

async def check_concurrent_jobs(user: UserInDB) -> bool:
    """Check if user has exceeded their concurrent job limit"""
    # Get plan limits
    plan_limits = PLAN_LIMITS.get(user.plan, PLAN_LIMITS[PlanType.FREE])
    max_concurrent = plan_limits["concurrent_jobs"]
    
    # Count active jobs
    active_jobs = jobs_collection.count_documents({
        "user_id": user.id,
        "status": {"$in": ["queued", "processing"]}
    })
    
    return active_jobs < max_concurrent

async def enforce_rate_limit(user: UserInDB, count: int = 1):
    """Enforce rate limit and raise exception if exceeded"""
    # Check concurrent jobs
    if not await check_concurrent_jobs(user):
        plan_limits = PLAN_LIMITS.get(user.plan, PLAN_LIMITS[PlanType.FREE])
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"You have reached the maximum concurrent jobs limit ({plan_limits['concurrent_jobs']}) for your plan"
        )
    
    # Check rate limit
    allowed, remaining = await check_rate_limit(user, count)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. You can validate {remaining} more emails in the current hour"
        )
    
    return remaining

# Email sending functions (mocked for simplicity)
async def send_welcome_email(email: str, name: Optional[str] = None):
    """Send welcome email to new users"""
    logger.info(f"Welcome email would be sent to {email}")
    return True

async def send_verification_email(email: str, name: Optional[str] = None, token: str = None):
    """Send email verification to new users"""
    logger.info(f"Verification email would be sent to {email} with token {token}")
    return True

async def send_password_reset_email(email: str, name: Optional[str] = None, token: str = None):
    """Send password reset email"""
    logger.info(f"Password reset email would be sent to {email} with token {token}")
    return True

# Premium Text Conversion Feature
def convert_text_to_premium(text: str, style: str = "standard") -> str:
    """
    Convert text to premium formatted text
    Available styles: standard, premium, bold
    """
    if style == "premium":
        # Convert to "100% Free" premium style
        return f"★ 100% FREE ★ {text} ★ PREMIUM VALIDATED ★"
    elif style == "bold":
        # Add bold formatting with asterisks (for markdown)
        return f"**{text}** - Verified Premium"
    else:
        # Default standard premium formatting
        return f"{text} ✓ Validated"

# Routes
@app.get("/", include_in_schema=False)
async def root():
    return {"message": "Email Validator API", "version": VERSION}
@app.get("/health")
def health_check():
    return {"status": "healthy"}

# Authentication routes
@app.post("/auth/token", response_model=UserResponse)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login
    users_collection.update_one(
        {"_id": ObjectId(user.id)},
        {"$set": {"last_login": datetime.utcnow()}}
    )
    
    # Create access token
    token, expires_at = create_access_token({"sub": user.id})
    
    # Convert to response model
    user_response = User(
        id=user.id,
        email=user.email,
        name=user.name,
        email_verified=user.email_verified,
        created_at=user.created_at,
        role=user.role,
        plan=user.plan,
        plan_expires_at=user.plan_expires_at
    )
    
    return UserResponse(
        user=user_response,
        access_token=token,
        expires_at=expires_at
    )

# User routes
@app.post("/users/signup", response_model=UserResponse)
async def create_user(user: UserCreate, background_tasks: BackgroundTasks):
    # Check if user already exists
    existing_user = users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered. Please log in instead."
        )
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    user_id = ObjectId()
    
    # Create verification token
    verification_token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=3)
    
    # Store verification
    verification_collection.insert_one({
        "email": user.email,
        "token": verification_token,
        "expires_at": expires_at
    })
    
    # Create user object
    now = datetime.utcnow()
    user_data = {
        "_id": user_id,
        "email": user.email,
        "name": user.name,
        "hashed_password": hashed_password,
        "email_verified": False,
        "disabled": False,
        "created_at": now,
        "updated_at": now,
        "role": Role.USER,
        "plan": PlanType.FREE,
        "last_login": now
    }
    
    # Insert user
    users_collection.insert_one(user_data)
    
    # Send verification email
    background_tasks.add_task(
        send_verification_email,
        user.email,
        user.name,
        verification_token
    )
    
    # Send welcome email
    background_tasks.add_task(
        send_welcome_email,
        user.email,
        user.name
    )
    
    # Create access token - auto login!
    token, expires_at = create_access_token({"sub": str(user_id)})
    
    # Create response
    user_response = User(
        id=str(user_id),
        email=user.email,
        name=user.name,
        email_verified=False,
        created_at=now,
        role=Role.USER,
        plan=PlanType.FREE
    )
    
    return UserResponse(
        user=user_response,
        access_token=token,
        expires_at=expires_at
    )

@app.post("/users/verify/{token}")
async def verify_email(token: str):
    # Find verification
    verification = verification_collection.find_one({
        "token": token,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    
    if not verification:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token"
        )
    
    # Update user
    result = users_collection.update_one(
        {"email": verification["email"]},
        {"$set": {"email_verified": True, "updated_at": datetime.utcnow()}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found"
        )
    
    # Remove verification
    verification_collection.delete_one({"_id": verification["_id"]})
    
    return {"message": "Email verified successfully"}

@app.get("/users/me", response_model=User)
async def get_current_user_info(current_user: UserInDB = Depends(get_current_active_user)):
    return User(
        id=current_user.id,
        email=current_user.email,
        name=current_user.name,
        email_verified=current_user.email_verified,
        created_at=current_user.created_at,
        plan=current_user.plan,
        plan_expires_at=current_user.plan_expires_at
    )

# Dashboard route
@app.get("/dashboard", response_model=UserStats)
async def get_user_stats(current_user: UserInDB = Depends(get_current_active_user)):
    """Get usage statistics for the current user"""
    user_id = current_user.id
    current_time = datetime.utcnow()
    
    # Get job statistics
    completed_jobs = jobs_collection.find(
        {"user_id": user_id, "status": "completed"},
        {"total_emails": 1, "valid_count": 1, "invalid_count": 1}
    )
    
    # Convert cursor to list
    completed_jobs_list = list(completed_jobs)
    
    # Calculate stats
    total_jobs = len(completed_jobs_list)
    total_validations = sum(job.get("total_emails", 0) for job in completed_jobs_list)
    valid_emails = sum(job.get("valid_count", 0) for job in completed_jobs_list)
    invalid_emails = sum(job.get("invalid_count", 0) for job in completed_jobs_list)
    
    # Get hourly usage for the last 24 hours
    hourly_usage = []
    for hour in range(24):
        hour_start = current_time - timedelta(hours=hour+1)
        hour_end = current_time - timedelta(hours=hour)
        
        pipeline = [
            {"$match": {
                "user_id": user_id,
                "timestamp": {"$gte": hour_start, "$lt": hour_end}
            }},
            {"$group": {"_id": None, "count": {"$sum": "$count"}}}
        ]
        
        result = list(rate_limits_collection.aggregate(pipeline))
        count = result[0]["count"] if result else 0
        
        hourly_usage.append({
            "hour": hour_start.strftime("%H:00"),
            "count": count
        })
   
    # Get remaining quota
    plan_limits = PLAN_LIMITS.get(current_user.plan, PLAN_LIMITS[PlanType.FREE])
    current_hour_usage = hourly_usage[0]["count"] if hourly_usage else 0
    remaining = max(0, plan_limits["hourly_limit"] - current_hour_usage)
    
    return UserStats(
        total_jobs=total_jobs,
        total_validations=total_validations,
        valid_emails=valid_emails,
        invalid_emails=invalid_emails,
        hourly_usage=hourly_usage,
        quota_remaining=remaining,
        plan_details=plan_limits
    )

# Email validation routes
@app.post("/validate/email", response_model=ValidationResponse)
async def validate_single_email(
    email: str,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Validate a single email address"""
    # Enforce rate limit
    await enforce_rate_limit(current_user, 1)
    
    # Create job
    job_id = str(uuid.uuid4())
    now = datetime.utcnow()
    job = {
        "_id": job_id,
        "user_id": current_user.id,
        "status": ValidationStatus.QUEUED,
        "progress": 0,
        "total_emails": 1,
        "valid_count": 0,
        "invalid_count": 0,
        "created_at": now,
        "updated_at": now
    }
    
    # Insert job
    jobs_collection.insert_one(job)
    
    # Start validation in background
    background_tasks.add_task(validate_emails_batch, job_id, [email])
    
    return ValidationResponse(
        job_id=job_id,
        status=ValidationStatus.QUEUED,
        progress=0,
        total_emails=1,
        created_at=now
    )

@app.post("/validate/emails", response_model=ValidationResponse)
async def validate_multiple_emails(
    request: ValidationRequest,
    background_tasks: BackgroundTasks,
    max_workers: int = Query(5, gt=0, le=20),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Validate multiple email addresses"""
    email_count = len(request.emails)
    
    # Enforce rate limit
    await enforce_rate_limit(current_user, email_count)
    
    # Create job
    job_id = str(uuid.uuid4())
    now = datetime.utcnow()
    job = {
        "_id": job_id,
        "user_id": current_user.id,
        "status": ValidationStatus.QUEUED,
        "progress": 0,
        "total_emails": email_count,
        "valid_count": 0,
        "invalid_count": 0,
        "created_at": now,
        "updated_at": now
    }
    
    # Insert job
    jobs_collection.insert_one(job)
    
    # Start validation in background
    background_tasks.add_task(validate_emails_batch, job_id, request.emails)
    
    return ValidationResponse(
        job_id=job_id,
        status=ValidationStatus.QUEUED,
        progress=0,
        total_emails=email_count,
        created_at=now
    )

@app.post("/validate/upload", response_model=ValidationResponse)
async def validate_from_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    max_workers: int = Form(5, gt=0, le=20),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Upload a file with emails and validate them"""
    # Check file extension
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ['.json', '.txt', '.csv']:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file format. Please upload .json, .txt, or .csv files."
        )
    
    # Get plan limits
    plan_limits = PLAN_LIMITS.get(current_user.plan, PLAN_LIMITS[PlanType.FREE])
    
    # Generate upload path
    file_id = str(uuid.uuid4())
    file_path = UPLOADS_DIR / f"{file_id}{file_ext}"
    
    # Save file
    try:
        content = await file.read()
        
        # Check file size
        max_size = plan_limits["max_file_size_mb"] * 1024 * 1024  # Convert MB to bytes
        if len(content) > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size for your plan is {plan_limits['max_file_size_mb']}MB"
            )
        
        # Save to disk
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(content)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save file: {str(e)}"
        )
    
    # Extract emails
    emails = []
    try:
        if file_ext == '.json':
            async with aiofiles.open(file_path, mode='r') as f:
                content = await f.read()
                data = json.loads(content)
                if isinstance(data, dict) and "emails" in data:
                    emails = data["emails"]
                elif isinstance(data, list):
                    emails = data
        elif file_ext == '.txt':
            async with aiofiles.open(file_path, mode='r') as f:
                content = await f.read()
                emails = [line.strip() for line in content.split('\n') if line.strip()]
        elif file_ext == '.csv':
            import csv
            async with aiofiles.open(file_path, mode='r') as f:
                content = await f.read()
                reader = csv.reader(content.splitlines())
                for row in reader:
                    if row and row[0]:
                        emails.append(row[0].strip())
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse file: {str(e)}"
        )
    
    # Check if there are emails to validate
    if not emails:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid emails found in the file"
        )
    
    # Enforce rate limit
    await enforce_rate_limit(current_user, len(emails))
    
    # Create job
    job_id = str(uuid.uuid4())
    now = datetime.utcnow()
    job = {
        "_id": job_id,
        "user_id": current_user.id,
        "status": ValidationStatus.QUEUED,
        "progress": 0,
        "total_emails": len(emails),
        "valid_count": 0,
        "invalid_count": 0,
        "file_name": file.filename,
        "file_path": str(file_path),
        "created_at": now,
        "updated_at": now
    }
    
    # Insert job
    jobs_collection.insert_one(job)
    
    # Start validation in background
    background_tasks.add_task(validate_emails_batch, job_id, emails)
    
    return ValidationResponse(
        job_id=job_id,
        status=ValidationStatus.QUEUED,
        progress=0,
        total_emails=len(emails),
        created_at=now
    )

@app.get("/jobs/{job_id}", response_model=ValidationResponse)
async def get_job_status(
    job_id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Get the status of a validation job"""
    job = jobs_collection.find_one({"_id": job_id, "user_id": current_user.id})
    
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found"
        )
    
    # Prepare download links if job is completed
    download_links = None
    if job["status"] == ValidationStatus.COMPLETED:
        base_url = "/jobs/download"
        download_links = {
            "valid": f"{base_url}/{job_id}/valid",
            "invalid": f"{base_url}/{job_id}/invalid",
            "all": f"{base_url}/{job_id}/all"
        }
    
    return ValidationResponse(
        job_id=job_id,
        status=job["status"],
        progress=job["progress"],
        total_emails=job["total_emails"],
        valid_count=job.get("valid_count"),
        invalid_count=job.get("invalid_count"),
        created_at=job["created_at"],
        completed_at=job.get("completed_at"),
        download_links=download_links
    )

@app.get("/jobs")
async def list_jobs(
    limit: int = Query(10, gt=0, le=100),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """List recent validation jobs"""
    jobs = jobs_collection.find(
        {"user_id": current_user.id}, 
        {"_id": 1, "status": 1, "progress": 1, "total_emails": 1, "valid_count": 1, 
         "invalid_count": 1, "created_at": 1, "completed_at": 1}
    ).sort("created_at", -1).limit(limit)
    
    result = []
    for job in jobs:
        # Create download links for completed jobs
        download_links = None
        if job["status"] == ValidationStatus.COMPLETED:
            base_url = "/jobs/download"
            download_links = {
                "valid": f"{base_url}/{job['_id']}/valid",
                "invalid": f"{base_url}/{job['_id']}/invalid",
                "all": f"{base_url}/{job['_id']}/all"
            }
            
        result.append({
            "job_id": job["_id"],
            "status": job["status"],
            "progress": job["progress"],
            "total_emails": job["total_emails"],
            "valid_count": job.get("valid_count"),
            "invalid_count": job.get("invalid_count"),
            "created_at": job["created_at"],
            "completed_at": job.get("completed_at"),
            "download_links": download_links
        })
    
    return result

@app.get("/jobs/download/{job_id}/{result_type}")
async def download_results(
    job_id: str,
    result_type: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Download validation results"""
    job = jobs_collection.find_one({"_id": job_id, "user_id": current_user.id})
    
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found"
        )
    
    if job["status"] != ValidationStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Job is not completed yet"
        )
    
    # Determine file path based on result type
    result_file = None
    if result_type == "valid":
        result_file = RESULTS_DIR / job_id / "valid_emails.txt"
    elif result_type == "invalid":
        result_file = RESULTS_DIR / job_id / "invalid_emails.txt"
    elif result_type == "all":
        result_file = RESULTS_DIR / job_id / "results.json"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid result type. Use 'valid', 'invalid', or 'all'"
        )
    
    if not result_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No {result_type} results found for this job"
        )
    
    return FileResponse(
        path=result_file,
        filename=result_file.name,
        media_type="text/plain" if result_type != "all" else "application/json"
    )

# Premium text conversion feature (Only for premium users)
@app.post("/premium/convert-text")
async def convert_text(
    request: TextConversionRequest,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Convert text to premium format (Premium users only)"""
    if current_user.plan != PlanType.PREMIUM:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This feature is only available for Premium users"
        )
    
    # Convert the text using our premium converter
    converted_text = convert_text_to_premium(request.text, request.style)
    
    return {
        "original_text": request.text,
        "converted_text": converted_text,
        "style": request.style
    }

# Plan upgrade route
@app.post("/users/upgrade-plan/{plan_type}")
async def upgrade_plan(
    plan_type: PlanType,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Upgrade user plan (mock implementation)"""
    if plan_type not in [PlanType.FREE, PlanType.STANDARD, PlanType.PREMIUM]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid plan type"
        )
    
    # In a real implementation, this would handle payment
    # But for this example, we'll just update the plan
    
    # Update user plan
    users_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {
            "$set": {
                "plan": plan_type,
                "plan_expires_at": datetime.utcnow() + timedelta(days=30),
                "updated_at": datetime.utcnow()
            }
        }
    )
    
    return {
        "message": f"Successfully upgraded to {plan_type} plan",
        "plan": plan_type,
        "expires_at": datetime.utcnow() + timedelta(days=30),
        "features": PLAN_LIMITS[plan_type]["features"]
    }

# Run app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)