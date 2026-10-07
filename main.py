from fastapi import FastAPI, Depends, HTTPException, status, Request, UploadFile, File, Form
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from sqlalchemy import create_engine, Column, String, DateTime, Text, Boolean, Integer
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from sqlalchemy.sql import func
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
import secrets
import uuid
import base64
import os

# --- Config ---
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production-12345678901234567890")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
DATABASE_URL = "sqlite:///./business_registry.db"

# --- Database ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())

class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), nullable=False, index=True)
    key_hash = Column(String(255), nullable=False)
    name = Column(String(100))
    last_used = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)

class Business(Base):
    __tablename__ = "businesses"
    id = Column(String(8), primary_key=True, default=lambda: str(uuid.uuid4())[:8])
    name = Column(String(200), nullable=False)
    owner_name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    phone = Column(String(30), nullable=True)
    address = Column(Text, nullable=False)
    category = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    image_base64 = Column(Text, nullable=True)
    created_by = Column(String(36), nullable=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

Base.metadata.create_all(bind=engine)

def business_to_dict(b: Business) -> dict:
    return {
        "id": b.id,
        "name": b.name,
        "owner_name": b.owner_name,
        "email": b.email,
        "phone": b.phone,
        "address": b.address,
        "category": b.category,
        "description": b.description,
        "image_base64": b.image_base64,
        "created_by": b.created_by,
        "created_at": b.created_at.isoformat() if b.created_at else None,
        "updated_at": b.updated_at.isoformat() if b.updated_at else None
    }

# --- Security ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security_basic = HTTPBasic()
security_bearer = HTTPBearer(auto_error=False)

# --- FastAPI App ---
app = FastAPI(title="Business Registry API", description="Complete Business Registry with Auth, API Keys, Image Upload")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Auth Helpers ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def hash_api_key(key: str) -> str:
    return pwd_context.hash(key)

def verify_api_key(plain_key: str, hashed_key: str) -> bool:
    return pwd_context.verify(plain_key, hashed_key)

def generate_api_key() -> str:
    return "br_" + secrets.token_urlsafe(32)

# --- Current User ---
async def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = auth_header.split(" ")[1]
    
    # Try JWT first
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id:
            user = db.query(User).filter(User.id == user_id).first()
            if user and user.is_active:
                return user
    except JWTError:
        pass
    
    # Try API Key
    api_keys = db.query(APIKey).all()
    for ak in api_keys:
        if verify_api_key(token, ak.key_hash):
            user = db.query(User).filter(User.id == ak.user_id).first()
            if user and user.is_active:
                ak.last_used = datetime.now(timezone.utc)
                db.commit()
                return user
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

async def get_current_admin(user = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# --- Pydantic Models ---
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class APIKeyCreate(BaseModel):
    name: str
    expires_days: Optional[int] = None

class APIKeyResponse(BaseModel):
    id: str
    name: str
    key: str  # Only shown once!
    created_at: str
    expires_at: Optional[str]

class BusinessCreate(BaseModel):
    name: str
    owner_name: str
    email: EmailStr
    phone: Optional[str] = None
    address: str
    category: str
    description: Optional[str] = None
    image_base64: Optional[str] = None

class BusinessUpdate(BaseModel):
    name: Optional[str] = None
    owner_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    image_base64: Optional[str] = None

from datetime import datetime

class BusinessResponse(BaseModel):
    id: str
    name: str
    owner_name: str
    email: str
    phone: Optional[str]
    address: str
    category: str
    description: Optional[str]
    image_base64: Optional[str]
    created_by: str
    created_at: str
    updated_at: str

class BusinessListResponse(BaseModel):
    businesses: List[BusinessResponse]
    total: int

class CategoryResponse(BaseModel):
    categories: List[str]

# --- Startup: Create default admin ---
@app.on_event("startup")
async def startup():
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "aparoksha").first()
        if not admin:
            admin = User(
                username="aparoksha",
                email="admin@aparoksha.local",
                hashed_password=get_password_hash("aparoksha123"),
                is_admin=True
            )
            db.add(admin)
            db.commit()
            print("Created default admin: aparoksha / aparoksha123")
        
        # Seed sample businesses if empty
        if db.query(Business).count() == 0:
            sample = [
                Business(id="demo001", name="Aparoksha Tech Solutions", owner_name="Aparoksha", email="contact@aparoksha.tech", phone="+91-9876543210", address="123 Tech Park, Bangalore, Karnataka 560001", category="Technology", description="Software development and IT consulting services", created_by=admin.id),
                Business(id="demo002", name="Green Gardens Nursery", owner_name="Rajesh Kumar", email="rajesh@greengardens.in", phone="+91-9876543211", address="45 Garden Road, Pune, Maharashtra 411001", category="Agriculture", description="Organic plants, seeds, and gardening supplies", created_by=admin.id),
                Business(id="demo003", name="Spice Route Restaurant", owner_name="Priya Sharma", email="priya@spiceroute.com", phone="+91-9876543212", address="78 Food Street, Mumbai, Maharashtra 400001", category="Food & Beverage", description="Authentic Indian cuisine with modern twist", created_by=admin.id),
            ]
            for b in sample:
                db.add(b)
            db.commit()
    finally:
        db.close()

# --- Public Endpoints ---
@app.get("/api/health")
async def health():
    return {"status": "healthy", "service": "business-registry", "version": "2.0"}

@app.get("/api/businesses")
async def list_businesses(
    category: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(Business)
    if category:
        query = query.filter(Business.category.ilike(category))
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (Business.name.ilike(search_term)) |
            (Business.description.ilike(search_term)) |
            (Business.category.ilike(search_term))
        )
    total = query.count()
    businesses = query.order_by(Business.created_at.desc()).offset(offset).limit(limit).all()
    return {"businesses": [business_to_dict(b) for b in businesses], "total": total}

@app.get("/api/businesses/{business_id}", response_model=BusinessResponse)
async def get_business(business_id: str, db: Session = Depends(get_db)):
    business = db.query(Business).filter(Business.id == business_id).first()
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")
    return business_to_dict(business)

@app.get("/api/categories", response_model=CategoryResponse)
async def get_categories(db: Session = Depends(get_db)):
    categories = db.query(Business.category).distinct().all()
    return {"categories": sorted([c[0] for c in categories])}

# --- Auth Endpoints ---
@app.post("/api/auth/register", response_model=Token)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    token = create_access_token({"sub": user.id})
    return {"access_token": token, "user": {"id": user.id, "username": user.username, "email": user.email, "is_admin": user.is_admin}}

@app.post("/api/auth/login", response_model=Token)
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    
    token = create_access_token({"sub": user.id})
    return {"access_token": token, "user": {"id": user.id, "username": user.username, "email": user.email, "is_admin": user.is_admin}}

@app.get("/api/auth/me")
async def get_me(user = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "email": user.email, "is_admin": user.is_admin}

# --- API Key Endpoints ---
@app.post("/api/auth/api-keys", response_model=APIKeyResponse)
async def create_api_key(key_data: APIKeyCreate, user = Depends(get_current_user), db: Session = Depends(get_db)):
    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    expires_at = datetime.now(timezone.utc) + timedelta(days=key_data.expires_days) if key_data.expires_days else None
    
    api_key = APIKey(
        user_id=user.id,
        key_hash=key_hash,
        name=key_data.name,
        expires_at=expires_at
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    
    return {
        "id": api_key.id,
        "name": api_key.name,
        "key": raw_key,  # Only returned once!
        "created_at": api_key.created_at.isoformat(),
        "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None
    }

@app.get("/api/auth/api-keys")
async def list_api_keys(user = Depends(get_current_user), db: Session = Depends(get_db)):
    keys = db.query(APIKey).filter(APIKey.user_id == user.id).all()
    return [{
        "id": k.id,
        "name": k.name,
        "last_used": k.last_used.isoformat() if k.last_used else None,
        "created_at": k.created_at.isoformat(),
        "expires_at": k.expires_at.isoformat() if k.expires_at else None
    } for k in keys]

@app.delete("/api/auth/api-keys/{key_id}")
async def delete_api_key(key_id: str, user = Depends(get_current_user), db: Session = Depends(get_db)):
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == user.id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    db.delete(key)
    db.commit()
    return {"message": "API key deleted"}

# --- Business CRUD (Protected) ---
@app.post("/api/businesses", response_model=BusinessResponse, status_code=201)
async def create_business(business: BusinessCreate, user = Depends(get_current_user), db: Session = Depends(get_db)):
    business_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc)
    
    new_business = Business(
        id=business_id,
        name=business.name,
        owner_name=business.owner_name,
        email=business.email,
        phone=business.phone,
        address=business.address,
        category=business.category,
        description=business.description,
        image_base64=business.image_base64,
        created_by=user.id,
        created_at=now,
        updated_at=now
    )
    db.add(new_business)
    db.commit()
    db.refresh(new_business)
    return business_to_dict(new_business)

@app.put("/api/businesses/{business_id}", response_model=BusinessResponse)
async def update_business(business_id: str, update: BusinessUpdate, user = Depends(get_current_user), db: Session = Depends(get_db)):
    business = db.query(Business).filter(Business.id == business_id).first()
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")
    
    update_data = update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(business, key, value)
    
    business.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(business)
    return business_to_dict(business)

@app.delete("/api/businesses/{business_id}")
async def delete_business(business_id: str, user = Depends(get_current_user), db: Session = Depends(get_db)):
    business = db.query(Business).filter(Business.id == business_id).first()
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")
    db.delete(business)
    db.commit()
    return {"message": "Business deleted", "id": business_id}

# --- Image Upload (Base64) ---
@app.post("/api/upload/image")
async def upload_image(file: UploadFile = File(...), user = Depends(get_current_user)):
    # Validate file type
    allowed_types = ["image/jpeg", "image/png", "image/gif", "image/webp"]
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail="Invalid image type. Use JPEG, PNG, GIF, or WebP")
    
    # Read and encode
    contents = await file.read()
    if len(contents) > 5 * 1024 * 1024:  # 5MB limit
        raise HTTPException(status_code=400, detail="Image too large (max 5MB)")
    
    base64_str = base64.b64encode(contents).decode('utf-8')
    data_url = f"data:{file.content_type};base64,{base64_str}"
    
    return {"image_base64": data_url, "size": len(contents), "type": file.content_type}

# --- Admin Endpoints ---
@app.get("/api/admin/users")
async def list_users(admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [{
        "id": u.id, "username": u.username, "email": u.email,
        "is_active": u.is_active, "is_admin": u.is_admin, "created_at": u.created_at.isoformat()
    } for u in users]

@app.put("/api/admin/users/{user_id}")
async def update_user(user_id: str, is_active: Optional[bool] = None, is_admin: Optional[bool] = None, admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot modify yourself")
    if is_active is not None:
        user.is_active = is_active
    if is_admin is not None:
        user.is_admin = is_admin
    db.commit()
    return {"message": "User updated", "user": {"id": user.id, "username": user.username, "is_active": user.is_active, "is_admin": user.is_admin}}

@app.get("/api/admin/stats")
async def admin_stats(admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    return {
        "total_users": db.query(User).count(),
        "total_businesses": db.query(Business).count(),
        "total_api_keys": db.query(APIKey).count(),
        "categories": len(db.query(Business.category).distinct().all())
    }

# --- Serve Frontend ---
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return open("frontend/index.html").read()

@app.get("/user", response_class=HTMLResponse)
async def serve_user_dashboard():
    return open("frontend/user.html").read()

@app.get("/admin", response_class=HTMLResponse)
async def serve_admin_panel():
    return open("frontend/admin.html").read()

# --- Run ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)