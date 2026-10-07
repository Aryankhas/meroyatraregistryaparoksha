from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import secrets
import uuid
from datetime import datetime

app = FastAPI(title="Business Registry API", description="Public Business Registry with Basic Auth")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBasic()
USERNAME = "aparoksha"
PASSWORD = "aparoksha123"

# In-memory storage (replace with DB later)
businesses_db = {}
users_db = {"aparoksha": "aparoksha123"}  # username: password

# Models
class BusinessCreate(BaseModel):
    name: str
    owner_name: str
    email: EmailStr
    phone: Optional[str] = None
    address: str
    category: str
    description: Optional[str] = None

class BusinessUpdate(BaseModel):
    name: Optional[str] = None
    owner_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None

class Business(BaseModel):
    id: str
    name: str
    owner_name: str
    email: str
    phone: Optional[str] = None
    address: str
    category: str
    description: Optional[str] = None
    created_at: str
    updated_at: str

class BusinessListResponse(BaseModel):
    businesses: List[Business]
    total: int

# Auth
def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, USERNAME)
    correct_password = secrets.compare_digest(credentials.password, PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# Public endpoints (no auth)
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return open("frontend/index.html").read()

@app.get("/api/health")
async def health():
    return {"status": "healthy", "service": "business-registry"}

@app.get("/api/businesses", response_model=BusinessListResponse)
async def list_businesses(
    category: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    """Public: List all businesses with optional filtering"""
    results = list(businesses_db.values())
    
    if category:
        results = [b for b in results if b["category"].lower() == category.lower()]
    if search:
        search_lower = search.lower()
        results = [b for b in results if search_lower in b["name"].lower() or search_lower in b["description"].lower() or search_lower in b["category"].lower()]
    
    total = len(results)
    results = results[offset:offset + limit]
    
    return {"businesses": results, "total": total}

@app.get("/api/businesses/{business_id}", response_model=Business)
async def get_business(business_id: str):
    """Public: Get single business"""
    if business_id not in businesses_db:
        raise HTTPException(status_code=404, detail="Business not found")
    return businesses_db[business_id]

@app.get("/api/categories")
async def get_categories():
    """Public: Get all categories"""
    categories = list(set(b["category"] for b in businesses_db.values()))
    return {"categories": sorted(categories)}

# Protected endpoints (require auth)
@app.post("/api/businesses", response_model=Business, status_code=201)
async def create_business(business: BusinessCreate, username: str = Depends(verify_credentials)):
    """Create new business (requires auth)"""
    business_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().isoformat()
    
    new_business = {
        "id": business_id,
        "name": business.name,
        "owner_name": business.owner_name,
        "email": business.email,
        "phone": business.phone,
        "address": business.address,
        "category": business.category,
        "description": business.description,
        "created_at": now,
        "updated_at": now
    }
    businesses_db[business_id] = new_business
    return new_business

@app.put("/api/businesses/{business_id}", response_model=Business)
async def update_business(business_id: str, update: BusinessUpdate, username: str = Depends(verify_credentials)):
    """Update business (requires auth)"""
    if business_id not in businesses_db:
        raise HTTPException(status_code=404, detail="Business not found")
    
    business = businesses_db[business_id]
    update_data = update.model_dump(exclude_unset=True)
    
    for key, value in update_data.items():
        business[key] = value
    
    business["updated_at"] = datetime.utcnow().isoformat()
    return business

@app.delete("/api/businesses/{business_id}")
async def delete_business(business_id: str, username: str = Depends(verify_credentials)):
    """Delete business (requires auth)"""
    if business_id not in businesses_db:
        raise HTTPException(status_code=404, detail="Business not found")
    del businesses_db[business_id]
    return {"message": "Business deleted", "id": business_id}

# Sample data on startup
@app.on_event("startup")
async def seed_data():
    sample_businesses = [
        {
            "id": "demo001",
            "name": "Aparoksha Tech Solutions",
            "owner_name": "Aparoksha",
            "email": "contact@aparoksha.tech",
            "phone": "+91-9876543210",
            "address": "123 Tech Park, Bangalore, Karnataka 560001",
            "category": "Technology",
            "description": "Software development and IT consulting services",
            "created_at": "2024-01-15T10:00:00",
            "updated_at": "2024-01-15T10:00:00"
        },
        {
            "id": "demo002",
            "name": "Green Gardens Nursery",
            "owner_name": "Rajesh Kumar",
            "email": "rajesh@greengardens.in",
            "phone": "+91-9876543211",
            "address": "45 Garden Road, Pune, Maharashtra 411001",
            "category": "Agriculture",
            "description": "Organic plants, seeds, and gardening supplies",
            "created_at": "2024-01-20T14:30:00",
            "updated_at": "2024-01-20T14:30:00"
        },
        {
            "id": "demo003",
            "name": "Spice Route Restaurant",
            "owner_name": "Priya Sharma",
            "email": "priya@spiceroute.com",
            "phone": "+91-9876543212",
            "address": "78 Food Street, Mumbai, Maharashtra 400001",
            "category": "Food & Beverage",
            "description": "Authentic Indian cuisine with modern twist",
            "created_at": "2024-02-01T09:00:00",
            "updated_at": "2024-02-01T09:00:00"
        }
    ]
    for biz in sample_businesses:
        businesses_db[biz["id"]] = biz

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)