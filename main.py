from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import JSONResponse
import secrets

app = FastAPI(title="Public API", description="Public API with basic auth")

security = HTTPBasic()

USERNAME = "aparoksha"
PASSWORD = "aparoksha123"

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

@app.get("/")
async def root():
    return {"message": "Welcome to the Public API", "status": "running"}

@app.get("/public")
async def public_endpoint():
    return {"message": "This is a public endpoint - no auth required", "data": {"public": True}}

@app.get("/protected")
async def protected_endpoint(username: str = Depends(verify_credentials)):
    return {
        "message": f"Hello {username}! This is a protected endpoint",
        "data": {"protected": True, "user": username}
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)