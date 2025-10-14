"""
FastAPI Application for Bounso.com Email Verification
Endpoints: /verify (single) and /bulk (parallel processing)
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, validator
from typing import List, Optional
from datetime import datetime

# Import verification logic
from verifier import EmailVerifier

# =========================
# APP INITIALIZATION
# =========================
app = FastAPI(
    title="Bounso Email Verifier API",
    description="High-speed email verification with deliverability scoring",
    version="1.0.0"
)

# CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Production mein specific domains add karna
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# PYDANTIC MODELS
# =========================
class EmailVerifyRequest(BaseModel):
    email: EmailStr

class BulkVerifyRequest(BaseModel):
    emails: List[EmailStr]
    
    @validator('emails')
    def check_limit(cls, v):
        if len(v) > 1000:
            raise ValueError('Maximum 1000 emails per request')
        if len(v) == 0:
            raise ValueError('At least 1 email required')
        return v

class EmailVerifyResponse(BaseModel):
    email: str
    status: str  # "deliverable" or "undeliverable"
    score: int  # 0-100
    reason: Optional[str] = None
    
    # Classification
    email_type: str  # "free", "role", "business", "government"
    is_free: bool
    is_role: bool
    is_disposable: bool
    
    # Technical details
    mx_provider: str
    mx_records: List[str]
    smtp_code: Optional[int] = None
    
    # Metadata
    domain: str
    verified_at: str
    processing_time_ms: int

class BulkVerifyResponse(BaseModel):
    total: int
    deliverable: int
    undeliverable: int
    results: List[EmailVerifyResponse]
    processing_time_ms: int

# =========================
# API ENDPOINTS
# =========================

@app.get("/")
async def root():
    """API health check"""
    return {
        "service": "Bounso Email Verifier",
        "status": "active",
        "version": "1.0.0",
        "endpoints": {
            "verify": "/verify - Single email verification",
            "bulk": "/bulk - Bulk verification (up to 1000 emails)",
            "health": "/health - Health check"
        },
        "documentation": "/docs"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "email-verifier"
    }

@app.post("/verify", response_model=EmailVerifyResponse)
async def verify_email(request: EmailVerifyRequest):
    """
    Verify a single email address
    
    Returns:
    - deliverability score (0-100)
    - status (deliverable/undeliverable)
    - email classification (free/role/business/government)
    - MX provider information
    
    Example:
    ```
    POST /verify
    {
        "email": "test@gmail.com"
    }
    ```
    """
    try:
        result = EmailVerifier.verify_single(request.email)
        return EmailVerifyResponse(**result)
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Verification failed: {str(e)}"
        )

@app.post("/bulk", response_model=BulkVerifyResponse)
async def verify_bulk(request: BulkVerifyRequest):
    """
    Verify multiple emails in parallel (up to 1000 emails)
    
    High-speed processing with 50 concurrent threads
    
    Example:
    ```
    POST /bulk
    {
        "emails": [
            "user1@gmail.com",
            "user2@yahoo.com",
            "user3@business.com"
        ]
    }
    ```
    
    Returns:
    - Summary statistics (total, deliverable, undeliverable)
    - Individual results for each email
    - Total processing time
    """
    try:
        result = EmailVerifier.verify_bulk(request.emails)
        return BulkVerifyResponse(**result)
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Bulk verification failed: {str(e)}"
        )

# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
