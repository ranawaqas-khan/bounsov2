from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
from app.verifier import verify_email, verify_bulk_emails

# =========================
# APP CONFIG
# =========================
app = FastAPI(
    title="Bounso v2 - AI Email Verifier",
    version="2.0",
    description="Advanced multi-threaded email verification API with timing + entropy heuristics."
)

# =========================
# REQUEST MODELS
# =========================
class SingleEmailRequest(BaseModel):
    email: str

class BulkEmailRequest(BaseModel):
    emails: List[str]

# =========================
# ROUTES
# =========================
@app.get("/")
def root():
    """
    Root endpoint to confirm the API is running.
    """
    return {
        "message": "🚀 Bounso v2 Email Verification API is running!",
        "version": "2.0",
        "author": "Seedhub / Rana Muhammad Waqas"
    }


@app.post("/verify")
async def verify_single(request: SingleEmailRequest):
    """
    Verify a single email address.
    Returns status, confidence, timing delta, entropy, provider, MX info, and score.
    """
    result = verify_email(request.email)
    return {
        "count": 1,
        "results": [result]
    }


@app.post("/bulk")
async def verify_bulk(request: BulkEmailRequest):
    """
    Verify multiple emails in parallel using multi-threaded execution.
    Each email result includes deliverability, timing, entropy, and confidence scoring.
    """
    results = verify_bulk_emails(request.emails)
    return {
        "count": len(results),
        "results": results
    }


@app.get("/health")
def health_check():
    """
    Health check endpoint for uptime monitoring.
    """
    return {"status": "ok", "service": "Bounso Email Verifier"}
