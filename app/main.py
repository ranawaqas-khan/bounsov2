from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from app.verifier import verify_email, verify_bulk_emails
import asyncio
import logging

# =========================
# APP CONFIG
# =========================
app = FastAPI(
    title="Bounso Email Verifier",
    version="3.3",
    description="High-accuracy SMTP email verifier (Railway-safe)"
)

# =========================
# LOGGING
# =========================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =========================
# MODELS
# =========================
class SingleEmailRequest(BaseModel):
    email: str

class BulkEmailRequest(BaseModel):
    emails: List[str]
    max_workers: int = 8

# =========================
# ROUTES
# =========================
@app.get("/")
def home():
    return {
        "message": "🚀 Bounso Email Verifier API is Live!",
        "version": "3.3",
        "endpoints": ["/verify", "/bulk"]
    }

@app.post("/verify")
async def verify_single(req: SingleEmailRequest):
    email = req.email.strip()
    if not email:
        raise HTTPException(status_code=400, detail="Empty email field")

    try:
        result = await asyncio.to_thread(verify_email, email)
    except Exception as e:
        logger.error(f"Verify error: {e}")
        raise HTTPException(status_code=500, detail="Verification failed")

    return {"count": 1, "result": result}

@app.post("/bulk")
async def verify_bulk(req: BulkEmailRequest):
    if not req.emails:
        raise HTTPException(status_code=400, detail="No emails provided")

    try:
        results = await asyncio.to_thread(
            verify_bulk_emails,
            req.emails,
            req.max_workers
        )
    except Exception as e:
        logger.error(f"Bulk error: {e}")
        raise HTTPException(status_code=500, detail="Bulk verification failed")

    return {"count": len(results), "results": results}
