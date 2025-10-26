from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from app.verifier import verify_email, verify_bulk_emails
import asyncio, logging
from functools import lru_cache
import dns.resolver

# =========================
# APP CONFIG
# =========================
app = FastAPI(
    title="Bounso Email Verifier",
    version="3.2",
    description="High-accuracy SMTP verifier with timing, entropy, and ESP behavioral analysis."
)

# =========================
# LOGGING CONFIG
# =========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger(__name__)

# =========================
# MODELS
# =========================
class SingleEmailRequest(BaseModel):
    email: str

class BulkEmailRequest(BaseModel):
    emails: List[str]
    max_workers: int = 20

# =========================
# MX CACHE
# =========================
@lru_cache(maxsize=500)
def get_mx(domain: str):
    """Cache MX results to avoid repeated lookups"""
    try:
        mx = str(dns.resolver.resolve(domain, "MX")[0].exchange)
        return mx
    except Exception:
        return None

# =========================
# ROUTES
# =========================
@app.get("/")
def home():
    return {
        "message": "🚀 Bounso Email Verifier API is Live!",
        "version": "3.2",
        "endpoints": ["/verify", "/bulk"]
    }

@app.post("/verify")
async def verify_single(req: SingleEmailRequest):
    """Verify a single email address"""
    email = req.email.strip()
    if not email:
        raise HTTPException(status_code=400, detail="Empty email field")

    logger.info(f"Verifying single email: {email}")

    try:
        result = await asyncio.to_thread(verify_email, email)
    except Exception as e:
        logger.error(f"Error verifying {email}: {e}")
        raise HTTPException(status_code=500, detail="Internal verification error")

    # Compact summary for frontend
    summary = {
        "email": email,
        "status": result.get("Status"),
        "score": result.get("Score"),
        "deliverable": result.get("Deliverable"),
        "provider": result.get("Provider"),
    }

    return {"count": 1, "summary": summary, "details": result}


@app.post("/bulk")
async def verify_bulk(req: BulkEmailRequest):
    """Verify multiple emails in parallel"""
    if not req.emails:
        raise HTTPException(status_code=400, detail="No emails provided")

    logger.info(f"Bulk verification started for {len(req.emails)} emails")

    try:
        results = await asyncio.to_thread(verify_bulk_emails, req.emails, req.max_workers)
    except Exception as e:
        logger.error(f"Bulk verification error: {e}")
        raise HTTPException(status_code=500, detail="Bulk verification failed")

    # Summaries for frontend display
    summary = [
        {
            "email": r.get("email") or req.emails[i],
            "status": r.get("Status"),
            "score": r.get("Score"),
            "deliverable": r.get("Deliverable"),
            "provider": r.get("Provider"),
        }
        for i, r in enumerate(results)
    ]

    logger.info(f"Bulk verification completed: {len(results)} results")
    return {"count": len(results), "summary": summary, "details": results}
