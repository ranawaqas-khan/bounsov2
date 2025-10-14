from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.verifier import verify_email

# =========
# FastAPI
# =========
app = FastAPI(
    title="Bounso v2 – Email Verifier",
    version="2.1",
    description="Single-probe Outlook/Gmail-safe verifier with rich JSON and bulk threading."
)

# CORS (allow your domains + Clay)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://bounso.com",
        "https://www.bounso.com",
        "https://clay.run",
        "https://www.clay.run",
        "*",  # if you want to test freely; tighten in prod
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========
# Models
# =========
class SingleEmailRequest(BaseModel):
    email: str = Field(..., example="name@company.com")

class BulkEmailRequest(BaseModel):
    emails: List[str] = Field(..., example=["a@b.com", "c@d.com"])
    max_workers: Optional[int] = Field(20, ge=1, le=64, description="Thread pool size")


# =========
# Routes
# =========
@app.get("/")
def root():
    return {
        "message": "🚀 Bounso v2 Email Verification API is running!",
        "version": "2.1",
        "endpoints": ["/verify", "/bulk", "/health"]
    }

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/verify")
def verify(request: SingleEmailRequest):
    """
    Verify a single email address.
    Returns only 'deliverable' or 'undeliverable', with a score and rich details.
    """
    return {"count": 1, "results": [verify_email(request.email)]}

@app.post("/bulk")
def bulk_verify(request: BulkEmailRequest):
    """
    Multi-threaded bulk verification.
    - Uses one RCPT probe per email
    - Thread pool size configurable via `max_workers`
    """
    emails = [e.strip() for e in request.emails if e and isinstance(e, str)]
    results = []
    with ThreadPoolExecutor(max_workers=request.max_workers or 20) as pool:
        futures = {pool.submit(verify_email, e): e for e in emails}
        for f in as_completed(futures):
            results.append(f.result())

    return {"count": len(results), "results": results}
