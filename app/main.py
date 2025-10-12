from fastapi import FastAPI
from pydantic import BaseModel
from app.verifier import verify_email
from typing import List

app = FastAPI(title="Bounso v2 Email Verifier", version="2.0")

# --- ✅ Define input schemas ---
class SingleEmailRequest(BaseModel):
    email: str

class BulkEmailRequest(BaseModel):
    emails: List[str]


@app.get("/")
def root():
    return {"message": "🚀 Bounso v2 Email Verification API is running!"}


@app.post("/verify")
async def verify_single(request: SingleEmailRequest):
    """Verify a single email"""
    result = verify_email(request.email)
    return {"results": result, "count": 1}


@app.post("/bulk")
async def verify_bulk(request: BulkEmailRequest):
    """Verify multiple emails"""
    emails = request.emails
    results = [verify_email(email) for email in emails]
    return {"results": results, "count": len(results)}
