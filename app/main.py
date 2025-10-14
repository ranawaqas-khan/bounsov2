from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
from app.verifier import verify_email, verify_bulk_emails

app = FastAPI(
    title="Bounso Email Verifier",
    version="3.0",
    description="High-accuracy SMTP verifier with entropy + catch-all detection"
)

class SingleEmailRequest(BaseModel):
    email: str

class BulkEmailRequest(BaseModel):
    emails: List[str]
    max_workers: int = 20

@app.get("/")
def home():
    return {"message": "🚀 Bounso Email Verifier API is Live!", "version": "3.0"}

@app.post("/verify")
async def verify_single(req: SingleEmailRequest):
    return {"count": 1, "results": [verify_email(req.email)]}

@app.post("/bulk")
async def verify_bulk(req: BulkEmailRequest):
    results = verify_bulk_emails(req.emails, req.max_workers)
    return {"count": len(results), "results": results}
