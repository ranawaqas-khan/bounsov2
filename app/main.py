from fastapi import FastAPI, Request
from verifier import verify_email
from typing import List

app = FastAPI(title="Bounso v2 Email Verifier", version="2.0")

@app.get("/")
def root():
    return {"message": "🚀 Bounso v2 Email Verification API is running!"}

@app.post("/verify")
async def verify_single(payload: dict):
    email = payload.get("email")
    if not email:
        return {"error": "email is required"}
    result = verify_email(email)
    return {"results": [result], "count": 1}

@app.post("/bulk")
async def verify_bulk(payload: dict):
    emails = payload.get("emails", [])
    if not isinstance(emails, list):
        if isinstance(emails, str):
            emails = [e.strip() for e in emails.split(",") if e.strip()]
        else:
            return {"error": "emails must be a list or comma-separated string"}
    results = [verify_email(email) for email in emails]
    return {"results": results, "count": len(results)}
