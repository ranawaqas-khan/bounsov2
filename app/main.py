from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
import asyncio
from concurrent.futures import ThreadPoolExecutor
from app.verifier import verify_email

executor = ThreadPoolExecutor(max_workers=100)
app = FastAPI(title="Email Verifier API", version="3.0")

class EmailPayload(BaseModel):
    emails: List[str]

@app.post("/verify")
async def verify_bulk(payload: EmailPayload):
    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(executor, verify_email, e) for e in payload.emails]
    results = await asyncio.gather(*tasks)
    return {"results": results, "count": len(results)}
