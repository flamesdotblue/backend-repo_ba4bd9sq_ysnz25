import os
import time
import secrets
import hashlib
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId
import requests

from database import db, create_document, get_documents
from schemas import Account, Session as SessionSchema, Feedback as FeedbackSchema

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY_V1")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
SESSION_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------- Helpers ----------------------

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + SESSION_TTL_SECONDS
    create_document("session", SessionSchema(user_id=user_id, token=token, expires_at=expires_at))
    return token


def get_user_by_token(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    if not authorization:
        return None
    if not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    session = db["session"].find_one({"token": token})
    if not session:
        return None
    if session.get("expires_at", 0) < time.time():
        db["session"].delete_one({"_id": session["_id"]})
        return None
    user = db["account"].find_one({"_id": ObjectId(session["user_id"])})
    return user


def require_auth(user = Depends(get_user_by_token)):
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user


def require_admin(user = Depends(require_auth)):
    if not user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def call_openai(prompt: str, instruction: Optional[str] = None) -> Optional[str]:
    if not OPENAI_API_KEY:
        return None
    try:
        # Use Chat Completions API
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }
        messages = []
        if instruction:
            messages.append({"role": "system", "content": instruction})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model": OPENAI_MODEL,
            "messages": messages,
            "temperature": 0.2,
        }
        resp = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
        else:
            return None
    except Exception:
        return None


def simple_summary(text: str, max_chars: int = 280) -> str:
    text = " ".join(text.strip().split())
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."

# ---------------------- Models ----------------------

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    token: str
    name: str
    email: EmailStr
    is_admin: bool
    is_premium: bool

class FeedbackCreateRequest(BaseModel):
    name: str
    email: EmailStr
    message: str

class FeedbackListItem(BaseModel):
    id: str
    name: str
    email: EmailStr
    message: str
    summary: Optional[str] = None
    suggested_response: Optional[str] = None
    tags: List[str] = []
    status: str
    created_at: Optional[str] = None

class FeedbackUpdateRequest(BaseModel):
    tags: Optional[List[str]] = None
    status: Optional[str] = None

# ---------------------- Routes ----------------------

@app.get("/")
def read_root():
    return {"message": "Feedback AI backend running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_name"] = getattr(db, "name", "✅ Connected")
            response["connection_status"] = "Connected"
            try:
                response["collections"] = db.list_collection_names()[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    import os
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

# Auth
@app.post("/auth/register", response_model=AuthResponse)
def register(body: RegisterRequest):
    if db["account"].find_one({"email": body.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    salt = secrets.token_hex(8)
    password_hash = hash_password(body.password, salt)
    user = Account(name=body.name, email=body.email, password_hash=password_hash, salt=salt)
    user_id = create_document("account", user)
    token = create_session(user_id)
    return AuthResponse(token=token, name=user.name, email=user.email, is_admin=False, is_premium=False)

@app.post("/auth/login", response_model=AuthResponse)
def login(body: LoginRequest):
    doc = db["account"].find_one({"email": body.email})
    if not doc:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    expected = hash_password(body.password, doc.get("salt", ""))
    if expected != doc.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session(str(doc["_id"]))
    return AuthResponse(
        token=token,
        name=doc.get("name", ""),
        email=doc.get("email", ""),
        is_admin=bool(doc.get("is_admin", False)),
        is_premium=bool(doc.get("is_premium", False)),
    )

@app.get("/auth/me")
def me(user = Depends(require_auth)):
    return {
        "name": user.get("name"),
        "email": user.get("email"),
        "is_admin": bool(user.get("is_admin", False)),
        "is_premium": bool(user.get("is_premium", False)),
    }

@app.post("/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        return {"ok": True}
    token = authorization.split(" ", 1)[1].strip()
    db["session"].delete_one({"token": token})
    return {"ok": True}

# Feedback
@app.post("/feedback", response_model=FeedbackListItem)
def submit_feedback(body: FeedbackCreateRequest, user = Depends(get_user_by_token)):
    # AI summary and suggestion
    instruction = "You are an assistant that summarizes customer feedback into 1-2 concise sentences."
    summary = call_openai(body.message, instruction) or simple_summary(body.message)

    suggest_sys = "You generate a short, polite support reply to the given customer feedback."
    suggested = call_openai(body.message, suggest_sys) or "Thank you for the feedback! We'll review this and get back to you shortly."

    fb = FeedbackSchema(
        user_id=str(user["_id"]) if user else None,
        name=body.name,
        email=body.email,
        message=body.message,
        summary=summary,
        suggested_response=suggested,
        tags=[],
        status="new",
    )
    fb_id = create_document("feedback", fb)
    doc = db["feedback"].find_one({"_id": ObjectId(fb_id)})
    return FeedbackListItem(
        id=fb_id,
        name=doc["name"],
        email=doc["email"],
        message=doc["message"],
        summary=doc.get("summary"),
        suggested_response=doc.get("suggested_response"),
        tags=doc.get("tags", []),
        status=doc.get("status", "new"),
        created_at=str(doc.get("created_at")) if doc.get("created_at") else None,
    )

@app.get("/admin/feedbacks", response_model=List[FeedbackListItem])
def list_feedbacks(admin = Depends(require_admin)):
    items: List[FeedbackListItem] = []
    for doc in db["feedback"].find().sort("created_at", -1):
        items.append(FeedbackListItem(
            id=str(doc["_id"]),
            name=doc.get("name", ""),
            email=doc.get("email", ""),
            message=doc.get("message", ""),
            summary=doc.get("summary"),
            suggested_response=doc.get("suggested_response"),
            tags=doc.get("tags", []),
            status=doc.get("status", "new"),
            created_at=str(doc.get("created_at")) if doc.get("created_at") else None,
        ))
    return items

@app.patch("/admin/feedbacks/{feedback_id}")
def update_feedback(feedback_id: str, body: FeedbackUpdateRequest, admin = Depends(require_admin)):
    update: Dict[str, Any] = {}
    if body.tags is not None:
        update["tags"] = body.tags
    if body.status is not None:
        update["status"] = body.status
    if not update:
        return {"ok": True}
    update["updated_at"] = time.time()
    res = db["feedback"].update_one({"_id": ObjectId(feedback_id)}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Feedback not found")
    return {"ok": True}

@app.post("/admin/feedbacks/{feedback_id}/suggestion")
def regenerate_suggestion(feedback_id: str, admin = Depends(require_admin)):
    doc = db["feedback"].find_one({"_id": ObjectId(feedback_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Feedback not found")
    suggest_sys = "You generate a short, polite support reply to the given customer feedback."
    suggested = call_openai(doc.get("message", ""), suggest_sys) or "Thank you for the feedback! We'll review this and get back to you shortly."
    db["feedback"].update_one({"_id": doc["_id"]}, {"$set": {"suggested_response": suggested, "updated_at": time.time()}})
    return {"suggested_response": suggested}

# Billing (simple upgrade toggle)
@app.post("/billing/upgrade")
def upgrade_to_premium(user = Depends(require_auth)):
    db["account"].update_one({"_id": user["_id"]}, {"$set": {"is_premium": True}})
    return {"ok": True, "is_premium": True}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
