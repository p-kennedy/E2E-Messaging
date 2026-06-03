import os
import sys
import datetime

from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

import jwt
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from pydantic import BaseModel
from passlib.context import CryptContext
from blockchain_service import record_digest_on_chain
from concurrent.futures import ThreadPoolExecutor
from blockchain_service import get_record_by_tx

_executor = ThreadPoolExecutor(max_workers=2)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "database"))
from connection import init_pool
import crud

app = FastAPI()
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24


# ── Models ────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    password: str
    public_key: str

class LoginRequest(BaseModel):
    username: str
    password: str

class SendMessageRequest(BaseModel):
    recipient: str
    ciphertext: str
    nonce: str
    header: str
    signature: str
    digest: str

class UploadOpksRequest(BaseModel):
    opk_pubs: list[dict]


# ── Auth helpers ──────────────────────────────────────────────────────────────

def make_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/api/auth/register", status_code=201)
def register(req: RegisterRequest):
    if crud.get_user_by_username(req.username):
        raise HTTPException(status_code=409, detail="Username already taken")
    password_hash = pwd_context.hash(req.password)
    user = crud.create_user(req.username, password_hash, req.public_key)
    return {"user_id": str(user["user_id"]), "username": user["username"]}

@app.post("/api/auth/login")
def login(req: LoginRequest):
    user = crud.get_user_by_username(req.username)
    if not user or not pwd_context.verify(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": make_token(str(user["user_id"]))}

@app.get("/api/users/me/opk-count")
def opk_count(user_id: str = Depends(get_current_user)):
    return {"count": crud.get_opk_count(user_id)}

@app.post("/api/users/me/opks", status_code=201)
def upload_opks(req: UploadOpksRequest, user_id: str = Depends(get_current_user)):
    new_total = crud.append_one_time_prekeys(user_id, req.opk_pubs)
    return {"total": new_total}

@app.get("/api/users/{username}/prekey-bundle")
def get_prekey_bundle(username: str, _: str = Depends(get_current_user)):
    bundle = crud.get_prekey_bundle_with_opk(username)
    if bundle is None:
        raise HTTPException(status_code=404, detail="User not found")
    return bundle


@app.post("/api/messages", status_code=201)
def send_message(req: SendMessageRequest, user_id: str = Depends(get_current_user)):
    recipient = crud.get_user_by_username(req.recipient)
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    # Save msg to DB first
    msg = crud.create_message(
        sender_id=user_id,
        recipient_id=str(recipient["user_id"]),
        content_ciphertext=req.ciphertext,
        nonce=req.nonce,
        header=req.header,
        signature=req.signature,
        digest=req.digest,
    )

    #Record on blockchain (in background)
    def anchor():
        try:
            tx_hash = record_digest_on_chain(req.digest)
            crud.update_blockchain_tx_hash(str(msg["message_id"]), tx_hash)
        except Exception as e:
            print(f"[Blockchain] Failed to anchor message {msg['message_id']}: {e}")

    print(f"[Blockchain] Submitting anchor job for message {msg['message_id']}")
    _executor.submit(anchor)
            
    return {"status": "queued"}

@app.get("/api/messages")
def fetch_messages(user_id: str = Depends(get_current_user)):
    messages = crud.get_messages_for_recipient(user_id)
    return {"messages": [
        {
            "message_id":         str(m["message_id"]),
            "sender_id":          str(m["sender_id"]),
            "recipient_id":       str(m["recipient_id"]),
            "ciphertext":         m["content_ciphertext"],
            "nonce":              m["nonce"],
            "header":             m["header"],
            "signature":          m["signature"],
            "digest":             m["digest"],
            "blockchain_tx_hash": m["blockchain_tx_hash"],
            "created_at":         str(m["created_at"]),
        }
        for m in messages
    ]}

#── Verification on Blockchain ────────────────────────────────────────────────────────────────

@app.get("/api/verify")
def verify(tx_hash: str):
    try:
        result = get_record_by_tx(tx_hash)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.get("/verify")
def verification_page():
    return FileResponse(os.path.join(os.path.dirname(__file__), "verify.html"))


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_pool()
