from typing import Optional
from fastapi import HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError, ExpiredSignatureError
import random
import pytz
import supabase

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "w!nQ8d2k@zY$L9uP#mT6rX5bB0hG1cFj"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def generate_otp():
    return str(random.randint(100000, 999999))

def get_token_from_db(user_id: str):
    response = supabase.table("tokens").select("token").eq("user_id", user_id).single().execute()
    return response.data["token"] if response.data else None

def verify_otp(email: str, otp: str, client_timezone: str = None) -> bool:
    otp_info = supabase.table("otp-request").select("*").eq("email", email).execute().data
    if not otp_info:
        raise HTTPException(status_code=400, detail="Mã OTP chưa được yêu cầu.")
    if str(otp_info[0]["otp"]) != str(otp):
        raise HTTPException(status_code=400, detail="Mã OTP không đúng.")
    try:
        local_tz = pytz.timezone(client_timezone) if client_timezone else pytz.utc
    except Exception:
        raise HTTPException(status_code=400, detail="Múi giờ không hợp lệ.")
    now = datetime.now(local_tz)
    expired_at_str = otp_info[0].get("expired_at")
    if not expired_at_str:
        raise HTTPException(status_code=400, detail="Lỗi dữ liệu: expired_at không hợp lệ.")
    expired_at = datetime.strptime(expired_at_str, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=pytz.utc).astimezone(local_tz)
    if now > expired_at:
        raise HTTPException(status_code=400, detail="Mã OTP đã hết hạn.")
    return True

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> int:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token không chứa user_id.")
        return int(user_id)
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token đã hết hạn.")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token không hợp lệ.")
    except Exception:
        raise HTTPException(status_code=401, detail="Token lỗi.")