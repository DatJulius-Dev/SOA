import random
import re
import time
from fastapi import APIRouter, Body, HTTPException, Query
import pytz
from core.security import hash_password, verify_password, create_access_token, generate_otp
from models.user import OTPRequestEmail, ResetPasswordRequest, UnlockAccountRequest, UserCreate, UserResponse, LoginRequest
from core.database import supabase
from fastapi import HTTPException
import random
from datetime import datetime, timedelta
from tzlocal import get_localzone

router = APIRouter()

def is_password_strong(password: str) -> bool:
    has_letter = re.search(r"[a-zA-Z]", password)
    has_number = re.search(r"\d", password)
    has_special = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    return bool(has_letter and has_number and has_special)

# Đăng ký tài khoản mới
@router.post("/register", response_model=UserResponse)
def register(user: UserCreate = Body(...)):
    if not is_password_strong(user.password):
        raise HTTPException(
            status_code=400,
            detail="Mật khẩu phải có ít nhất 1 chữ cái, 1 chữ số và 1 ký tự đặc biệt!"
        )

    existing_user = supabase.table("users").select("email").eq("email", user.email).execute()
    if existing_user.data:
        raise HTTPException(status_code=400, detail="Email đã tồn tại")

    user_id = random.randint(100000, 999999)
    hashed_password = hash_password(user.password)

    try:
        all_users = supabase.table("users").select("user_id").execute()
        role_to_assign = "Admin" if not all_users.data else "Customer"

        supabase.table("users").insert({
            "user_id": user_id,
            "email": user.email,
            "hashed_password": hashed_password,
            "role": role_to_assign,
            "status": "active"
        }).execute()

        supabase.table("profile").insert({
            "user_id": user_id,
            "phone": None,
            "full_name": None,
            "birth_date": None,
            "avatar_url": None
        }).execute()

        time.sleep(3)
        supabase.table("otp-request").insert({
            "user_id": user_id,
            "email": user.email
        }).execute()

        supabase.table("login_attempts").insert({
            "user_id": user_id,
            "email": user.email
        }).execute()

    except Exception as e:
        print(f"Lỗi khi đăng ký tài khoản: {str(e)}")
        supabase.table("users").delete().eq("user_id", user_id).execute()
        raise HTTPException(status_code=500, detail=f"Lỗi khi đăng ký tài khoản: {str(e)}")

    return {
        "message": f"Tài khoản {user.email} đã được đăng ký thành công với vai trò: {role_to_assign}!"
    }

# Đăng nhập
@router.post("/login")
def login(request: LoginRequest):
    user_response = supabase.table("users").select("*").eq("email", request.email).single().execute()
    if not user_response.data:
        raise HTTPException(status_code=400, detail="Sai email hoặc mật khẩu")
    user_data = user_response.data
    user_id = user_data["user_id"]

    if user_data["status"] == "locked":
        raise HTTPException(status_code=403, detail="Tài khoản đã bị khóa. Vui lòng xác minh OTP để mở khóa.")

    attempts_response = supabase.table("login_attempts").select("*").eq("user_id", user_id).single().execute()
    attempts_data = attempts_response.data if attempts_response.data else None
    failed_attempts = attempts_data["failed_attempts"] if attempts_data and attempts_data["failed_attempts"] is not None else 0

    if not verify_password(request.password, user_data["hashed_password"]):
        failed_attempts += 1
        if not attempts_data:
            supabase.table("login_attempts").insert({"user_id": user_id, "failed_attempts": failed_attempts}).execute()
        else:
            supabase.table("login_attempts").update({"failed_attempts": failed_attempts}).eq("user_id", user_id).execute()

        if failed_attempts >= 5:
            supabase.table("users").update({"status": "locked"}).eq("user_id", user_id).execute()
            supabase.table("login_attempts").update({"locked": True}).eq("user_id", user_id).execute()
            raise HTTPException(status_code=403, detail="Tài khoản đã bị khóa do nhập sai quá nhiều lần.")
        raise HTTPException(status_code=400, detail="Sai email hoặc mật khẩu")

    supabase.table("login_attempts").update({"failed_attempts": 0, "locked": False}).eq("user_id", user_id).execute()

    token = create_access_token(data={
        "user_id": user_id,
        "email": user_data["email"],
        "role": user_data.get("role", "User")
    })

    return {
        "message": "Đăng nhập thành công!",
        "email": user_data["email"],
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600
    }

# Mở khóa tài khoản
@router.post("/unlock-account")
def unlock_account(
    request: UnlockAccountRequest,
    client_timezone: str = Query(None)
):
    user = supabase.table("users").select("*").eq("email", request.email).execute().data
    if not user:
        raise HTTPException(status_code=400, detail="Email không tồn tại.")
    
    login_attempt = supabase.table("users").select("status").eq("email", request.email).execute().data
    if not login_attempt or login_attempt[0]["status"] != "locked":
        raise HTTPException(status_code=400, detail="Tài khoản không bị khóa.")

    otp_info = supabase.table("otp-request").select("*").eq("email", request.email).execute().data
    if not otp_info:
        raise HTTPException(status_code=400, detail="Mã OTP chưa được yêu cầu.")

    stored_otp = str(otp_info[0]["otp"])
    if stored_otp != str(request.otp):
        raise HTTPException(status_code=400, detail="Mã OTP không đúng.")

    try:
        local_tz = pytz.timezone(client_timezone) if client_timezone else get_localzone()
    except Exception:
        raise HTTPException(status_code=400, detail="Múi giờ không hợp lệ.")

    now = datetime.now(local_tz)

    expired_at_str = otp_info[0].get("expired_at")
    if not expired_at_str:
        raise HTTPException(status_code=400, detail="Lỗi dữ liệu: expired_at không hợp lệ.")

    expired_at = datetime.strptime(expired_at_str, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=pytz.utc).astimezone(local_tz)
    
    if now > expired_at:
        raise HTTPException(status_code=400, detail="Mã OTP đã hết hạn.")

    supabase.table("otp-request").delete().eq("email", request.email).execute()
    supabase.table("users").update({"status": "active"}).eq("email", request.email).execute()
    supabase.table("login_attempts").update({"failed_attempts": 0, "locked": False}).eq("email", request.email).execute()
    return {"message": "Tài khoản đã được mở khóa thành công."}

# Yêu cầu mã xác thực OTP
@router.post("/request-otp")
def request_otp(data: OTPRequestEmail):
    if not data.email:
        raise HTTPException(status_code=400, detail="Email is required")

    user_response = supabase.table("users").select("user_id").eq("email", data.email).execute()
    
    if not user_response.data:
        raise HTTPException(status_code=404, detail="Email không tồn tại")

    user_id = user_response.data[0]["user_id"]

    otp = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    expires_at_str = expires_at.strftime('%Y-%m-%dT%H:%M:%S')

    try:
        response = supabase.table("otp-request").upsert({
            "user_id": user_id,
            "email": data.email,
            "otp": otp,
            "expired_at": expires_at_str
        }).execute()

        if not response.data:
            raise HTTPException(status_code=500, detail=f"Lưu OTP thất bại: {response}")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi Supabase: {str(e)}")

    return {"message": "OTP đã được gửi", "email": data.email, "otp": otp, "user_id": user_id}

# Quên mật khẩu
@router.post("/reset-password")
def reset_password(
    request: ResetPasswordRequest,
    client_timezone: str = Query(None)
):
    user = supabase.table("users").select("*").eq("email", request.email).execute().data
    if not user:
        raise HTTPException(status_code=400, detail="Email không tồn tại.")
    
    otp_info = supabase.table("otp-request").select("*").eq("email", request.email).execute().data
    if not otp_info:
        raise HTTPException(status_code=400, detail="Mã OTP chưa được yêu cầu.")
    
    if str(otp_info[0]["otp"]) != str(request.otp):
        raise HTTPException(status_code=400, detail="Mã OTP không đúng.")

    try:
        if client_timezone:
            local_tz = pytz.timezone(client_timezone)
        else:
            local_tz = get_localzone()
    except Exception:
        raise HTTPException(status_code=400, detail="Múi giờ không hợp lệ.")

    now = datetime.now(local_tz)

    expired_at_str = otp_info[0].get("expired_at")
    if not expired_at_str:
        raise HTTPException(status_code=400, detail="Lỗi dữ liệu: expired_at không hợp lệ.")

    expired_at = datetime.strptime(expired_at_str, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=pytz.utc).astimezone(local_tz)
    
    if now > expired_at:
        raise HTTPException(status_code=400, detail="Mã OTP đã hết hạn.")
    
    hashed_new_password = hash_password(request.new_password)
    supabase.table("users").update({"hashed_password": hashed_new_password}).eq("email", request.email).execute()
    supabase.table("otp-request").delete().eq("email", request.email).execute()
    return {"message": "Mật khẩu đã được đặt lại thành công."}

def check_user_status(user):
    if user.status == "locked":
        raise HTTPException(status_code=403, detail="Tài khoản đã bị khóa.")
    if user.status == "inactive":
        raise HTTPException(status_code=403, detail="Tài khoản chưa được kích hoạt.")

def check_admin_role(user):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập chức năng này.")