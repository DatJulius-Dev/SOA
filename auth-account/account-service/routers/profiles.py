from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
import pytz
from tzlocal import get_localzone
from models.user import PasswordUpdate, PhoneUpdate, ProfileUpdate, ProfileResponse, UpdateEmailAccount
from core.security import hash_password, verify_password, get_current_user
from core.database import supabase

router = APIRouter()

# Lấy thông tin cá nhân
@router.get("/profile", response_model=ProfileResponse)
def get_profile(user_id: int = Depends(get_current_user)):
    result = supabase.table("profile").select("full_name, phone, birth_date, avatar_url")\
        .eq("user_id", user_id).single().execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Không tìm thấy thông tin người dùng.")
    
    profile = result.data
    return {
        "full_name": profile.get("full_name"),
        "phone": profile.get("phone"),
        "birth_date": profile.get("birth_date"),
        "avatar_url": profile.get("avatar_url") or "default_avatar_url"
    }

# Cập nhật trang cá nhân
@router.put("/profile")
def update_profile(profile: ProfileUpdate, user_id: str = Depends(get_current_user)):
    if profile.birth_date:
        try:
            birth_date = datetime.strptime(profile.birth_date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Định dạng ngày sinh không hợp lệ. Dùng định dạng ISO: YYYY-MM-DD"
            )

        now = datetime.now()
        if now.tzinfo is not None:
            now = now.replace(tzinfo=None)

        if birth_date > now:
            raise HTTPException(status_code=400, detail="Ngày sinh không được lớn hơn hiện tại.")

        age = (now - birth_date).days // 365
        if age < 1:
            raise HTTPException(status_code=400, detail="Người dùng phải trên 1 tuổi.")
        if age > 100:
            raise HTTPException(status_code=400, detail="Tuổi không được vượt quá 100.")

    data = {"user_id": user_id, **profile.dict(exclude_unset=True)}
    supabase.table("profile").upsert(data).execute()

    return {"message": "Cập nhật thành công", "user_id": user_id}

def get_timezone(tz_str: str):
    try:
        if tz_str and tz_str in pytz.all_timezones:
            return pytz.timezone(tz_str)
        return get_localzone()
    except Exception:
        return pytz.utc

# Thay đổi email
@router.put("/update-account")
def update_email(email_data: UpdateEmailAccount):
    if not supabase.table("users").select("email").eq("email", email_data.old_email).execute().data:
        raise HTTPException(status_code=404, detail="Người dùng không tồn tại.")

    if supabase.table("users").select("email").eq("email", email_data.new_email).execute().data:
        raise HTTPException(status_code=400, detail="Email mới đã được sử dụng.")

    otp_response = supabase.table("otp-request").select("*").eq("email", email_data.old_email).execute()
    if not otp_response.data:
        raise HTTPException(status_code=400, detail="Mã OTP chưa được yêu cầu.")
    
    otp_info = otp_response.data[0]
    if str(otp_info["otp"]) != str(email_data.otp):
        raise HTTPException(status_code=400, detail="Mã OTP không đúng.")

    local_tz = get_timezone(email_data.client_timezone)
    now = datetime.now(local_tz)

    expired_at_str = otp_info.get("expired_at")
    if not expired_at_str:
        raise HTTPException(status_code=400, detail="Lỗi dữ liệu: expired_at không hợp lệ.")
    
    expired_at = datetime.strptime(expired_at_str, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=pytz.utc).astimezone(local_tz)
    if now > expired_at:
        raise HTTPException(status_code=400, detail="Mã OTP đã hết hạn.")

    supabase.table("users").update({"email": email_data.new_email}).eq("email", email_data.old_email).execute()
    return {"message": "Cập nhật email thành công."}

# Thay đổi số điện thoại
@router.put("/change-phone")
def change_phone(phone_data: PhoneUpdate):
    otp_response = supabase.table("otp-request").select("*").eq("otp", phone_data.otp).execute()
    if not otp_response.data:
        raise HTTPException(status_code=400, detail="Mã OTP không đúng hoặc chưa được yêu cầu.")

    otp_info = otp_response.data[0]
    user_id = otp_info.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Không tìm thấy user_id tương ứng với mã OTP.")

    expired_at_str = otp_info.get("expired_at")
    if not expired_at_str:
        raise HTTPException(status_code=400, detail="expired_at không hợp lệ.")

    local_tz = get_timezone(phone_data.client_timezone)
    now = datetime.now(local_tz)
    expired_at = datetime.strptime(expired_at_str, "%Y-%m-%dT%H:%M:%S") \
        .replace(tzinfo=pytz.utc).astimezone(local_tz)

    if now > expired_at:
        raise HTTPException(status_code=400, detail="Mã OTP đã hết hạn.")

    supabase.table("profile").update({"phone": phone_data.new_phone}).eq("user_id", user_id).execute()

    return {"message": "Cập nhật số điện thoại thành công."}

# Thay đổi mật khẩu
@router.put("/change-password")
def change_password(password_data: PasswordUpdate, user_id: str = Depends(get_current_user)):
    if password_data.new_password != password_data.new_password_again:
        raise HTTPException(status_code=400, detail="Mật khẩu mới không khớp.")

    user_response = supabase.table("users").select("hashed_password").eq("user_id", user_id).single().execute()
    user = user_response.data
    if not user or not verify_password(password_data.old_password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Mật khẩu cũ không đúng.")

    new_hashed = hash_password(password_data.new_password)
    supabase.table("users").update({"hashed_password": new_hashed}).eq("user_id", user_id).execute()
    return {"message": "Đổi mật khẩu thành công."}

# Quản lý tài khoản (Admin)
@router.get("/manage-accounts")
def manage_accounts(user_id: str = Depends(get_current_user)):
    user_data = supabase.table("users").select("email", "role").eq("user_id", user_id).single().execute().data
    if not user_data:
        raise HTTPException(status_code=401, detail="Không tìm thấy người dùng.")

    if user_data["role"] == "Admin":
        users = supabase.table("users").select("email", "full_name", "phone", "created_at").execute().data
        return {"users": users}
    
    return {"users": [{"email": user_data["email"]}]}