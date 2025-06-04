from supabase import create_client, Client
import os
from dotenv import load_dotenv
import time

start_time = time.time()
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Lỗi: Thiếu SUPABASE_URL hoặc SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
print(f"Supabase client initialized in {time.time() - start_time:.2f} seconds")