from fastapi import FastAPI
import uvicorn
from routers import accounts
from dotenv import load_dotenv
import os
import logging

load_dotenv()

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/auth_service.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

app = FastAPI(title="FastAPI Auth Service")

@app.get("/")
def home():
    logger.info("Truy cập trang chủ Auth Service.")
    return {"message": "Welcome to FastAPI With Auth Service"}

app.include_router(accounts.router, prefix="/accounts", tags=["Accounts"])

if __name__ == "__main__":
    logger.info("Server đang chạy tại: http://localhost:8001")
    print("Server đang chạy tại: http://localhost:8001")
    uvicorn.run("main:app", host="localhost", port=8001)