from fastapi import FastAPI
import uvicorn
from routers import profiles
import os
import logging

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/account_service.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Account Service",
    description="Service for managing user profiles, transactions, and rewards.",
    version="1.0.0"
)

app.include_router(profiles.router, prefix="/profiles", tags=["Profiles"])

@app.get("/")
def read_root():
    logger.info("Truy cập trang chủ Account Service.")
    return {"message": "Welcome to Account Service is up and running!"}

if __name__ == "__main__":
    logger.info("Server Account Service đang chạy tại: http://localhost:8002")
    print("Server đang chạy tại: http://localhost:8002")
    uvicorn.run("main:app", host="localhost", port=8002)