import os
import asyncio
from datetime import datetime
from typing import List, Dict

import redis.asyncio as redis
from bson import ObjectId
from fastapi import (FastAPI, Request, WebSocket, WebSocketDisconnect, Depends,
                     HTTPException, status, Form)
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from pymongo import MongoClient

# --- Налаштування ---
app = FastAPI(title="Простий Чат на FastAPI, MongoDB та Redis")

# Налаштування шаблонів Jinja2 для рендерингу HTML
templates = Jinja2Templates(directory="templates")

# Налаштування для хешування паролів
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBasic()

# --- Підключення до баз даних ---

MONGO_URL =  "mongodb://localhost:27017/" #os.getenv("MONGO_URL", "mongodb://localhost:27017")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

# Підключення до MongoDB
mongo_client = MongoClient(MONGO_URL)
db = mongo_client.chat_app
users_collection = db.users
messages_collection = db.messages

# Підключення до Redis
redis_conn = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# --- Pydantic моделі ---
class UserCreate(BaseModel):
    username: str
    password: str

class Message(BaseModel):
    id: str = Field(alias="_id")
    username: str
    text: str
    timestamp: datetime

# --- Автентифікація ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    """Перевіряє крели користувача"""
    user = users_collection.find_one({"username": credentials.username})
    if not user or not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неправильне ім'я користувача або пароль",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user["username"]

# --- Менеджер WebSocket з'єднань ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        self.active_connections[username] = websocket
        await redis_conn.incr("active_users_counter")

    async def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]
            await redis_conn.decr("active_users_counter")

    async def broadcast(self, message: str):
        for connection in self.active_connections.values():
            await connection.send_text(message)

manager = ConnectionManager()

# --- Ендпоінти ---

# Головна сторінка
@app.get("/")
async def get_chat_page(request: Request):
    """Рендерить головну сторінку чату"""
    return templates.TemplateResponse("index.html", {"request": request})

# WebSocket для чату
@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    """Обробляє WebSocket з'єднання для чату в реальному часі"""
    await manager.connect(websocket, username)
    await manager.broadcast(f"Користувач {username} приєднався до чату.")
    try:
        while True:
            data = await websocket.receive_text()
            message_data = {
                "username": username,
                "text": data,
                "timestamp": datetime.utcnow()
            }
            messages_collection.insert_one(message_data)
            await manager.broadcast(f"{username}: {data}")
    except WebSocketDisconnect:
        await manager.disconnect(username)
        await manager.broadcast(f"Користувач {username} покинув чат.")

# --- CRUD Операції та інше ---

# C (Create) - Реєстрація користувача
@app.post("/register")
async def register_user(username: str = Form(...), password: str = Form(...)):
    """Створює нового користувача"""
    if users_collection.find_one({"username": username}):
        raise HTTPException(status_code=400, detail="Користувач з таким іменем вже існує")
    
    hashed_password = get_password_hash(password)
    users_collection.insert_one({"username": username, "hashed_password": hashed_password})
    return {"message": f"Користувач {username} успішно зареєстрований"}

# R (Read) - Отримати всі повідомлення
@app.get("/messages", response_model=List[Message])
async def get_all_messages():
    """Повертає всі повідомлення з бази даних"""
    messages = messages_collection.find().sort("timestamp", 1)
    # Конвертуємо ObjectId в рядок для серіалізації
    return [{**msg, "_id": str(msg["_id"])} for msg in messages]

# U (Update) - Оновити повідомлення
@app.put("/messages/{message_id}")
async def update_message(message_id: str, new_text: str, current_user: str = Depends(get_current_user)):
    """Оновлює текст існуючого повідомлення"""
    try:
        obj_id = ObjectId(message_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Неправильний ID повідомлення")

    message = messages_collection.find_one({"_id": obj_id})
    if not message:
        raise HTTPException(status_code=404, detail="Повідомлення не знайдено")
    if message["username"] != current_user:
        raise HTTPException(status_code=403, detail="Ви не можете редагувати чужі повідомлення")

    messages_collection.update_one({"_id": obj_id}, {"$set": {"text": new_text}})
    return {"message": "Повідомлення успішно оновлено"}

# D (Delete) - Видалити повідомлення
@app.delete("/messages/{message_id}")
async def delete_message(message_id: str, current_user: str = Depends(get_current_user)):
    """Видаляє повідомлення"""
    try:
        obj_id = ObjectId(message_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Неправильний ID повідомлення")
        
    message = messages_collection.find_one({"_id": obj_id})
    if not message:
        raise HTTPException(status_code=404, detail="Повідомлення не знайдено")
    if message["username"] != current_user:
        raise HTTPException(status_code=403, detail="Ви не можете видаляти чужі повідомлення")

    messages_collection.delete_one({"_id": obj_id})
    return {"message": "Повідомлення успішно видалено"}

# Лічильник активних користувачів з Redis
@app.get("/active-users")
async def get_active_users():
    """Повертає кількість активних користувачів з Redis"""
    count = await redis_conn.get("active_users_counter")
    return {"active_users": int(count) if count else 0}

# Приклад агрегації
@app.get("/stats/most-active-users")
async def get_most_active_users():
    """
    Приклад агрегації середньої складності:
    Знаходить 5 найактивніших користувачів за кількістю повідомлень.
    """
    pipeline = [
        {"$group": {"_id": "$username", "message_count": {"$sum": 1}}},
        {"$sort": {"message_count": -1}},
        {"$limit": 5}
    ]
    result = list(messages_collection.aggregate(pipeline))
    return result

@app.get("/stats/hourly-activity")
async def get_hourly_activity():
    """
    Приклад агрегації 2:
    Групує повідомлення по годинах (UTC), щоб показати піки активності.
    """
    pipeline = [
        {
            "$group": {
                "_id": {"$hour": "$timestamp"},
                "message_count": {"$sum": 1}
            }
        },
        {"$sort": {"_id": 1}}
    ]
    result = list(messages_collection.aggregate(pipeline))
    return [{"hour_of_day_utc": item["_id"], "count": item["message_count"]} for item in result]

@app.get("/stats/daily-count")
async def get_daily_message_count():
    """
    Приклад агрегації 3:
    Рахує кількість повідомлень за кожен день.
    """
    pipeline = [
        {
            "$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "message_count": {"$sum": 1}
            }
        },
        {"$sort": {"_id": 1}}
    ]
    result = list(messages_collection.aggregate(pipeline))
    return [{"date": item["_id"], "count": item["message_count"]} for item in result]

@app.get("/stats/avg-message-length")
async def get_avg_message_length():
    """
    Приклад агрегації 4:
    Розраховує середню довжину повідомлення для кожного користувача.
    """
    pipeline = [
        {
            "$group": {
                "_id": "$username",
                "avg_length": {"$avg": {"$strLenCP": "$text"}}
            }
        },
        {"$sort": {"avg_length": -1}}
    ]
    result = list(messages_collection.aggregate(pipeline))
    return [{"username": item["_id"], "average_message_length": round(item["avg_length"], 2)} for item in result]

