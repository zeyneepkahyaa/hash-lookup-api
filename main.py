import os
import requests
import redis
from fastapi import FastAPI, Request, Form, Depends
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_all_metadata, create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# --- 1. SQLALCHEMY VERİTABANI AYARLARI ---
# Docker'daki 'db' isimli servise bağlaniyoruz
SQLALCHEMY_DATABASE_URL = "postgresql://user:password@db/hash_db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Veritabanı Tablo Modelimiz
class HashRecord(Base):
    __tablename__ = "analiz_kayitlari"
    id = Column(Integer, primary_key=True, index=True)
    hash_value = Column(String, unique=True, index=True)
    result = Column(String)

# Tabloyu otomatik olustur (Eger yoksa)
Base.metadata.create_all(bind=engine)

# Veritabanı oturumu yönetimi
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- 2. REDIS VE DIŞ SERVİS AYARLARI ---
redis_client = redis.StrictRedis(host='redis', port=6379, db=0, decode_responses=True)

def fetch_from_virustotal(hash_value: str):
    api_key = "KENDI_API_ANAHTARINI_BURAYA_YAZ"
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return f"Zararli: {stats['malicious']}, Güvenli: {stats['undetected']}"
        return "Hash bulunamadi."
    except:
        return "Bağlantı hatası."

# --- 3. ANA UÇ NOKTALAR ---

@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze")
async def analyze(request: Request, hash_input: str = Form(...), db: Session = Depends(get_db)):
    # Önce Redis'e bak (Hız için)
    cached = redis_client.get(hash_input)
    if cached:
        return templates.TemplateResponse("index.html", {"request": request, "result": cached, "hash": hash_input})

    # Redis'te yoksa, önce Veritabanına (Postgres) bak (Kalıcılık için)
    db_record = db.query(HashRecord).filter(HashRecord.hash_value == hash_input).first()
    if db_record:
        # Veritabanında bulduk, Redis'e de atalim ki bir dahaki sefere daha hizli olsun
        redis_client.setex(hash_input, 86400, db_record.result)
        return templates.TemplateResponse("index.html", {"request": request, "result": db_record.result, "hash": hash_input})

    # Hiçbir yerde yoksa API'ye git
    result = fetch_from_virustotal(hash_input)
    
    # Yeni sonucu hem Veritabanına hem Redis'e kaydet
    new_record = HashRecord(hash_value=hash_input, result=result)
    db.add(new_record)
    db.commit()
    redis_client.setex(hash_input, 86400, result)

    return templates.TemplateResponse("index.html", {"request": request, "result": result, "hash": hash_input})
