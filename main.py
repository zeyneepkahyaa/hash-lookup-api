import redis, requests
from fastapi import FastAPI, Request
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base
from fastapi.templating import Jinja2Templates

# 1. Veritabanı Yapılandırması (PostgreSQL)
# Docker iç ağında 'db' ismiyle servisler birbirini bulur.
DB_URL = "postgresql://postgres:1234*@db/hash_db"
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Veri Modeli: Hash sonuçlarını kalıcı olarak saklar
class HashRecord(Base):
    __tablename__ = "hashes"
    id = Column(Integer, primary_key=True)
    val = Column(String, unique=True)
    is_bad = Column(Boolean)

Base.metadata.create_all(bind=engine)

# 2. Uygulama ve Cache (Redis) Ayarları
app = FastAPI()
tmp = Jinja2Templates(directory="templates")
# Önemli: Host mutlaka 'redis' servis ismi olmalı!
cache = redis.Redis(host='redis', decode_responses=True)

# 3. Teknik Çekirdek: Hibrit Sorgulama Mantığı (Redis + VirusTotal)
def check_hash(h):
    # Katman 1: Redis Önbellek (Milisaniyeler içinde yanıt)
    cached = cache.get(h)
    if cached: return cached == "True"

    # Katman 2: VirusTotal API (Dış kaynak sorgusu)
    url = f"https://www.virustotal.com/api/v3/files/{h}"
    headers = {"x-apikey": "3146b4b87a13d1f4ae062f09dccbbafded8863ad367f771b0b268471d4d00cd0"}
    res = requests.get(url, headers=headers)
    
    is_bad = False
    if res.status_code == 200:
        stats = res.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        is_bad = stats.get('malicious', 0) > 0
    
    # Performans için sonucu 24 saatliğine Redis'e işle
    cache.setex(h, 86400, str(is_bad))
    return is_bad

# 4. API Uç Noktaları (Endpoints)
@app.get("/")
def home(request: Request):
    return tmp.TemplateResponse("index.html", {"request": request})

@app.get("/scan/{h}")
def scan(h: str):
    db = SessionLocal()
    # Veritabanı Kontrolü: Aynı hash daha önce taranmış mı?
    item = db.query(HashRecord).filter(HashRecord.val == h).first()
    if item: return {"status": "exists", "malicious": item.is_bad}

    # Yeni tarama yap ve her iki veritabanına da (PG + Redis) kaydet
    bad = check_hash(h)
    new_item = HashRecord(val=h, is_bad=bad)
    db.add(new_item); db.commit()
    return {"status": "new", "malicious": bad}
