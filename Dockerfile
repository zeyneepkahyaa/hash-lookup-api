FROM python:3.9-slim

# 2. Çalışma dizinini /app olarak ayarla
WORKDIR /app

# 3. Gerekli kütüphane listesini kopyala ve kur
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Tüm proje dosyalarını içeri kopyala
COPY . .

# 5. Uygulamayı başlat (Uvicorn ile)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
