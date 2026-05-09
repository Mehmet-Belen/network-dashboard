@echo off
:: Bu komut her kosulda ana proje dizininde baslamasini garanti eder:
cd /d "%~dp0"

title Siber Guvenlik SOC - Sistem Baslatici
echo ===================================================
echo 🚀 Sistem Calistiriliyor...
echo ===================================================

:: 1. Frontend'i (React) Başlat
echo [1/3] React Frontend (Port 3001) baslatiliyor...
start "Frontend" cmd /k "cd frontend && npm start"

:: 2. Backend 1'i (Capture.py) Başlat
echo [2/3] Ag Ajanı (capture.py) baslatiliyor...
start "Capture Agent" cmd /k "cd backend && venv\Scripts\activate && python capture.py"

:: 3. Backend 2'yi (Diger Python Uygulamasi - app.py vs.) Başlat
echo [3/3] Backend API baslatiliyor...
start "Backend API" cmd /k "cd backend && venv\Scripts\activate && python app.py"

echo ===================================================
echo ✅ Butun terminaller ayaga kaldirildi! 
echo ⚠️  Docker'in acik oldugundan emin olun.
echo ===================================================
pause