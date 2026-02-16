@echo off
echo Установка зависимостей...
pip install -r requirements.txt

echo.
echo Запуск DevConnect...
python app.py

pause
