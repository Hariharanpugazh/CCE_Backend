#!/bin/bash
set -e

echo "🏗️ Installing Python Dependencies..."
pip install -r requirements.txt

echo "🌍 Installing Playwright & Browsers..."
npx playwright install --with-deps chromium

echo "🚀 Starting Gunicorn Server..."
gunicorn backend.wsgi:application --bind 0.0.0.0:$PORT --timeout 120 --workers=1
