#!/bin/bash
set -e

echo "🏗️ Installing Python Dependencies..."
pip install --no-cache-dir -r requirements.txt

echo "🌍 Installing Playwright Dependencies..."
PLAYWRIGHT_BROWSERS_PATH=0 playwright install chromium

echo "🚀 Starting Gunicorn Server..."
gunicorn backend.wsgi:application --bind 0.0.0.0:$PORT
