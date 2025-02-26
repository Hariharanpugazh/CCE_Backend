#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Installing Playwright and browsers..."
playwright install chromium firefox webkit --with-deps || true  # No root access required

# Start Gunicorn server
echo "Starting Gunicorn server..."
gunicorn backend.wsgi:application --bind 0.0.0.0:$PORT --timeout 300 --workers=3
