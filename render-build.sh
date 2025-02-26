#!/bin/bash

# Exit if any command fails
set -e

echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt 

# **Fix Playwright browser installation without root access**
echo "Installing Playwright and browsers..."
npx playwright install chromium firefox webkit --with-deps || true  # Skip errors

# Start the Gunicorn server
echo "Starting Gunicorn server..."
gunicorn backend.wsgi:application --bind 0.0.0.0:$PORT --timeout 120
