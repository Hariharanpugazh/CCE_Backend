#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "Installing dependencies..."
pip install --upgrade pip  # Ensure the latest pip version
pip install -r requirements.txt 

# Install Playwright **and force browser installation**
echo "Installing Playwright and browsers..."
playwright install chromium firefox webkit --with-deps

# Start the Gunicorn server
echo "Starting Gunicorn server..."
gunicorn backend.wsgi:application --bind 0.0.0.0:$PORT
