#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "Installing dependencies..."
pip install --upgrade pip  # Ensure the latest pip version
pip install -r requirements.txt 

# Install Playwright without unsupported flags
echo "Installing Playwright..."
playwright install --with-deps || true  # Prevent failure if Playwright is not required

# Start the Gunicorn server
echo "Starting Gunicorn server..."
gunicorn backend.wsgi:application --bind 0.0.0.0:$PORT
