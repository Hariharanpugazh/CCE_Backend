#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "Installing dependencies..."
pip install --upgrade pip  # Ensure the latest pip version
pip install -r requirements.txt 

# Install Playwright without root requirement
echo "Installing Playwright..."
npx playwright install --with-deps --no-sandbox || true  # Ignore errors

# Apply database migrations
echo "Running migrations..."
python manage.py migrate

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Start the Gunicorn server
echo "Starting Gunicorn server..."
gunicorn backend.wsgi:application --bind 0.0.0.0:$PORT
