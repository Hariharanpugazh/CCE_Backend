#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e  

echo "Installing dependencies..."
pip install -r requirements.txt  

# Install Playwright without requiring root access
echo "Installing Playwright..."
playwright install --with-deps --single-process  

# Start the Django application
echo "Running migrations..."
python manage.py migrate  

echo "Collecting static files..."
python manage.py collectstatic --noinput  

echo "Starting Gunicorn server..."
gunicorn backend.wsgi:application --bind 0.0.0.0:8000  
