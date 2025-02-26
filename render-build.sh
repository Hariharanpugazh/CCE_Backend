#!/bin/bash
set -e

# Install Playwright Browsers
playwright install chromium

# Start the Django app
gunicorn backend.wsgi:application --bind 0.0.0.0:10000 --timeout 120 --workers=1
