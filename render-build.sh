#!/bin/bash
set -e

# Install Playwright Browsers
playwright install --with-deps chromium

# Start Gunicorn Server (Increase Timeout)
gunicorn backend.wsgi:application --bind 0.0.0.0:$PORT --timeout 120 --workers=1
