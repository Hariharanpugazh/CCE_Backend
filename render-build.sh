#!/bin/bash

# Exit on any failure
set -e  

# Install project dependencies
pip install -r requirements.txt

# Install Playwright and required browsers
playwright install --with-deps

# Display installed browsers (for debugging)
playwright install --check

# Run the application
exec "$@"
