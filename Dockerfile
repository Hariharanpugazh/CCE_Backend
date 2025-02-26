# Use the official Python image as the base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (required for Playwright)
RUN wget -qO- https://deb.nodesource.com/setup_16.x | bash - && \
    apt-get install -y nodejs

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Install Playwright and its dependencies
RUN npx playwright install --with-deps

# Copy the application code
COPY . /app/

# Expose the port your application runs on
EXPOSE 8000

# Command to run the application
CMD ["gunicorn", "backend.wsgi:application", "--bind", "0.0.0.0:8000"]
