# Use a base Python image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app

# Install system dependencies for Playwright
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    libnss3 \
    libatk1.0-0 \
    libpangocairo-1.0-0 \
    libxcomposite1 \
    libxrandr2 \
    libgbm-dev \
    libasound2 \
    libc6 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (required for Playwright)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Install Playwright and its dependencies
RUN npm install -g playwright && playwright install --with-deps

# Copy the application code
COPY . /app/

# Expose the port your application runs on
EXPOSE 8000

# Start the application
CMD ["gunicorn", "backend.wsgi:application", "--bind", "0.0.0.0:8000"]
