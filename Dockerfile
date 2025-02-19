# Use an official Python image as the base
FROM python:3.9-slim-buster

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies
# This step installs necessary OS packages which might be required for your application.
RUN apt-get update && apt-get install -y \
    gcc \
    libc-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Improve security by not running the app as root
RUN useradd -m myuser
USER myuser

# Copy only the requirements file, to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose port 8080 to the outside world (change according to your Flask app settings)
EXPOSE 8080

# Command to run the application
CMD ["python", "app.py"]
