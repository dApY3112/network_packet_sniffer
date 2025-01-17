# Use an official Python image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy application files
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose a port (optional, based on your app's usage)
EXPOSE 8080

# Command to run the application
CMD ["python", "packet_sniffer.py"]
