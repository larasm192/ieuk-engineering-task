# Use official Python image
FROM python:3.11-slim

# Set working directory in container
WORKDIR /app

# Copy project files into container
COPY . .

# Install dependencies (add others if needed)
RUN pip install --no-cache-dir pytest pandas

# Default command
CMD ["pytest"]
