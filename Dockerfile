# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Prevent python from buffering stdout and stderr, which is good for logging
ENV PYTHONUNBUFFERED=1

# Copy the requirements file into the container
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code (app.py and the templates folder)
COPY . .

# Cloud Run provides the PORT environment variable
ENV PORT 8080

# Expose the port that Gunicorn will run on
EXPOSE 8080

# Use Gunicorn to run the app. 'app:app' means "in the file app.py, run the variable named app"
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--timeout", "0", "app:app"]