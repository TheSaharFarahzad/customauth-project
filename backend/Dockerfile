# Build Stage
FROM python:3.12-slim as builder

# Set working directory
WORKDIR /app

# Copy the requirements.txt into the image
COPY requirements.txt ./

# Install dependencies and build wheel files
RUN pip install --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


# Runner Stage
FROM python:3.12-slim as runner

# Set working directory
WORKDIR /app

# Copy wheel files from the build stage
COPY --from=builder /wheels /wheels

# Install packages from wheel files
RUN pip install --no-cache-dir /wheels/*

# Copy Flask application
COPY app.py /app

# Set Flask environment variable
ENV FLASK_APP=app.py

# Expose port 8000 for the application
EXPOSE 8000

# Start the application
CMD ["flask", "run", "--host=0.0.0.0", "--port=8000"]
