# stage 1: build stage
FROM python:3.12-slim as builder
WORKDIR /app
COPY requirements.txt /app/

RUN python -m pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# stage 2: runtime stage
FROM python:3.12-slim
WORKDIR /app

# set pyton to run in unbuffered mode to output each line of log immdediately to console
ENV PYTHONUNBUFFERED=1

# copy necessary files from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/
COPY ./app /app/app

RUN apt-get update -y && apt-get clean \
    && chmod 755 -R /app/app

# Expose port 8000
EXPOSE 8000

# Run FastAPI app on port 8000, binding to all interfaces
CMD ["fastapi", "run", "/app/app/app.py", "--port", "8000", "--host", "0.0.0.0"]
