# Vaultrix Labs web front door.
# NOTE: passive URL scans and repo scans (via the borrowed Docker-image scanners)
# need the Docker CLI available to this container; the sandbox attack/fix also need
# the Supabase CLI. For a full-feature deploy, run on a Docker-enabled host and
# mount the docker socket, or split the attack/fix jobs onto a Docker-enabled worker.
FROM python:3.13-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY interfaces/web/requirements.txt /app/interfaces/web/requirements.txt
RUN pip install --no-cache-dir -r interfaces/web/requirements.txt
COPY . /app
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
# 1 worker keeps the in-process job store coherent (see jobs.py ceiling note).
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:8000", "interfaces.web.app:app"]
