FROM python:3.13-slim
WORKDIR /app
COPY app.py .
EXPOSE 8080
HEALTHCHECK --interval=2s --timeout=3s --retries=15 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8080/health')"
CMD ["python", "app.py"]
