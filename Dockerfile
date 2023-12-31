FROM python:3.9-alpine
LABEL org.opencontainers.image.source "https://github.com/Diogo-Costa/imperva-exporter"
ENV TZ="GMT"
WORKDIR /app
COPY exporter .
RUN pip install -r requirements.txt && chmod u+x imperva_exporter.py
