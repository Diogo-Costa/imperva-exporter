FROM python:3.9-alpine

WORKDIR /app
COPY exporter .

RUN pip install -r requirements.txt

RUN chmod u+x imperva_exporter.py

ENTRYPOINT ["/app/imperva_exporter.py"]