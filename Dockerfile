FROM python:3.11-slim

# Don't run as root
RUN groupadd -r honeypot && useradd -r -g honeypot honeypot

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R honeypot:honeypot /app

USER honeypot

EXPOSE 2222 8080 2121 5000

CMD ["python", "-m", "api.app"]
