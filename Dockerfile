FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir .

COPY server.py tools.py cybersleuth.py ./

EXPOSE 5001

CMD ["python", "server.py", "--transport", "streamable-http", "--port", "5001"]
