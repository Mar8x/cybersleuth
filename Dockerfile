FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

# Install dependencies only (no editable install needed in Docker)
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir $(python -c "
import tomllib
with open('pyproject.toml','rb') as f: d=tomllib.load(f)
print(' '.join(d['project']['dependencies']))
")

COPY server.py tools.py cybersleuth.py ./

EXPOSE 5001

CMD ["python", "server.py", "--transport", "streamable-http", "--port", "5001"]
