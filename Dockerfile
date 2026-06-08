FROM python:3.11-slim

WORKDIR /app

# Build reference for chain-of-evidence provenance — stamped onto every tool response + the manifest.
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
ENV CYBERSLEUTH_GIT_COMMIT=${GIT_COMMIT}
ENV CYBERSLEUTH_BUILD_DATE=${BUILD_DATE}

RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir .

COPY server.py tools.py cybersleuth.py manifest.py ./

EXPOSE 5001

CMD ["python", "server.py", "--transport", "streamable-http", "--port", "5001"]
