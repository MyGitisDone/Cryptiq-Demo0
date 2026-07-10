FROM python:3.11-slim

WORKDIR /app

# tcpdump for capturing traffic inside the container — copied out to the host after the session
# procps provides ps/pgrep, useful for debugging inside the container if needed
RUN apt-get update -qq && apt-get install -y --no-install-recommends tcpdump procps && rm -rf /var/lib/apt/lists/*

# kyber-py for ML-KEM (pip package = kyber-py, import = kyber_py.ml_kem)
RUN pip install --no-cache-dir kyber-py

# Copy the protocol core and both roles
COPY protocol.py      /app/protocol.py
COPY server/server.py /app/server/server.py
COPY client/client.py /app/client/client.py

# Expose SSH port
EXPOSE 2222

CMD ["python3", "/app/server/server.py"]
