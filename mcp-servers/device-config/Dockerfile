FROM python:3.12-slim

LABEL maintainer="NetClaw" \
      description="gNMI Streaming Telemetry MCP Server" \
      version="1.0.0"

WORKDIR /app

# Install system dependencies for gRPC compilation
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Run as non-root user
RUN useradd -m -r gnmi && chown -R gnmi:gnmi /app
USER gnmi

# Default entrypoint: stdio transport
ENTRYPOINT ["python", "gnmi_mcp_server.py"]
