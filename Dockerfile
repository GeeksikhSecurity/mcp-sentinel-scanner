FROM python:3.11-slim

# Set metadata
LABEL maintainer="MCP Security Team <mcp-security@example.com>"
LABEL description="MCP Sentinel Scanner - Security scanner for Model Context Protocol services"
LABEL version="1.5.0"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 scanner && \
    mkdir -p /app /scan /reports && \
    chown -R scanner:scanner /app /scan /reports

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY --chown=scanner:scanner requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=scanner:scanner . ./

# Install package
RUN pip install --no-cache-dir -e .

# Switch to non-root user
USER scanner

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Create alias for convenience (not "mcp-scan": that name collides with
# Invariant Labs' unrelated MCP protocol scanner)
RUN echo 'alias mcp-sentinel="python -m scripts.sentinel_cli"' >> ~/.bashrc

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import src; print('healthy')" || exit 1

# Default entrypoint
ENTRYPOINT ["python", "-m", "scripts.sentinel_cli"]

# Default command (scan /scan directory)
CMD ["/scan"]
