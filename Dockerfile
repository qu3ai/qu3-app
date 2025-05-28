# Dockerfile for qu3-app with liboqs support
FROM ubuntu:latest

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    cmake \
    libssl-dev \
    python3 \
    python3-venv \
    pip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Get and install liboqs
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs
RUN cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON && \
    cmake --build liboqs/build --parallel 4 && \
    cmake --build liboqs/build --target install

# Create non-root user for security
RUN useradd -m qu3user && \
    mkdir -p /home/qu3user/.qu3/keys && \
    chown -R qu3user:qu3user /home/qu3user/.qu3 && \
    chmod 700 /home/qu3user/.qu3/keys

# Switch to non-root user
USER qu3user
WORKDIR /home/qu3user

# Create Python virtual environment
RUN python3 -m venv venv

# Set up application directory
WORKDIR /app
COPY requirements.txt .

# Set environment variables for library paths
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV PATH="/home/qu3user/venv/bin:$PATH"

# Install Python dependencies
RUN . /home/qu3user/venv/bin/activate && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .
USER root
RUN chown -R qu3user:qu3user /app
USER qu3user

# Set environment variables
ENV PYTHONPATH=/app
ENV QU3_ENV=production
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "from src.environment import validate_environment; validate_environment()" || exit 1

# Default command
CMD ["python3", "-m", "src.main", "--help"]

