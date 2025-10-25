# Packet Monitor - Development Container
FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update and install prerequisites
RUN apt-get update && apt-get install -y \
    software-properties-common \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Add universe repository
RUN add-apt-repository universe && apt-get update

# Install kernel headers and BCC tools
RUN apt-get install -y \
    linux-headers-generic \
    bpfcc-tools \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# Install development tools and dependencies
RUN apt-get update && apt-get install -y \
    git \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    sqlite3 \
    libsqlite3-dev \
    build-essential \
    clang \
    llvm \
    net-tools \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install Python BCC bindings (CORRECT PACKAGE NAME)
RUN apt-get update && apt-get install -y \
    python3-bpfcc \
    && rm -rf /var/lib/apt/lists/*

# --- VENV FIX FOR DISTUTILS ERROR ---
# Create a Python virtual environment
RUN python3 -m venv /opt/venv

# Add the venv to the PATH. Now 'pip' and 'python' will use the venv
ENV PATH="/opt/venv/bin:$PATH"
# ------------------------------------

# Upgrade pip (now uses the venv's pip)
RUN pip install --upgrade pip

# Install Python libraries (now installs into the venv)
RUN pip install --no-cache-dir \
    pandas \
    numpy \
    rich \
    click \
    colorama \
    flask \
    flask-cors \
    prometheus-client

# Set working directory
WORKDIR /workspaces

# Keep container running
CMD ["sleep", "infinity"]

