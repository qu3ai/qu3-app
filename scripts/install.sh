#!/bin/bash

# QU3-App Installation Script
# This script helps with the complex installation process of qu3-app

set -e

echo "🚀 QU3-App Installation Script"
echo "=============================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if running in Docker
if [ -f /.dockerenv ]; then
    print_info "Running in Docker environment"
    IN_DOCKER=true
else
    IN_DOCKER=false
fi

# Check Python version
print_info "Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    print_error "Python 3.8 or higher is required. Found: $PYTHON_VERSION"
    exit 1
fi

print_status "Python version $PYTHON_VERSION is compatible"

# Check for required system dependencies
print_info "Checking system dependencies..."

check_command() {
    if command -v $1 >/dev/null 2>&1; then
        print_status "$1 is available"
        return 0
    else
        print_warning "$1 is not available"
        return 1
    fi
}

MISSING_DEPS=()

if ! check_command cmake; then
    MISSING_DEPS+=("cmake")
fi

if ! check_command gcc; then
    MISSING_DEPS+=("build-essential")
fi

if ! check_command git; then
    MISSING_DEPS+=("git")
fi

# Install missing dependencies if we can
if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    print_warning "Missing dependencies: ${MISSING_DEPS[*]}"
    
    if [ "$IN_DOCKER" = true ] || [ "$EUID" -eq 0 ]; then
        print_info "Attempting to install missing dependencies..."
        
        # Detect package manager
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update
            for dep in "${MISSING_DEPS[@]}"; do
                apt-get install -y $dep
            done
        elif command -v yum >/dev/null 2>&1; then
            for dep in "${MISSING_DEPS[@]}"; do
                yum install -y $dep
            done
        elif command -v brew >/dev/null 2>&1; then
            for dep in "${MISSING_DEPS[@]}"; do
                brew install $dep
            done
        else
            print_error "Cannot automatically install dependencies. Please install: ${MISSING_DEPS[*]}"
            exit 1
        fi
        
        print_status "Dependencies installed successfully"
    else
        print_error "Please install the following dependencies manually: ${MISSING_DEPS[*]}"
        print_info "On Ubuntu/Debian: sudo apt-get install ${MISSING_DEPS[*]}"
        print_info "On CentOS/RHEL: sudo yum install ${MISSING_DEPS[*]}"
        print_info "On macOS: brew install ${MISSING_DEPS[*]}"
        exit 1
    fi
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    print_info "Creating Python virtual environment..."
    python3 -m venv venv
    print_status "Virtual environment created"
else
    print_status "Virtual environment already exists"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
print_info "Upgrading pip..."
pip install --upgrade pip

# Install requirements
print_info "Installing Python dependencies..."
print_warning "This may take several minutes due to liboqs-python compilation..."

# Install requirements with timeout and retry logic
MAX_RETRIES=3
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if pip install -r requirements.txt; then
        print_status "Python dependencies installed successfully"
        break
    else
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
            print_warning "Installation failed, retrying ($RETRY_COUNT/$MAX_RETRIES)..."
            sleep 5
        else
            print_error "Failed to install dependencies after $MAX_RETRIES attempts"
            print_info "You may need to install liboqs manually. See: https://github.com/open-quantum-safe/liboqs"
            exit 1
        fi
    fi
done

# Install development dependencies if requested
if [ "$1" = "--dev" ]; then
    print_info "Installing development dependencies..."
    pip install pytest pytest-cov black isort flake8 mypy pre-commit
    print_status "Development dependencies installed"
fi

# Validate installation
print_info "Validating installation..."

if python -c "import oqs; print('liboqs-python:', oqs.__version__)" 2>/dev/null; then
    print_status "liboqs-python is working correctly"
else
    print_error "liboqs-python installation validation failed"
    exit 1
fi

if python -c "import src.main" 2>/dev/null; then
    print_status "QU3-App modules can be imported"
else
    print_error "QU3-App module import failed"
    exit 1
fi

# Create default configuration if it doesn't exist
if [ ! -f "config.yaml" ]; then
    print_info "Creating default configuration..."
    cat > config.yaml << EOF
# QU3-App Configuration
key_directory: "~/.qu3/keys/"
server_url: "http://127.0.0.1:8000"

# Logging configuration
logging:
  level: "INFO"
  file: null  # Set to a file path to enable file logging

# Network configuration
network:
  timeout: 30
  verify_ssl: true
EOF
    print_status "Default configuration created"
fi

# Run environment validation
print_info "Running environment validation..."
if python -m src.environment 2>/dev/null; then
    print_status "Environment validation passed"
else
    print_warning "Environment validation had issues (this may be normal)"
fi

echo ""
print_status "🎉 QU3-App installation completed successfully!"
echo ""
print_info "Next steps:"
echo "  1. Activate the virtual environment: source venv/bin/activate"
echo "  2. Generate client keys: python -m src.main generate-keys"
echo "  3. Start the mock server: python -m scripts.mock_mcp_server"
echo "  4. Test the installation: python -m src.main validate-config"
echo ""
print_info "For help: python -m src.main --help"

