# QU3-App Development Guide

This guide provides comprehensive information for developers working on the qu3-app project.

## Table of Contents

- [Development Setup](#development-setup)
- [Architecture Overview](#architecture-overview)
- [Testing](#testing)
- [Docker Development](#docker-development)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Docker (optional, for containerized development)
- CMake and build tools (for liboqs compilation)

### Local Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/qu3ai/qu3-app.git
   cd qu3-app
   ```

2. **Create and activate virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install -e ".[dev]"  # Install development dependencies
   ```

4. **Install pre-commit hooks:**
   ```bash
   pre-commit install
   ```

5. **Run environment validation:**
   ```bash
   python -m src.environment
   ```

### Docker Development Setup

For easier dependency management, especially with liboqs:

1. **Build the Docker image:**
   ```bash
   docker build -t qu3-app .
   ```

2. **Run with Docker Compose:**
   ```bash
   docker-compose up --build
   ```

## Architecture Overview

### Core Components

```
src/
├── main.py              # CLI interface (Typer)
├── mcp_client.py        # MCP client implementation
├── pqc_utils.py         # Post-quantum cryptography utilities
├── config_utils.py      # Configuration management
└── environment.py       # Environment validation and setup
```

### Key Design Patterns

- **Dependency Injection**: Configuration and keys are injected into components
- **Error Handling**: Comprehensive error handling with custom exception hierarchy
- **Retry Logic**: Exponential backoff for network operations
- **Security by Default**: Secure defaults with explicit opt-out for development

### Data Flow

1. **Initialization**: Load configuration and validate environment
2. **Key Management**: Generate or load PQC key pairs
3. **Connection**: Establish secure session via KEM handshake
4. **Request/Response**: Sign, encrypt, send, decrypt, verify
5. **Cleanup**: Secure cleanup of sensitive data


## Testing

### Test Structure

```
tests/
├── test_pqc_utils.py      # PQC utilities tests
├── test_config_utils.py   # Configuration tests
├── test_mcp_client.py     # Client integration tests
└── conftest.py            # Pytest configuration
```


## Docker Development

### Building Images

```bash
# Build development image
docker build -t qu3-app:dev .

# Build with specific target
docker build --target builder -t qu3-app:builder .
```

### Development Workflow

```bash
# Start development environment
docker-compose up -d

# Access container shell
docker-compose exec qu3-client bash

# View logs
docker-compose logs -f qu3-client
```

### Volume Mounts

For development, mount source code:

```yaml
volumes:
  - ./src:/app/src:ro
  - ./tests:/app/tests:ro
  - ./config.yaml:/app/config.yaml:ro
```

## Security Considerations

### Key Management

- Keys are stored with restrictive permissions (600 for private, 644 for public)
- Key directories have 700 permissions
- No keys should ever be committed to version control

### Secure Coding Practices

1. **Input Validation**: Validate all inputs at boundaries
2. **Error Handling**: Don't leak sensitive information in error messages
3. **Logging**: Be careful not to log sensitive data
4. **Dependencies**: Keep dependencies updated and scan for vulnerabilities


### Monitoring

- Use structured logging for observability
- Monitor key metrics: response times, error rates, resource usage
- Set up alerts for critical failures

## Troubleshooting

### Common Issues

#### liboqs Installation Fails

**Problem**: CMake or compilation errors during liboqs installation

**Solutions**:
1. Use Docker for consistent environment
2. Install system dependencies: `apt-get install build-essential cmake`
3. Use pre-built wheels if available

#### Key Generation Errors

**Problem**: PQC key generation fails

**Solutions**:
1. Check liboqs installation: `python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"`
2. Verify algorithm names match exactly
3. Check file permissions on key directory

#### Connection Timeouts

**Problem**: Client cannot connect to server

**Solutions**:
1. Check server is running: `curl http://localhost:8000/`
2. Verify network connectivity
3. Check firewall settings
4. Increase timeout values in config

#### SSL/TLS Issues

**Problem**: Certificate verification errors

**Solutions**:
1. For development: set `verify_ssl: false` in config
2. For production: ensure valid certificates
3. Check system certificate store

### Debug Mode

Enable debug logging for detailed troubleshooting:

```yaml
# config.yaml
logging:
  level: "DEBUG"
  file: "debug.log"
```

### Environment Diagnostics

Run comprehensive environment check:

```bash
python -m src.environment
```

This will output:
- System information
- Python version and packages
- liboqs status and available algorithms
- Configuration validation
- Security recommendations

## Contributing

### Development Workflow

1. Create feature branch: `git checkout -b feature/your-feature`
2. Make changes with tests
3. Run quality checks: `pre-commit run --all-files`
4. Run tests: `pytest`
5. Commit changes: `git commit -m "feat: add your feature"`
6. Push and create pull request

### Commit Message Format

Use conventional commits:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Test additions or changes
- `chore:` Maintenance tasks

### Code Review Guidelines

- All code must be reviewed before merging
- Tests must pass and coverage should not decrease
- Documentation should be updated for new features
- Security implications should be considered

