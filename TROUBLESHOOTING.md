# QU3-App Troubleshooting Guide

This guide helps you resolve common issues when working with QU3-App.

## 🚨 Common Issues

### Installation Problems

#### liboqs-python Installation Fails

**Symptoms:**
- CMake errors during installation
- Compilation failures
- "No module named 'oqs'" errors

**Solutions:**

1. **Use the automated installer:**
   ```bash
   ./scripts/install.sh
   ```

2. **Manual dependency installation:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install build-essential cmake git

   # CentOS/RHEL
   sudo yum install gcc gcc-c++ cmake git

   # macOS
   brew install cmake
   ```

3. **Docker alternative:**
   ```bash
   docker-compose up --build
   ```

4. **Pre-built wheels (if available):**
   ```bash
   pip install --find-links https://github.com/open-quantum-safe/liboqs-python/releases liboqs-python
   ```

#### Python Version Issues

**Symptoms:**
- "Python 3.8 or higher is required"
- Syntax errors in modern Python code

**Solutions:**
1. **Check Python version:**
   ```bash
   python3 --version
   ```

2. **Install newer Python:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install python3.9 python3.9-venv

   # macOS
   brew install python@3.9
   ```

3. **Use pyenv for version management:**
   ```bash
   pyenv install 3.9.0
   pyenv local 3.9.0
   ```

### Configuration Issues

#### Server URL Not Configured

**Symptoms:**
- "Server URL not configured" errors
- Connection failures

**Solutions:**
1. **Check config.yaml:**
   ```yaml
   server_url: "http://127.0.0.1:8000"
   ```

2. **Use CLI override:**
   ```bash
   python -m src.main run-inference model_name '{}' --server-url http://localhost:8000
   ```

3. **Validate configuration:**
   ```bash
   python -m src.main validate-config
   ```

#### Key Directory Issues

**Symptoms:**
- Permission denied errors
- Keys not found

**Solutions:**
1. **Check directory permissions:**
   ```bash
   ls -la ~/.qu3/keys/
   ```

2. **Fix permissions:**
   ```bash
   chmod 700 ~/.qu3/keys/
   chmod 600 ~/.qu3/keys/*.sec
   chmod 644 ~/.qu3/keys/*.pub
   ```

3. **Regenerate keys:**
   ```bash
   python -m src.main generate-keys --force
   ```

### Connection Problems

#### Cannot Connect to Server

**Symptoms:**
- Connection timeout errors
- "Server is not reachable" messages

**Solutions:**
1. **Test basic connectivity:**
   ```bash
   python -m src.main test-connection
   ```

2. **Check if server is running:**
   ```bash
   curl http://127.0.0.1:8000/
   ```

3. **Start the mock server:**
   ```bash
   python -m scripts.mock_mcp_server
   ```

4. **Check firewall settings:**
   ```bash
   # Linux
   sudo ufw status
   
   # macOS
   sudo pfctl -sr
   ```

#### SSL/TLS Certificate Issues

**Symptoms:**
- Certificate verification errors
- SSL handshake failures

**Solutions:**
1. **For development, disable SSL verification:**
   ```yaml
   # config.yaml
   network:
     verify_ssl: false
   ```

2. **Update certificates:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update && sudo apt-get install ca-certificates
   
   # macOS
   brew install ca-certificates
   ```

### Runtime Errors

#### Key Generation Failures

**Symptoms:**
- "Failed to generate keys" errors
- PQC algorithm not found

**Solutions:**
1. **Verify liboqs installation:**
   ```bash
   python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"
   ```

2. **Check available algorithms:**
   ```bash
   python -c "import oqs; print('KEM:', oqs.get_enabled_kem_mechanisms()); print('SIG:', oqs.get_enabled_sig_mechanisms())"
   ```

3. **Reinstall liboqs-python:**
   ```bash
   pip uninstall liboqs-python
   pip install git+https://github.com/open-quantum-safe/liboqs-python@main
   ```

#### Memory Issues

**Symptoms:**
- Out of memory errors during key generation
- Slow performance

**Solutions:**
1. **Increase available memory:**
   - Close other applications
   - Use a machine with more RAM

2. **Use Docker with memory limits:**
   ```bash
   docker run --memory=2g qu3-app
   ```

3. **Monitor memory usage:**
   ```bash
   python -m src.main benchmark --iterations 5
   ```

### Performance Issues

#### Slow Key Generation

**Symptoms:**
- Key generation takes very long
- Timeouts during operations

**Solutions:**
1. **Benchmark performance:**
   ```bash
   python -m src.main benchmark
   ```

2. **Check system resources:**
   ```bash
   top
   htop
   ```

3. **Use faster algorithms (if acceptable for your use case):**
   - Consider different parameter sets
   - Check algorithm documentation

#### Network Timeouts

**Symptoms:**
- Request timeout errors
- Slow server responses

**Solutions:**
1. **Increase timeout values:**
   ```yaml
   # config.yaml
   network:
     timeout: 60
   ```

2. **Check network latency:**
   ```bash
   ping your-server-url
   ```

3. **Use local server for testing:**
   ```bash
   python -m scripts.mock_mcp_server
   ```

## 🔧 Debugging Tools

### Environment Validation
```bash
python -m src.environment
```

### Configuration Check
```bash
python -m src.main validate-config
```

### Key Inspection
```bash
python -m src.main inspect-keys
```

### Connection Testing
```bash
python -m src.main test-connection
```

### Performance Benchmarking
```bash
python -m src.main benchmark --iterations 10
```

### Verbose Logging
```yaml
# config.yaml
logging:
  level: "DEBUG"
  file: "debug.log"
```

## 🆘 Getting Help

### Self-Help Resources
1. **Check this troubleshooting guide**
2. **Review the main README.md**
3. **Check DEVELOPMENT.md for detailed setup**
4. **Run diagnostic commands**

### Community Support
1. **GitHub Issues**: Report bugs and request features
2. **Discussions**: Ask questions and share experiences
3. **Documentation**: Contribute improvements

### Professional Support
For enterprise users requiring dedicated support:
- **Email**: joseph@qu3.ai
- **Priority Support**: Available for enterprise customers
- **Custom Integration**: Professional services available

## 🔍 Diagnostic Information

When reporting issues, please include:

1. **System Information:**
   ```bash
   python -m src.environment
   ```

2. **Configuration:**
   ```bash
   python -m src.main validate-config
   ```

3. **Error Messages:**
   - Full error output
   - Stack traces
   - Log files (if enabled)

4. **Steps to Reproduce:**
   - Exact commands used
   - Expected vs actual behavior
   - Environment details

## 📝 Known Issues

### Current Limitations
- **Installation Time**: liboqs-python compilation can take 10-30 minutes
- **Memory Usage**: Key generation requires significant memory
- **Platform Support**: Limited Windows support (use WSL)

### Workarounds
- **Use Docker**: Avoids compilation issues
- **Pre-built Images**: Available for common platforms
- **Cloud Development**: Use cloud instances for development

### Future Improvements
- **Binary Distributions**: Pre-compiled packages
- **Optimized Algorithms**: Faster implementations
- **Better Windows Support**: Native Windows builds

---

**Still having issues?** 

1. Check our [GitHub Issues](https://github.com/qu3ai/qu3-app/issues)
2. Create a new issue with diagnostic information
3. Contact support at joseph@qu3.ai

