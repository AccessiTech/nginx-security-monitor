# Performance Tuning Guide

This guide provides strategies and techniques for optimizing Nginx Security Monitor performance in production environments.

## Performance Overview

Nginx Security Monitor's performance depends on several factors:

- **Log Processing Rate**: Number of log entries processed per second
- **Pattern Matching Efficiency**: Speed of threat detection algorithms
- **Memory Usage**: RAM consumption for pattern storage and processing
- **Network I/O**: Integration and alerting performance
- **Storage I/O**: Log file reading and writing performance

## Performance Monitoring

### Key Metrics

```yaml
# Performance monitoring configuration
monitoring:
  metrics:
    log_processing_rate:
      target: 10000  # entries/second
      warning: 5000
      critical: 1000
      
    memory_usage:
      target: "256MB"
      warning: "512MB"
      critical: "1GB"
      
    response_time:
      target: "100ms"
      warning: "500ms"
      critical: "2s"
      
    detection_accuracy:
      target: "99%"
      warning: "95%"
      critical: "90%"
```

### Performance Dashboard

```bash
# Monitor real-time performance
python scripts/performance-monitor.py

# Generate performance report
python scripts/performance-report.py --period 24h

# Check system resources
htop
iostat -x 1
vmstat 1
```

## Log Processing Optimization

### Efficient Log Parsing

```python
# Optimized log parsing configuration
log_processing:
  parser:
    type: "compiled_regex"  # Faster than standard regex
    cache_size: 10000       # Cache compiled patterns
    batch_size: 1000        # Process logs in batches
    
  buffer:
    size: "64MB"            # Input buffer size
    flush_interval: "1s"    # Flush frequency
    
  threading:
    worker_threads: 4       # CPU cores - 1
    queue_size: 10000       # Work queue size
```

### Log File Optimization

```bash
# Optimize log file reading
# Use memory-mapped files for large logs
echo 'vm.swappiness=10' >> /etc/sysctl.conf

# Enable log compression
logrotate -f /etc/logrotate.d/nginx

# Use SSD storage for logs
mount /var/log/nginx -o noatime,nodiratime
```

### Pattern Matching Performance

```yaml
# Optimized pattern configuration
patterns:
  optimization:
    compile_patterns: true    # Pre-compile all regex patterns
    use_dfa: true            # Use deterministic finite automaton
    pattern_cache: true      # Cache pattern matching results
    
  engine:
    type: "hyperscan"        # Intel Hyperscan for high performance
    cpu_features: ["sse4.2", "avx2"]  # Use CPU-specific optimizations
    
  rules:
    priority_based: true     # Process high-priority patterns first
    early_termination: true  # Stop on first match for exclusive rules
```

## Memory Optimization

### Memory Configuration

```yaml
# Memory management settings
memory:
  allocation:
    initial_heap: "128MB"
    max_heap: "512MB"
    
  garbage_collection:
    strategy: "generational"
    frequency: "adaptive"
    
  caching:
    pattern_cache: "64MB"
    log_cache: "32MB"
    result_cache: "16MB"
    
  monitoring:
    enable_profiling: true
    dump_on_oom: true
    alert_threshold: "80%"
```

### Memory Profiling

```bash
# Monitor memory usage
python -m memory_profiler scripts/memory-monitor.py

# Generate memory profile
valgrind --tool=massif python -m nginx_security_monitor

# Analyze memory leaks
python -m pympler.asizeof nginx_security_monitor
```

## CPU Optimization

### Multi-threading Configuration

```yaml
# CPU optimization settings
processing:
  threading:
    model: "thread_pool"     # Use thread pool for I/O
    worker_threads: 8        # Adjust based on CPU cores
    cpu_affinity: true       # Bind threads to specific cores
    
  parallelization:
    log_reading: true        # Parallel log file reading
    pattern_matching: true   # Parallel pattern processing
    integration_calls: true  # Parallel integration requests
    
  scheduling:
    priority: "high"         # Process priority
    nice_value: -5           # CPU scheduling priority
```

### CPU Profiling

```bash
# Profile CPU usage
python -m cProfile -o cpu.prof -m nginx_security_monitor
snakeviz cpu.prof

# Monitor CPU per thread
top -H -p $(pgrep nginx-security-monitor)

# Check CPU utilization
sar -u 1 60
```

## Network Performance

### Network Optimization

```yaml
# Network performance settings
network:
  tcp:
    keepalive: true
    nodelay: true
    buffer_size: "64KB"
    
  http:
    connection_pool: 100
    timeout: 30
    retry_attempts: 3
    
  integrations:
    batch_requests: true
    compression: true
    persistent_connections: true
```

### Network Monitoring

```bash
# Monitor network performance
iftop -i eth0
netstat -i
ss -tuln

# Check network latency
ping -c 10 integration-endpoint.example.com
traceroute integration-endpoint.example.com
```

## Storage I/O Optimization

### Storage Configuration

```yaml
# Storage optimization
storage:
  log_files:
    read_ahead: "1MB"
    buffer_size: "64KB"
    use_mmap: true           # Memory-mapped file access
    
  databases:
    wal_mode: true           # Write-ahead logging
    cache_size: "256MB"      # Database cache
    synchronous: "normal"    # Balance safety and performance
    
  temp_files:
    location: "/tmp"         # Use tmpfs for temporary files
    cleanup_interval: "1h"   # Regular cleanup
```

### I/O Monitoring

```bash
# Monitor I/O performance
iostat -x 1
iotop -a

# Check disk usage
df -h
du -sh /var/log/nginx-security-monitor/

# Monitor file descriptors
lsof -p $(pgrep nginx-security-monitor)
```

## Performance Tuning Strategies

### 1. Baseline Performance Testing

```bash
# Establish baseline metrics
python scripts/benchmark.py --duration 300 --log-rate 1000

# Load testing
python scripts/load-test.py --concurrent-logs 10000 --duration 600

# Stress testing
python scripts/stress-test.py --max-load --duration 1800
```

### 2. Iterative Optimization

```bash
# Step 1: Identify bottlenecks
python scripts/profile-bottlenecks.py

# Step 2: Apply optimizations
python scripts/apply-optimizations.py --config optimized.yaml

# Step 3: Measure improvements
python scripts/compare-performance.py --before baseline.json --after optimized.json
```

### 3. Configuration Tuning

```yaml
# Production-optimized configuration
performance:
  mode: "high_throughput"   # vs "low_latency" or "balanced"
  
  log_processing:
    batch_size: 5000        # Larger batches for throughput
    worker_threads: 16      # Scale with CPU cores
    
  pattern_matching:
    algorithm: "aho_corasick"  # Efficient multi-pattern matching
    optimization_level: 3      # Maximum optimization
    
  memory:
    prealloc_size: "1GB"    # Pre-allocate memory
    gc_threshold: "512MB"   # Adjust garbage collection
```

## Scaling Strategies

### Horizontal Scaling

```yaml
# Multi-instance configuration
scaling:
  instances: 4
  load_balancing:
    algorithm: "round_robin"
    health_checks: true
    
  data_partitioning:
    strategy: "log_source"   # Partition by log file
    sharding_key: "server_ip"
    
  coordination:
    service_discovery: "consul"
    configuration_sync: true
```

### Vertical Scaling

```bash
# Increase system resources
# CPU: Add more cores or faster processors
# Memory: Increase RAM allocation
# Storage: Use faster SSDs or NVMe drives
# Network: Upgrade to higher bandwidth interfaces

# System tuning for larger resources
echo 'kernel.shmmax = 1073741824' >> /etc/sysctl.conf
echo 'fs.file-max = 1000000' >> /etc/sysctl.conf
ulimit -n 65536
```

## Performance Troubleshooting

### Common Performance Issues

1. **High CPU Usage**

   ```bash
   # Check pattern complexity
   python scripts/analyze-patterns.py --complexity

   # Optimize regex patterns
   python scripts/optimize-patterns.py --input patterns.json
   ```

1. **Memory Leaks**

   ```bash
   # Monitor memory growth
   python scripts/memory-leak-detector.py --duration 3600

   # Analyze heap dumps
   python scripts/analyze-heap.py --dump memory.dump
   ```

1. **I/O Bottlenecks**

   ```bash
   # Check I/O wait times
   iostat -x 1 | grep -E '(avg|Device)'

   # Optimize file access patterns
   python scripts/optimize-io.py --profile io-profile.json
   ```

### Performance Debugging

```bash
# Enable performance debugging
export NSM_PERFORMANCE_DEBUG=true
export NSM_PROFILE_OUTPUT=/tmp/nsm-profile.json

# Collect performance data
python -m nginx_security_monitor --performance-mode

# Analyze performance data
python scripts/analyze-performance.py --profile /tmp/nsm-profile.json
```

## Benchmark Results

### Reference Performance

| Configuration | Log Rate (entries/sec) | Memory Usage | CPU Usage | Latency |
| ------------- | ---------------------- | ------------ | --------- | ------- |
| Basic         | 1,000                  | 128MB        | 25%       | 100ms   |
| Optimized     | 10,000                 | 256MB        | 50%       | 50ms    |
| High-Perf     | 50,000                 | 512MB        | 80%       | 20ms    |

### Performance Targets

- **Throughput**: > 10,000 log entries/second
- **Latency**: < 100ms average response time
- **Memory**: < 512MB steady-state usage
- **CPU**: < 70% average utilization
- **Availability**: > 99.9% uptime

## Monitoring and Alerting

### Performance Alerts

```yaml
# Performance alerting configuration
alerts:
  performance:
    log_processing_slow:
      threshold: 1000  # entries/second
      duration: "5m"
      severity: "warning"
      
    high_memory_usage:
      threshold: "80%"
      duration: "10m"
      severity: "critical"
      
    response_time_high:
      threshold: "500ms"
      duration: "2m"
      severity: "warning"
```

### Performance Dashboards

```bash
# Grafana dashboard setup
cp templates/grafana-dashboard.json /etc/grafana/dashboards/

# Prometheus metrics endpoint
curl http://localhost:8080/metrics

# Custom performance dashboard
python scripts/create-dashboard.py --template performance
```

______________________________________________________________________

**Related Documentation:**

- [Operations Guide](../OPERATIONS_GUIDE.md)
- [Monitoring Guide](monitoring.md)
- [Configuration Guide](../CONFIGURATION.md)
- [Troubleshooting](../TROUBLESHOOTING.md)
