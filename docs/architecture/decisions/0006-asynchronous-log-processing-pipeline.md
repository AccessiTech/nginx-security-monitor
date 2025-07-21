# ADR-0006: Asynchronous Log Processing Pipeline

## Status

Accepted

## Date

2024-03-15

## Author

Architecture Team

## Context

The Nginx Security Monitor needs to process large volumes of log data in real-time. Current requirements:

- **Throughput**: Process 10,000+ log entries per second
- **Latency**: Detect threats within 100ms of log entry
- **Reliability**: Handle temporary spikes without losing data
- **Scalability**: Support horizontal scaling across multiple nodes

Current challenges with synchronous processing:

- **Blocking I/O**: File reading and network calls block the main thread
- **Sequential Processing**: One slow operation delays all subsequent processing
- **Resource Utilization**: Poor CPU and I/O utilization
- **Scalability Limits**: Difficult to scale beyond single-threaded performance

Processing pipeline requirements:

1. **Log Ingestion**: Read from multiple log sources simultaneously
1. **Pattern Matching**: Apply multiple detection rules concurrently
1. **Integration Calls**: Send alerts to external systems without blocking
1. **Data Persistence**: Store results and metrics asynchronously

## Decision

We will implement an **asynchronous, event-driven log processing pipeline** using Python's asyncio framework.

Architecture components:

1. **Async Log Reader**: Concurrent file monitoring using aiofiles
1. **Processing Queue**: asyncio.Queue for buffering log entries
1. **Worker Pool**: Configurable number of async workers for pattern matching
1. **Integration Manager**: Async HTTP client for external API calls
1. **Event Bus**: Internal pub/sub for component communication

### Pipeline Flow

```
Log Sources → Log Reader → Processing Queue → Workers → Integration Manager
     ↓              ↓            ↓           ↓            ↓
File Monitor → Line Parser → Entry Buffer → Pattern Match → Alert Dispatch
```

## Consequences

### Positive

- **High Throughput**: Concurrent processing of multiple log entries
- **Low Latency**: Non-blocking operations maintain responsiveness
- **Resource Efficiency**: Better CPU and I/O utilization
- **Scalability**: Easy to add more workers or distribute across nodes
- **Reliability**: Queue-based buffering handles traffic spikes

### Negative

- **Complexity**: Async programming model is more complex than synchronous
- **Debugging**: Async stack traces and debugging can be challenging
- **Memory Usage**: Queues and coroutines consume more memory
- **Learning Curve**: Team needs to understand async/await patterns

### Neutral

- **Testing**: Requires async-aware testing frameworks
- **Dependencies**: Adds dependencies on asyncio-compatible libraries

## Implementation

### Core Components

```python
# Async log processor
import asyncio
import aiofiles
from asyncio import Queue
from typing import AsyncGenerator

class AsyncLogProcessor:
    def __init__(self, workers: int = 4, queue_size: int = 1000):
        self.workers = workers
        self.queue = Queue(maxsize=queue_size)
        self.running = False
    
    async def start(self):
        """Start the processing pipeline"""
        self.running = True
        
        # Start components
        tasks = [
            self.log_reader(),
            *[self.worker(i) for i in range(self.workers)],
            self.integration_manager()
        ]
        
        await asyncio.gather(*tasks)
    
    async def log_reader(self):
        """Read logs asynchronously"""
        async for log_entry in self.read_log_files():
            await self.queue.put(log_entry)
    
    async def worker(self, worker_id: int):
        """Process log entries"""
        while self.running:
            try:
                entry = await asyncio.wait_for(
                    self.queue.get(), timeout=1.0
                )
                await self.process_entry(entry)
                self.queue.task_done()
            except asyncio.TimeoutError:
                continue
    
    async def process_entry(self, entry: dict):
        """Apply pattern matching"""
        # Concurrent pattern matching
        tasks = [
            self.apply_pattern(entry, pattern) 
            for pattern in self.patterns
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle results
        for result in results:
            if isinstance(result, ThreatDetection):
                await self.alert_queue.put(result)
```

### Configuration

```yaml
# Async processing configuration
processing:
  async:
    enabled: true
    workers: 8  # Number of async workers
    queue_size: 10000  # Max queued entries
    batch_size: 100  # Process entries in batches
    
  timeouts:
    queue_timeout: 1.0  # Queue get timeout (seconds)
    processing_timeout: 5.0  # Max processing time per entry
    integration_timeout: 10.0  # Integration call timeout
    
  performance:
    max_concurrent_files: 50  # Max concurrent file handles
    read_buffer_size: 65536  # File read buffer size
    pattern_cache_size: 1000  # Compiled pattern cache
```

### Monitoring and Metrics

```python
# Async performance metrics
import time
from collections import defaultdict

class AsyncMetrics:
    def __init__(self):
        self.counters = defaultdict(int)
        self.timers = defaultdict(list)
        self.queue_sizes = defaultdict(list)
    
    async def monitor_queues(self):
        """Monitor queue sizes"""
        while True:
            self.queue_sizes['processing'].append(
                self.processing_queue.qsize()
            )
            self.queue_sizes['alerts'].append(
                self.alert_queue.qsize()
            )
            await asyncio.sleep(1)
    
    def record_processing_time(self, duration: float):
        """Record entry processing time"""
        self.timers['processing'].append(duration)
        
    def get_performance_stats(self):
        """Get performance statistics"""
        return {
            'queue_sizes': {
                name: {
                    'current': sizes[-1] if sizes else 0,
                    'avg': sum(sizes) / len(sizes) if sizes else 0,
                    'max': max(sizes) if sizes else 0
                }
                for name, sizes in self.queue_sizes.items()
            },
            'processing_times': {
                'avg': sum(self.timers['processing']) / len(self.timers['processing']) if self.timers['processing'] else 0,
                'p95': self.percentile(self.timers['processing'], 95) if self.timers['processing'] else 0
            }
        }
```

### Testing Strategy

```python
# Async testing with pytest-asyncio
import pytest
import asyncio
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_async_log_processing():
    """Test async log processing pipeline"""
    processor = AsyncLogProcessor(workers=2, queue_size=10)
    
    # Mock log entries
    test_entries = [
        {"timestamp": "2024-03-15T10:00:00Z", "message": "test entry 1"},
        {"timestamp": "2024-03-15T10:00:01Z", "message": "test entry 2"}
    ]
    
    # Mock pattern matching
    processor.apply_pattern = AsyncMock(return_value=None)
    
    # Test processing
    for entry in test_entries:
        await processor.queue.put(entry)
    
    # Process entries
    worker_task = asyncio.create_task(processor.worker(0))
    await asyncio.sleep(0.1)  # Allow processing
    worker_task.cancel()
    
    # Verify calls
    assert processor.apply_pattern.call_count == len(test_entries)
```

## Related Decisions

- ADR-0001: Use Python for Implementation
- ADR-0002: Pattern-Based Detection Engine
- ADR-0009: Monitoring and Observability Strategy

## Notes

- Performance benchmarks show 5x improvement in throughput
- Memory usage increases by ~30% due to queues and coroutines
- Consider implementing backpressure mechanisms for extreme load scenarios
- Regular profiling needed to identify async bottlenecks
