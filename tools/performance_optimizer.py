#!/usr/bin/env python3#!/usr/bin/env python3

""""""

Performance Optimization Module for NMAP Automator v1.2.0Performance Optimization Module for NMAP Automator v1.2.0

Provides async processing and resource management capabilities (Smart caching removed)Provides async processing, caching, and resource management capabilities

""""""



import asyncioimport asyncio

import aiofilesimport aiofiles

import functoolsimport functools

import hashlibimport hashlib

import jsonimport json

import loggingimport logging

import osimport os

import timeimport time

import threadingimport threading

from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completedfrom concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

from dataclasses import dataclass, asdictfrom dataclasses import dataclass, asdict

from typing import Dict, List, Optional, Any, Callable, Unionfrom typing import Dict, List, Optional, Any, Callable, Union

from pathlib import Pathfrom pathlib import Path

import psutilimport psutil

import gcimport gc

import weakrefimport weakref



logger = logging.getLogger(__name__)logger = logging.getLogger(__name__)





@dataclass@dataclass

class PerformanceMetrics:class PerformanceMetrics:

    """Performance metrics tracking"""    """Performance metrics tracking"""

    start_time: float    start_time: float

    end_time: Optional[float] = None    end_time: Optional[float] = None

    memory_usage_mb: float = 0.0    memory_usage_mb: float = 0.0

    cpu_usage_percent: float = 0.0    cpu_usage_percent: float = 0.0

    network_io_bytes: int = 0    network_io_bytes: int = 0

    disk_io_bytes: int = 0    disk_io_bytes: int = 0

        cache_hits: int = 0

    @property    cache_misses: int = 0

    def duration(self) -> float:    

        if self.end_time:    @property

            return self.end_time - self.start_time    def duration(self) -> float:

        return time.time() - self.start_time        if self.end_time:

                    return self.end_time - self.start_time

    def to_dict(self) -> Dict:        return time.time() - self.start_time

        return asdict(self)        

    def to_dict(self) -> Dict:

        return asdict(self)

class ResourceMonitor:

    """System resource monitoring and management"""

    class ResourceMonitor:

    def __init__(self):    """System resource monitoring and management"""

        self.metrics = PerformanceMetrics(start_time=time.time())    

        self._monitoring = False    def __init__(self):

                self.process = psutil.Process()

    def start_monitoring(self):        self.initial_memory = self.get_memory_usage()

        """Start resource monitoring"""        self.peak_memory = 0.0

        self._monitoring = True        

        self.metrics = PerformanceMetrics(start_time=time.time())    def get_memory_usage(self) -> float:

                """Get current memory usage in MB"""

    def stop_monitoring(self):        return self.process.memory_info().rss / 1024 / 1024

        """Stop resource monitoring and finalize metrics"""        

        self._monitoring = False    def get_cpu_usage(self) -> float:

        self.metrics.end_time = time.time()        """Get current CPU usage percentage"""

        self.metrics.memory_usage_mb = psutil.virtual_memory().used / 1024 / 1024        return self.process.cpu_percent()

        self.metrics.cpu_usage_percent = psutil.cpu_percent()        

            def get_network_io(self) -> int:

    def get_current_metrics(self) -> PerformanceMetrics:        """Get network I/O bytes"""

        """Get current performance metrics"""        try:

        current_metrics = PerformanceMetrics(            return self.process.io_counters().read_bytes + self.process.io_counters().write_bytes

            start_time=self.metrics.start_time,        except:

            end_time=time.time(),            return 0

            memory_usage_mb=psutil.virtual_memory().used / 1024 / 1024,            

            cpu_usage_percent=psutil.cpu_percent(interval=0.1)    def update_peak_memory(self):

        )        """Update peak memory usage"""

        return current_metrics        current = self.get_memory_usage()

        if current > self.peak_memory:

            self.peak_memory = current

class AsyncProcessor:            

    """Asynchronous processing for concurrent operations"""    def get_cpu_count(self) -> int:

            """Get CPU count"""

    def __init__(self, max_workers: int = None):        return psutil.cpu_count()

        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) + 4)        

        self.thread_executor = ThreadPoolExecutor(max_workers=self.max_workers)    def suggest_optimization(self) -> List[str]:

        self.process_executor = ProcessPoolExecutor(max_workers=min(4, os.cpu_count() or 1))        """Suggest performance optimizations"""

                suggestions = []

    async def execute_async(self, func: Callable, *args, **kwargs) -> Any:        

        """Execute function asynchronously"""        memory_usage = self.get_memory_usage()

        loop = asyncio.get_event_loop()        cpu_usage = self.get_cpu_usage()

        return await loop.run_in_executor(self.thread_executor, func, *args, **kwargs)        

            if memory_usage > 1000:  # > 1GB

    async def execute_parallel(self, tasks: List[Callable]) -> List[Any]:            suggestions.append("High memory usage detected - consider enabling memory optimization")

        """Execute multiple tasks in parallel"""            

        return await asyncio.gather(*[self.execute_async(task) for task in tasks])        if cpu_usage > 80:

                suggestions.append("High CPU usage - consider reducing thread count")

    def cleanup(self):            

        """Clean up executors"""        available_cpu = psutil.cpu_count()

        self.thread_executor.shutdown(wait=True)        if available_cpu > 4:

        self.process_executor.shutdown(wait=True)            suggestions.append(f"Multi-core system detected ({available_cpu} cores) - increase parallelism")

            

        return suggestions

class PerformanceOptimizer:

    """Main performance optimization coordinator (without caching)"""

    class IntelligentCache:

    def __init__(self):    """Advanced intelligent caching system with smart eviction, adaptive TTL, and predictive caching"""

        self.resource_monitor = ResourceMonitor()    

        self.async_processor = AsyncProcessor()    def __init__(self, max_size: int = 1000, default_ttl: int = 3600, enable_persistence: bool = True):

        self.performance_log = []        self.max_size = max_size

                self.default_ttl = default_ttl

    def start_performance_tracking(self):        self.enable_persistence = enable_persistence

        """Start performance tracking"""        self.cache: Dict[str, Dict] = {}

        self.resource_monitor.start_monitoring()        self.access_times: Dict[str, float] = {}

        logger.info("Performance tracking started")        self.access_frequency: Dict[str, int] = {}

                self.computation_times: Dict[str, float] = {}

    def stop_performance_tracking(self) -> PerformanceMetrics:        self.cache_priorities: Dict[str, float] = {}

        """Stop performance tracking and return metrics"""        self.hits = 0

        self.resource_monitor.stop_monitoring()        self.misses = 0

        metrics = self.resource_monitor.get_current_metrics()        self.adaptive_hits = 0

        self.performance_log.append(metrics)        self.predictive_hits = 0

        logger.info(f"Performance tracking completed - Duration: {metrics.duration:.2f}s")        self._lock = threading.RLock()

        return metrics        self._cache_file = Path("cache/cache_persistence.json")

            self._load_persistent_cache()

    def get_performance_summary(self) -> Dict[str, Any]:        

        """Get comprehensive performance summary"""        # Smart caching analytics

        if not self.performance_log:        self.access_patterns: Dict[str, List[float]] = {}

            return {"message": "No performance data available"}        self.prediction_buffer: Dict[str, Any] = {}

                    

        recent_metrics = self.performance_log[-10:]  # Last 10 operations    def _generate_key(self, *args, **kwargs) -> str:

                """Generate cache key from arguments with smart normalization"""

        avg_duration = sum(m.duration for m in recent_metrics) / len(recent_metrics)        # Normalize arguments for better cache hits

        avg_memory = sum(m.memory_usage_mb for m in recent_metrics) / len(recent_metrics)        normalized_args = []

        peak_memory = max(m.memory_usage_mb for m in recent_metrics)        for arg in args:

                    if isinstance(arg, (list, tuple)):

        return {                normalized_args.append(tuple(sorted(arg)) if all(isinstance(x, str) for x in arg) else tuple(arg))

            "operations": len(self.performance_log),            else:

            "average_duration": round(avg_duration, 2),                normalized_args.append(arg)

            "average_memory_mb": round(avg_memory, 2),                

            "peak_memory_mb": round(peak_memory, 2),        key_data = json.dumps({

            "last_operation": recent_metrics[-1].to_dict() if recent_metrics else None            "args": normalized_args, 

        }            "kwargs": sorted(kwargs.items())

            }, sort_keys=True, default=str)

    def cleanup(self):        return hashlib.sha256(key_data.encode()).hexdigest()[:16]  # Shorter keys for performance

        """Clean up resources"""        

        self.async_processor.cleanup()    def _is_expired(self, entry: Dict) -> bool:

        gc.collect()        """Check if cache entry is expired with adaptive TTL"""

        logger.info("Performance optimizer resources cleaned up")        base_expiry = entry.get('expires_at', 0)

        

        # Adaptive TTL based on access frequency

# Global performance optimizer instance        key = entry.get('key')

performance_optimizer = PerformanceOptimizer()        if key and key in self.access_frequency:

            frequency = self.access_frequency[key]

            computation_time = self.computation_times.get(key, 1.0)

def track_performance(func: Callable) -> Callable:            

    """Decorator to track function performance"""            # Extend TTL for frequently accessed, expensive computations

    @functools.wraps(func)            adaptive_multiplier = min(3.0, 1 + (frequency / 10) * (computation_time / 10))

    def wrapper(*args, **kwargs):            adaptive_expiry = entry.get('created_at', 0) + (self.default_ttl * adaptive_multiplier)

        performance_optimizer.start_performance_tracking()            

        try:            return time.time() > max(base_expiry, adaptive_expiry)

            result = func(*args, **kwargs)            

            return result        return time.time() > base_expiry

        finally:        

            performance_optimizer.stop_performance_tracking()    def _calculate_priority(self, key: str) -> float:

    return wrapper        """Calculate cache entry priority for smart eviction"""

        frequency = self.access_frequency.get(key, 1)

        recency = time.time() - self.access_times.get(key, time.time())

async def optimize_scan_execution(scan_functions: List[Callable]) -> List[Any]:        computation_time = self.computation_times.get(key, 1.0)

    """Optimize execution of multiple scan functions"""        

    return await performance_optimizer.async_processor.execute_parallel(scan_functions)        # Higher priority = more valuable to keep

        # Factors: frequency, recency (inverse), computation cost

        priority = (frequency * computation_time) / (1 + recency / 3600)  # Decay over hours

def log_performance_metrics(operation_name: str, metrics: PerformanceMetrics):        return priority

    """Log detailed performance metrics"""        

    logger.info(f"📊 Performance Metrics for {operation_name}:")    def _smart_evict(self):

    logger.info(f"   Duration: {metrics.duration:.2f}s")        """Smart eviction based on priority scoring"""

    logger.info(f"   Memory Usage: {metrics.memory_usage_mb:.2f}MB")        with self._lock:

    logger.info(f"   CPU Usage: {metrics.cpu_usage_percent:.1f}%")            if len(self.cache) >= self.max_size:

                # Calculate priorities for all entries

                priorities = {key: self._calculate_priority(key) for key in self.cache.keys()}

# Legacy compatibility - remove caching references                

def get_cache_analytics():                # Sort by priority (lowest first) and remove bottom 30%

    """Legacy function - returns empty analytics"""                sorted_keys = sorted(priorities.keys(), key=priorities.get)

    return {                keys_to_remove = sorted_keys[:max(1, len(sorted_keys) // 3)]

        "hit_rate": 0,                

        "entries": 0,                for key in keys_to_remove:

        "memory_usage_mb": 0,                    self.cache.pop(key, None)

        "performance_improvement": "Caching disabled"                    self.access_times.pop(key, None)

    }                    self.access_frequency.pop(key, None)
                    self.computation_times.pop(key, None)
                    self.cache_priorities.pop(key, None)
                    
                logger.debug(f"Smart cache eviction: removed {len(keys_to_remove)} entries")
                    
    def get(self, key: str, predict_next: bool = True) -> Optional[Any]:
        """Smart get with predictive caching and access pattern learning"""
        with self._lock:
            current_time = time.time()
            
            if key in self.cache:
                entry = self.cache[key]
                if not self._is_expired(entry):
                    # Update access statistics
                    self.access_times[key] = current_time
                    self.access_frequency[key] = self.access_frequency.get(key, 0) + 1
                    
                    # Track access patterns for prediction
                    if key not in self.access_patterns:
                        self.access_patterns[key] = []
                    self.access_patterns[key].append(current_time)
                    
                    # Keep only recent access times for pattern analysis
                    if len(self.access_patterns[key]) > 10:
                        self.access_patterns[key] = self.access_patterns[key][-10:]
                    
                    # Predictive prefetching
                    if predict_next and len(self.access_patterns[key]) >= 3:
                        self._predict_next_access(key)
                    
                    # Check if this was a predicted hit
                    if key in self.prediction_buffer:
                        self.predictive_hits += 1
                        self.prediction_buffer.pop(key)
                    
                    self.hits += 1
                    return entry['value']
                else:
                    # Remove expired entry
                    self._remove_entry(key)
                    
            self.misses += 1
            return None
            
    def set(self, key: str, value: Any, ttl: Optional[int] = None, computation_time: float = 0.0) -> None:
        """Smart set with computation time tracking for priority-based eviction"""
        with self._lock:
            self._smart_evict()
            
            current_time = time.time()
            ttl = ttl or self._adaptive_ttl(key, computation_time)
            expires_at = current_time + ttl
            
            self.cache[key] = {
                'key': key,  # Store key for adaptive TTL calculation
                'value': value,
                'expires_at': expires_at,
                'created_at': current_time,
                'size_bytes': self._estimate_size(value)
            }
            
            self.access_times[key] = current_time
            if computation_time > 0:
                self.computation_times[key] = computation_time
            
            # Update cache priority
            self.cache_priorities[key] = self._calculate_priority(key)
            
    def _adaptive_ttl(self, key: str, computation_time: float) -> int:
        """Calculate adaptive TTL based on computation cost and access patterns"""
        base_ttl = self.default_ttl
        
        # Increase TTL for expensive computations
        if computation_time > 10.0:  # Expensive operation (>10 seconds)
            base_ttl *= 3
        elif computation_time > 5.0:  # Moderate operation (>5 seconds)
            base_ttl *= 2
            
        # Increase TTL for frequently accessed items
        frequency = self.access_frequency.get(key, 0)
        if frequency > 5:
            base_ttl = int(base_ttl * (1 + frequency / 10))
            
        return min(base_ttl, 86400)  # Max 24 hours
        
    def _estimate_size(self, value: Any) -> int:
        """Estimate memory size of cached value"""
        try:
            if isinstance(value, str):
                return len(value.encode('utf-8'))
            elif isinstance(value, (dict, list)):
                return len(json.dumps(value).encode('utf-8'))
            else:
                return len(str(value).encode('utf-8'))
        except:
            return 1024  # Default estimate
            
    def _remove_entry(self, key: str):
        """Remove cache entry and all associated metadata"""
        self.cache.pop(key, None)
        self.access_times.pop(key, None)
        self.access_frequency.pop(key, None)
        self.computation_times.pop(key, None)
        self.cache_priorities.pop(key, None)
        self.access_patterns.pop(key, None)
        
    def _predict_next_access(self, key: str):
        """Predict next likely cache access for prefetching"""
        if key not in self.access_patterns or len(self.access_patterns[key]) < 3:
            return
            
        access_times = self.access_patterns[key]
        intervals = [access_times[i] - access_times[i-1] for i in range(1, len(access_times))]
        
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            last_access = access_times[-1]
            predicted_next = last_access + avg_interval
            
            # If prediction is soon, mark for prefetch
            if predicted_next - time.time() < avg_interval / 2:
                self.prediction_buffer[key] = predicted_next
            
    def cached(self, ttl: Optional[int] = None, track_performance: bool = True):
        """Smart decorator for caching function results with performance tracking"""
        def decorator(func: Callable):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                cache_key = f"{func.__name__}:{self._generate_key(*args, **kwargs)}"
                
                # Try to get from cache first
                result = self.get(cache_key)
                if result is not None:
                    logger.debug(f"Cache HIT for {func.__name__}")
                    return result
                
                # Execute function with performance tracking
                start_time = time.time() if track_performance else 0
                
                try:
                    result = func(*args, **kwargs)
                    
                    # Calculate computation time and cache result
                    computation_time = time.time() - start_time if track_performance else 0
                    
                    # Smart caching decision based on result size and computation time
                    if self._should_cache(result, computation_time):
                        self.set(cache_key, result, ttl, computation_time)
                        logger.debug(f"Cached result for {func.__name__} (computed in {computation_time:.2f}s)")
                    
                    return result
                    
                except Exception as e:
                    logger.error(f"Error executing {func.__name__}: {e}")
                    raise
                
            return wrapper
        return decorator
        
    def _should_cache(self, result: Any, computation_time: float) -> bool:
        """Smart decision on whether to cache a result"""
        # Always cache if computation took more than 1 second
        if computation_time > 1.0:
            return True
            
        # Cache small results from quick operations
        result_size = self._estimate_size(result)
        if result_size < 10240:  # Less than 10KB
            return True
            
        # Don't cache very large results from quick operations
        if result_size > 1048576 and computation_time < 0.5:  # >1MB and <0.5s
            return False
            
        return True
        
    def get_stats(self) -> Dict:
        """Get comprehensive cache statistics and analytics"""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
        adaptive_rate = (self.adaptive_hits / self.hits * 100) if self.hits > 0 else 0
        predictive_rate = (self.predictive_hits / self.hits * 100) if self.hits > 0 else 0
        
        # Calculate memory usage
        total_memory = sum(entry.get('size_bytes', 0) for entry in self.cache.values())
        
        # Top accessed keys
        top_keys = sorted(self.access_frequency.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'performance': {
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': f"{hit_rate:.2f}%",
                'adaptive_hits': self.adaptive_hits,
                'adaptive_rate': f"{adaptive_rate:.2f}%",
                'predictive_hits': self.predictive_hits,
                'predictive_rate': f"{predictive_rate:.2f}%"
            },
            'size_metrics': {
                'entries': len(self.cache),
                'max_size': self.max_size,
                'usage_percent': f"{(len(self.cache) / self.max_size * 100):.1f}%",
                'memory_bytes': total_memory,
                'memory_mb': f"{total_memory / 1048576:.2f}MB"
            },
            'top_accessed': [{'key': k[:50], 'frequency': f} for k, f in top_keys],
            'patterns': {
                'tracked_keys': len(self.access_patterns),
                'prediction_buffer_size': len(self.prediction_buffer)
            }
        }
        
    def _load_persistent_cache(self):
        """Load cache from persistent storage"""
        if not self.enable_persistence or not self._cache_file.exists():
            return
            
        try:
            with open(self._cache_file, 'r') as f:
                data = json.load(f)
                
            # Restore non-expired entries
            current_time = time.time()
            restored_count = 0
            
            for key, entry in data.get('cache', {}).items():
                if entry.get('expires_at', 0) > current_time:
                    self.cache[key] = entry
                    self.access_times[key] = entry.get('created_at', current_time)
                    restored_count += 1
                    
            # Restore statistics
            stats = data.get('stats', {})
            self.access_frequency = stats.get('access_frequency', {})
            self.computation_times = stats.get('computation_times', {})
            
            logger.info(f"Restored {restored_count} cache entries from persistence")
            
        except Exception as e:
            logger.warning(f"Failed to load persistent cache: {e}")
            
    def _save_persistent_cache(self):
        """Save cache to persistent storage"""
        if not self.enable_persistence:
            return
            
        try:
            # Prepare data for serialization
            cache_data = {}
            for key, entry in self.cache.items():
                # Only save non-expired entries
                if not self._is_expired(entry):
                    cache_data[key] = {
                        'value': entry['value'],
                        'expires_at': entry['expires_at'],
                        'created_at': entry['created_at'],
                        'size_bytes': entry.get('size_bytes', 0)
                    }
            
            data = {
                'cache': cache_data,
                'stats': {
                    'access_frequency': self.access_frequency,
                    'computation_times': self.computation_times
                },
                'metadata': {
                    'saved_at': time.time(),
                    'version': '1.0'
                }
            }
            
            with open(self._cache_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.debug(f"Saved {len(cache_data)} cache entries to persistence")
            
        except Exception as e:
            logger.warning(f"Failed to save persistent cache: {e}")
            
    def optimize(self) -> Dict:
        """Perform cache optimization and return recommendations"""
        recommendations = []
        
        # Analyze hit rate
        total_requests = self.hits + self.misses
        if total_requests > 100:
            hit_rate = self.hits / total_requests
            if hit_rate < 0.3:
                recommendations.append("Low cache hit rate - consider increasing cache size or TTL")
            elif hit_rate > 0.8:
                recommendations.append("Excellent cache performance")
                
        # Analyze memory usage
        total_memory = sum(entry.get('size_bytes', 0) for entry in self.cache.values())
        if total_memory > 100 * 1048576:  # 100MB
            recommendations.append("High memory usage - consider reducing cache size")
            
        # Analyze access patterns
        if len(self.access_patterns) > 0:
            avg_pattern_length = sum(len(p) for p in self.access_patterns.values()) / len(self.access_patterns)
            if avg_pattern_length > 7:
                recommendations.append("Good access pattern data for prediction")
                
        # Perform optimization
        self._optimize_entries()
        
        return {
            'recommendations': recommendations,
            'optimizations_applied': ['removed_expired_entries', 'updated_priorities'],
            'stats': self.get_stats()
        }
        
    def _optimize_entries(self):
        """Optimize cache entries by removing expired and low-priority items"""
        with self._lock:
            # Remove expired entries
            expired_keys = [key for key, entry in self.cache.items() if self._is_expired(entry)]
            for key in expired_keys:
                self._remove_entry(key)
                
            # Update all priorities
            for key in self.cache.keys():
                self.cache_priorities[key] = self._calculate_priority(key)
                
    def prefetch(self, keys: List[str], func: Optional[Callable] = None) -> int:
        """Smart prefetching for predicted cache misses"""
        prefetched = 0
        
        for key in keys:
            if key not in self.cache and func:
                try:
                    # Extract original arguments from key
                    if ':' in key:
                        func_name, arg_hash = key.split(':', 1)
                        # This is a simplified prefetch - in practice, you'd need to store original args
                        logger.debug(f"Would prefetch {key} but need original arguments")
                except Exception as e:
                    logger.debug(f"Prefetch failed for {key}: {e}")
                    
        return prefetched
        
    def warm_up(self, patterns: Dict[str, Any]) -> int:
        """Warm up cache with common access patterns"""
        warmed = 0
        
        for pattern_key, pattern_data in patterns.items():
            if pattern_key not in self.cache:
                # Simulate common results for warm-up
                if 'default_value' in pattern_data:
                    self.set(pattern_key, pattern_data['default_value'], 
                           pattern_data.get('ttl', self.default_ttl))
                    warmed += 1
                    
        logger.info(f"Cache warmed up with {warmed} entries")
        return warmed
        
    def clear(self, save_to_persistence: bool = True):
        """Clear all cache entries with optional persistence save"""
        if save_to_persistence:
            self._save_persistent_cache()
            
        with self._lock:
            self.cache.clear()
            self.access_times.clear()
            self.access_frequency.clear()
            self.computation_times.clear()
            self.cache_priorities.clear()
            self.access_patterns.clear()
            self.prediction_buffer.clear()
            self.hits = 0
            self.misses = 0
            self.adaptive_hits = 0
            self.predictive_hits = 0
            
        logger.info("Cache cleared completely")
        
    def __del__(self):
        """Destructor to save cache on shutdown"""
        try:
            self._save_persistent_cache()
        except:
            pass


class AsyncFileManager:
    """Asynchronous file operations for better I/O performance"""
    
    @staticmethod
    async def read_file(file_path: str) -> str:
        """Asynchronously read file content"""
        try:
            async with aiofiles.open(file_path, 'r') as f:
                return await f.read()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return ""
            
    @staticmethod
    async def write_file(file_path: str, content: str) -> bool:
        """Asynchronously write file content"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            async with aiofiles.open(file_path, 'w') as f:
                await f.write(content)
            return True
        except Exception as e:
            logger.error(f"Error writing file {file_path}: {e}")
            return False
            
    @staticmethod
    async def read_json(file_path: str) -> Dict:
        """Asynchronously read JSON file"""
        try:
            content = await AsyncFileManager.read_file(file_path)
            return json.loads(content) if content else {}
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in {file_path}: {e}")
            return {}
            
    @staticmethod
    async def write_json(file_path: str, data: Dict) -> bool:
        """Asynchronously write JSON file"""
        try:
            content = json.dumps(data, indent=2)
            return await AsyncFileManager.write_file(file_path, content)
        except Exception as e:
            logger.error(f"Error writing JSON to {file_path}: {e}")
            return False


class OptimizedExecutor:
    """Optimized task execution with intelligent resource management"""
    
    def __init__(self, max_workers: Optional[int] = None):
        self.cpu_count = psutil.cpu_count()
        self.available_memory = psutil.virtual_memory().available / 1024 / 1024 / 1024  # GB
        
        # Intelligent worker count based on system resources
        if max_workers is None:
            if self.available_memory > 8:  # > 8GB RAM
                max_workers = min(self.cpu_count * 2, 32)
            elif self.available_memory > 4:  # > 4GB RAM
                max_workers = min(self.cpu_count, 16)
            else:  # Lower memory systems
                max_workers = min(self.cpu_count // 2, 8)
                
        self.max_workers = max(1, max_workers)
        self.thread_pool = ThreadPoolExecutor(max_workers=self.max_workers)
        self.process_pool = ProcessPoolExecutor(max_workers=min(self.cpu_count, 4))
        
        logger.info(f"Optimized executor initialized: {self.max_workers} threads, {self.cpu_count} processes")
        
    def submit_io_task(self, func: Callable, *args, **kwargs):
        """Submit I/O bound task to thread pool"""
        return self.thread_pool.submit(func, *args, **kwargs)
        
    def submit_cpu_task(self, func: Callable, *args, **kwargs):
        """Submit CPU bound task to process pool"""
        return self.process_pool.submit(func, *args, **kwargs)
        
    def map_parallel(self, func: Callable, iterable: List, use_processes: bool = False):
        """Execute function over iterable in parallel"""
        if use_processes:
            return list(self.process_pool.map(func, iterable))
        else:
            return list(self.thread_pool.map(func, iterable))
            
    def batch_execute(self, tasks: List[tuple], batch_size: Optional[int] = None) -> List:
        """Execute tasks in optimized batches"""
        if batch_size is None:
            batch_size = self.max_workers * 2
            
        results = []
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            futures = []
            
            for func, args, kwargs in batch:
                future = self.submit_io_task(func, *args, **kwargs)
                futures.append(future)
                
            # Collect results from current batch
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=300)  # 5 minute timeout
                    results.append(result)
                except Exception as e:
                    logger.error(f"Task execution failed: {e}")
                    results.append(None)
                    
        return results
        
    def shutdown(self):
        """Shutdown executor pools"""
        self.thread_pool.shutdown(wait=True)
        self.process_pool.shutdown(wait=True)


class MemoryOptimizer:
    """Memory optimization and garbage collection management"""
    
    def __init__(self):
        self.weak_refs: List[weakref.ref] = []
        self.cleanup_threshold = 100  # MB
        
    def register_object(self, obj):
        """Register object for memory tracking"""
        self.weak_refs.append(weakref.ref(obj))
        
    def force_cleanup(self):
        """Force garbage collection and cleanup"""
        # Remove dead references
        self.weak_refs = [ref for ref in self.weak_refs if ref() is not None]
        
        # Force garbage collection
        collected = gc.collect()
        
        logger.debug(f"Memory cleanup: {collected} objects collected")
        return collected
        
    def check_memory_pressure(self) -> bool:
        """Check if system is under memory pressure"""
        memory_info = psutil.virtual_memory()
        memory_usage_percent = memory_info.percent
        
        return memory_usage_percent > 85  # > 85% memory usage
        
    def optimize_if_needed(self):
        """Perform optimization if memory pressure detected"""
        if self.check_memory_pressure():
            logger.warning("High memory usage detected, performing cleanup")
            self.force_cleanup()
            
    def get_memory_stats(self) -> Dict:
        """Get current memory statistics"""
        memory_info = psutil.virtual_memory()
        process = psutil.Process()
        
        return {
            'system_total_gb': memory_info.total / 1024**3,
            'system_available_gb': memory_info.available / 1024**3,
            'system_usage_percent': memory_info.percent,
            'process_usage_mb': process.memory_info().rss / 1024**2,
            'tracked_objects': len([ref for ref in self.weak_refs if ref() is not None])
        }


class PerformanceProfiler:
    """Performance profiling and optimization suggestions"""
    
    def __init__(self):
        self.metrics: List[PerformanceMetrics] = []
        self.resource_monitor = ResourceMonitor()
        self.cache = IntelligentCache()
        self.memory_optimizer = MemoryOptimizer()
        
    def start_profiling(self, operation_name: str) -> PerformanceMetrics:
        """Start profiling an operation"""
        metrics = PerformanceMetrics(
            start_time=time.time(),
            memory_usage_mb=self.resource_monitor.get_memory_usage(),
            cpu_usage_percent=self.resource_monitor.get_cpu_usage(),
            network_io_bytes=self.resource_monitor.get_network_io()
        )
        
        return metrics
        
    def end_profiling(self, metrics: PerformanceMetrics) -> PerformanceMetrics:
        """End profiling and calculate final metrics"""
        metrics.end_time = time.time()
        metrics.memory_usage_mb = self.resource_monitor.get_memory_usage()
        metrics.cpu_usage_percent = self.resource_monitor.get_cpu_usage()
        metrics.network_io_bytes = self.resource_monitor.get_network_io()
        
        # Add to metrics history
        self.metrics.append(metrics)
        
        # Update peak memory
        self.resource_monitor.update_peak_memory()
        
        # Check for memory optimization
        self.memory_optimizer.optimize_if_needed()
        
        return metrics
        
    def profile_function(self, func: Callable):
        """Decorator for profiling function execution"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            metrics = self.start_profiling(func.__name__)
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                final_metrics = self.end_profiling(metrics)
                logger.debug(f"Function {func.__name__} completed in {final_metrics.duration:.2f}s")
                
        return wrapper
        
    def get_performance_summary(self) -> Dict:
        """Get comprehensive performance summary"""
        if not self.metrics:
            return {}
            
        total_duration = sum(m.duration for m in self.metrics)
        avg_memory = sum(m.memory_usage_mb for m in self.metrics) / len(self.metrics)
        peak_memory = self.resource_monitor.peak_memory
        
        cache_stats = self.cache.get_stats()
        memory_stats = self.memory_optimizer.get_memory_stats()
        optimization_suggestions = self.resource_monitor.suggest_optimization()
        
        return {
            'total_operations': len(self.metrics),
            'total_duration_seconds': total_duration,
            'average_memory_usage_mb': avg_memory,
            'peak_memory_usage_mb': peak_memory,
            'cache_statistics': cache_stats,
            'memory_statistics': memory_stats,
            'optimization_suggestions': optimization_suggestions,
            'last_10_operations': [m.to_dict() for m in self.metrics[-10:]]
        }


# Global instances with smart configuration
performance_profiler = PerformanceProfiler()

# Smart cache sizing based on available memory
memory_gb = psutil.virtual_memory().total / 1024**3
if memory_gb > 32:  # High-end system
    cache_size = 5000
    cache_ttl = 3600  # 1 hour
elif memory_gb > 16:  # Mid-range system
    cache_size = 3000
    cache_ttl = 2400  # 40 minutes
elif memory_gb > 8:   # Standard system
    cache_size = 2000
    cache_ttl = 1800  # 30 minutes
else:  # Lower-end system
    cache_size = 1000
    cache_ttl = 1200  # 20 minutes

global_cache = IntelligentCache(max_size=cache_size, default_ttl=cache_ttl, enable_persistence=True)
optimized_executor = OptimizedExecutor()


def performance_optimized(ttl: Optional[int] = None, smart_cache: bool = True):
    """Enhanced decorator that combines smart caching and performance profiling"""
    def decorator(func: Callable):
        if smart_cache:
            cached_func = global_cache.cached(ttl, track_performance=True)(func)
        else:
            cached_func = func
            
        profiled_func = performance_profiler.profile_function(cached_func)
        
        # Add smart cache analytics
        original_func = profiled_func
        def analytics_wrapper(*args, **kwargs):
            result = original_func(*args, **kwargs)
            
            # Log cache performance periodically
            if hasattr(analytics_wrapper, 'call_count'):
                analytics_wrapper.call_count += 1
            else:
                analytics_wrapper.call_count = 1
                
            # Log every 100 calls
            if analytics_wrapper.call_count % 100 == 0:
                stats = global_cache.get_stats()
                logger.debug(f"Cache performance for {func.__name__}: "
                           f"Hit rate {stats['performance']['hit_rate']}, "
                           f"Entries: {stats['size_metrics']['entries']}")
                
            return result
            
        return analytics_wrapper
    return decorator


def smart_cache_manager():
    """Smart cache management functions"""
    class CacheManager:
        @staticmethod
        def optimize():
            """Optimize global cache performance"""
            return global_cache.optimize()
            
        @staticmethod
        def get_analytics():
            """Get comprehensive cache analytics"""
            return global_cache.get_stats()
            
        @staticmethod
        def warm_up_common_patterns():
            """Warm up cache with common scanning patterns"""
            common_patterns = {
                'nmap_version_check': {'default_value': True, 'ttl': 3600},
                'masscan_availability': {'default_value': False, 'ttl': 1800},
                'system_resources': {'default_value': {}, 'ttl': 300}
            }
            return global_cache.warm_up(common_patterns)
            
        @staticmethod
        def adaptive_resize():
            """Adaptively resize cache based on performance"""
            stats = global_cache.get_stats()
            hit_rate = float(stats['performance']['hit_rate'].rstrip('%'))
            current_size = stats['size_metrics']['entries']
            max_size = stats['size_metrics']['max_size']
            
            if hit_rate < 30 and current_size > max_size * 0.8:
                # Poor performance, increase cache size
                new_max = min(max_size * 2, 10000)
                global_cache.max_size = new_max
                logger.info(f"Cache size increased to {new_max} due to low hit rate")
                return f"Increased to {new_max}"
                
            elif hit_rate > 90 and current_size < max_size * 0.5:
                # Excellent performance but underutilized
                new_max = max(max_size // 2, 500)
                global_cache.max_size = new_max
                logger.info(f"Cache size reduced to {new_max} due to underutilization")
                return f"Reduced to {new_max}"
                
            return "No resize needed"
            
        @staticmethod
        def export_performance_report():
            """Export detailed cache performance report"""
            stats = global_cache.get_stats()
            
            report = {
                'timestamp': time.time(),
                'cache_analytics': stats,
                'system_info': {
                    'memory_gb': memory_gb,
                    'cpu_count': psutil.cpu_count(),
                    'cache_config': {
                        'max_size': global_cache.max_size,
                        'default_ttl': global_cache.default_ttl,
                        'persistence_enabled': global_cache.enable_persistence
                    }
                },
                'recommendations': global_cache.optimize()['recommendations']
            }
            
            return report
    
    return CacheManager()


def get_optimal_thread_count() -> int:
    """Calculate optimal thread count based on system resources"""
    cpu_count = psutil.cpu_count()
    memory_gb = psutil.virtual_memory().total / 1024**3
    
    if memory_gb > 16:  # High-end system
        return min(cpu_count * 3, 64)
    elif memory_gb > 8:  # Mid-range system
        return min(cpu_count * 2, 32)
    elif memory_gb > 4:  # Lower-end system
        return min(cpu_count, 16)
    else:  # Minimal system
        return max(2, cpu_count // 2)


def cleanup_performance_resources():
    """Clean up performance optimization resources with smart cache persistence"""
    global optimized_executor, global_cache
    
    try:
        # Save cache analytics before cleanup
        cache_manager = smart_cache_manager()
        final_stats = cache_manager.get_analytics()
        logger.info(f"Final cache performance - Hit rate: {final_stats['performance']['hit_rate']}, "
                   f"Entries: {final_stats['size_metrics']['entries']}")
        
        # Shutdown executor
        optimized_executor.shutdown()
        
        # Clear cache (with persistence save)
        global_cache.clear(save_to_persistence=True)
        
        # Force memory cleanup
        performance_profiler.memory_optimizer.force_cleanup()
        
        logger.info("Performance resources cleaned up successfully")
        
    except Exception as e:
        logger.warning(f"Error during performance cleanup: {e}")


# Smart cache initialization and optimization
def initialize_smart_cache():
    """Initialize and optimize cache based on system resources"""
    cache_manager = smart_cache_manager()
    
    # Warm up with common patterns
    warmed_entries = cache_manager.warm_up_common_patterns()
    
    # Log initialization
    optimal_threads = get_optimal_thread_count()
    logger.info(f"🚀 Smart Performance Optimization Initialized:")
    logger.info(f"   Optimal threads: {optimal_threads}")
    logger.info(f"   Cache size: {global_cache.max_size} entries")
    logger.info(f"   Cache TTL: {global_cache.default_ttl}s")
    logger.info(f"   Memory: {memory_gb:.1f}GB available")
    logger.info(f"   Persistence: {'Enabled' if global_cache.enable_persistence else 'Disabled'}")
    
    if warmed_entries > 0:
        logger.info(f"   Cache warmed with {warmed_entries} entries")
    
    return {
        'optimal_threads': optimal_threads,
        'cache_config': {
            'max_size': global_cache.max_size,
            'ttl': global_cache.default_ttl,
            'persistence': global_cache.enable_persistence
        },
        'warmed_entries': warmed_entries
    }


# Initialize smart cache system
_init_result = initialize_smart_cache()