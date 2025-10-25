#!/usr/bin/env python3
"""
Performance Optimization Module for NMAP Automator v2.1.0
Provides smart caching, resource monitoring, and performance profiling.
"""

import functools
import hashlib
import json
import logging
import os
import time
import threading
from dataclasses import dataclass, asdict
from typing import Optional, Any
import psutil

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
	start_time: float
	end_time: Optional[float] = None
	duration: Optional[float] = None
	memory_usage: Optional[float] = None
	cpu_usage: Optional[float] = None
	result: Any = None
	error: Optional[str] = None
	def to_dict(self):
		return asdict(self)

class SmartCache:
	def __init__(self, max_size=128, default_ttl=600):
		self.cache = {}
		self.max_size = max_size
		self.default_ttl = default_ttl
		self.lock = threading.RLock()
	def _make_key(self, func_name, args, kwargs):
		key = json.dumps({'func': func_name, 'args': args, 'kwargs': kwargs}, sort_keys=True)
		return hashlib.sha256(key.encode()).hexdigest()
	def get(self, key):
		with self.lock:
			entry = self.cache.get(key)
			if entry and (time.time() - entry['time'] < entry['ttl']):
				return entry['value']
			elif entry:
				del self.cache[key]
			return None
	def set(self, key, value, ttl=None):
		with self.lock:
			if len(self.cache) >= self.max_size:
				oldest = min(self.cache.items(), key=lambda x: x[1]['time'])[0]
				del self.cache[oldest]
			self.cache[key] = {
				'value': value,
				'time': time.time(),
				'ttl': ttl or self.default_ttl
			}
	def clear(self):
		with self.lock:
			self.cache.clear()
	def get_stats(self):
		with self.lock:
			return {
				'size': len(self.cache),
				'max_size': self.max_size,
				'default_ttl': self.default_ttl
			}

smart_cache = SmartCache()

def smart_cache_decorator(ttl=None):
	def decorator(func):
		@functools.wraps(func)
		def wrapper(*args, **kwargs):
			key = smart_cache._make_key(func.__name__, args, kwargs)
			cached = smart_cache.get(key)
			if cached is not None:
				logger.info(f"[CACHE HIT] {func.__name__} {args} {kwargs}")
				return cached
			result = func(*args, **kwargs)
			smart_cache.set(key, result, ttl)
			logger.info(f"[CACHE MISS] {func.__name__} {args} {kwargs}")
			return result
		return wrapper
	return decorator

class ResourceMonitor:
	def __init__(self):
		self.process = psutil.Process(os.getpid())
	def get_memory_usage(self):
		return self.process.memory_info().rss / 1024 / 1024
	def get_cpu_usage(self):
		return self.process.cpu_percent(interval=0.1)

class PerformanceOptimizer:
	def __init__(self):
		self.resource_monitor = ResourceMonitor()
	def profile_function(self, func):
		@functools.wraps(func)
		def wrapper(*args, **kwargs):
			metrics = PerformanceMetrics(start_time=time.time())
			try:
				metrics.memory_usage = self.resource_monitor.get_memory_usage()
				metrics.cpu_usage = self.resource_monitor.get_cpu_usage()
				result = func(*args, **kwargs)
				metrics.result = result
				metrics.error = None
			except Exception as e:
				metrics.error = str(e)
				raise
			finally:
				metrics.end_time = time.time()
				metrics.duration = metrics.end_time - metrics.start_time
			logger.info(f"[PERF] {func.__name__}: {metrics.to_dict()}")
			return metrics.result
		return wrapper

profiler = PerformanceOptimizer()

# --- Test Functionality ---
if __name__ == "__main__":
	logging.basicConfig(level=logging.INFO)

	@smart_cache_decorator(ttl=2)
	def slow_add(a, b):
		time.sleep(1)
		return a + b

	print("First call (should be slow):", slow_add(2, 3))
	print("Second call (should be cached):", slow_add(2, 3))
	time.sleep(2.1)
	print("Third call (cache expired, slow again):", slow_add(2, 3))

	@profiler.profile_function
	def fast_multiply(a, b):
		return a * b

	print("Profiled multiply:", fast_multiply(4, 5))
