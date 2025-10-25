#!/usr/bin/env python3
"""
Smart Caching Test and Demo for SecureScout
Demonstrates the advanced caching capabilities
"""

import sys
import os
import time
# Ensure project root is on sys.path so 'tools' package can be imported
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from tools.performance_optimizer import smart_cache_decorator, smart_cache
except ImportError:
    from performance_optimizer import smart_cache_decorator, smart_cache
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def demo_basic_caching():
    """Demo basic caching functionality"""
    print("🔍 Testing Basic Caching...")

    @smart_cache_decorator(ttl=60)
    def expensive_operation(n):
        time.sleep(0.1)
        return n * n

    # Test cache miss and hit
    start = time.time()
    result1 = expensive_operation(10)  # Cache miss
    miss_time = time.time() - start

    start = time.time()
    result2 = expensive_operation(10)  # Cache hit
    hit_time = time.time() - start

    print(f"   First call (miss): {miss_time:.3f}s")
    print(f"   Second call (hit): {hit_time:.3f}s")
    print(f"   Speed improvement: {miss_time/hit_time:.1f}x faster")

    stats = smart_cache.get_stats()
    print(f"   Cache stats: {stats['size']} entries")
    return smart_cache

def demo_smart_features(cache):
    """Demo smart caching features"""
    print("\n🧠 Testing Smart Caching Features...")

    @smart_cache_decorator(ttl=30)
    def variable_complexity(complexity):
        time.sleep(complexity / 10)
        return f"result_{complexity}"

    for complexity in [1, 5, 10]:
        start = time.time()
        result = variable_complexity(complexity)
        duration = time.time() - start
        print(f"   Complexity {complexity}: {duration:.3f}s")

    for complexity in [1, 5, 10]:
        start = time.time()
        result = variable_complexity(complexity)
        duration = time.time() - start
        print(f"   Cached complexity {complexity}: {duration:.3f}s (cached)")

def demo_predictive_caching(cache):
    """Demo simple sequential caching"""
    print("\n🔮 Testing Sequential Caching...")

    @smart_cache_decorator(ttl=20)
    def sequential_operation(n):
        time.sleep(0.05)
        return f"data_{n}"

    print("   Creating access pattern...")
    for i in range(5):
        result = sequential_operation(i)
        time.sleep(0.1)

    print("   Testing cache hits...")
    for i in range(5):
        start = time.time()
        result = sequential_operation(i)
        duration = time.time() - start
        print(f"   Access {i}: {duration:.3f}s (cached)")

def demo_smart_eviction(cache):
    """Demo cache eviction by size"""
    print("\n🎯 Testing Cache Eviction...")

    @smart_cache_decorator(ttl=10)
    def data_generator(key, computation_time=0.01):
        time.sleep(computation_time)
        return f"value_for_{key}"

    print("   Filling cache...")
    for i in range(150):
        data_generator(f"filler_{i}", 0.001)

    # Check cache size
    stats = smart_cache.get_stats()
    print(f"   Cache size after fill: {stats['size']} (max {stats['max_size']})")

def demo_cache_analytics():
    """Demo cache stats"""
    print("\n📊 Testing Cache Stats...")
    stats = smart_cache.get_stats()
    print(f"   Cache entries: {stats['size']} / {stats['max_size']}")
    print(f"   Default TTL: {stats['default_ttl']} seconds")

def demo_persistence():
    """Demo cache clear/reset"""
    print("\n💾 Testing Cache Clear...")
    smart_cache.clear()
    print("   Cache cleared.")

def main():
    """Run smart caching demonstrations"""
    print("🚀 SecureScout Smart Caching System Demo")
    print("=" * 50)

    try:
        cache = demo_basic_caching()
        demo_smart_features(cache)
        demo_predictive_caching(cache)
        demo_smart_eviction(cache)
        demo_cache_analytics()
        demo_persistence()
        print("\n✅ Smart Caching Demo Complete!")
        final_stats = smart_cache.get_stats()
        print(f"\nFinal Cache Stats:")
        print(f"   Entries: {final_stats['size']} / {final_stats['max_size']}")
        print(f"   Default TTL: {final_stats['default_ttl']} seconds")
    except Exception as e:
        logger.error(f"Demo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()