#!/usr/bin/env python3
"""
Smart Caching Test and Demo for SecureScout
Demonstrates the advanced caching capabilities
"""

import sys
import os
import time
sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))

from performance_optimizer import IntelligentCache, smart_cache_manager
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def demo_basic_caching():
    """Demo basic caching functionality"""
    print("🔍 Testing Basic Caching...")
    
    cache = IntelligentCache(max_size=100, default_ttl=300)
    
    @cache.cached(ttl=60)
    def expensive_operation(n):
        """Simulate expensive computation"""
        time.sleep(0.1)  # Simulate work
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
    
    stats = cache.get_stats()
    print(f"   Cache stats: {stats['performance']['hit_rate']} hit rate")
    
    return cache

def demo_smart_features(cache):
    """Demo smart caching features"""
    print("\n🧠 Testing Smart Caching Features...")
    
    # Test adaptive TTL
    @cache.cached(track_performance=True)
    def variable_complexity(complexity):
        """Function with variable computation time"""
        time.sleep(complexity / 10)  # Variable delay
        return f"result_{complexity}"
    
    # Test different complexities
    for complexity in [1, 5, 10]:  # 0.1s, 0.5s, 1.0s
        start = time.time()
        result = variable_complexity(complexity)
        duration = time.time() - start
        print(f"   Complexity {complexity}: {duration:.3f}s")
    
    # Test cache hits with adaptive TTL
    for complexity in [1, 5, 10]:
        start = time.time()
        result = variable_complexity(complexity)  # Should be cache hits
        duration = time.time() - start
        print(f"   Cached complexity {complexity}: {duration:.3f}s (cached)")

def demo_predictive_caching(cache):
    """Demo predictive caching"""
    print("\n🔮 Testing Predictive Caching...")
    
    @cache.cached()
    def sequential_operation(n):
        """Simulate sequential access pattern"""
        time.sleep(0.05)
        return f"data_{n}"
    
    # Create access pattern
    print("   Creating access pattern...")
    for i in range(5):
        result = sequential_operation(i)
        time.sleep(0.1)  # Simulate regular interval
    
    # Access pattern should be learned now
    print("   Testing pattern prediction...")
    for i in range(5, 10):
        start = time.time()
        result = sequential_operation(i)
        duration = time.time() - start
        print(f"   Access {i}: {duration:.3f}s")

def demo_smart_eviction(cache):
    """Demo smart eviction based on priority"""
    print("\n🎯 Testing Smart Eviction...")
    
    # Fill cache beyond capacity
    @cache.cached()
    def data_generator(key, computation_time=0.01):
        time.sleep(computation_time)
        return f"value_for_{key}"
    
    print("   Filling cache with different priority items...")
    
    # High priority (frequent access, expensive computation)
    for _ in range(3):
        data_generator("high_priority", 0.1)  # Expensive
    
    # Medium priority  
    for _ in range(2):
        data_generator("medium_priority", 0.05)
    
    # Low priority (quick computation, infrequent access)
    data_generator("low_priority", 0.01)
    
    # Fill cache to trigger eviction
    for i in range(150):  # Exceed cache capacity
        data_generator(f"filler_{i}", 0.001)
    
    # Check what survived eviction
    test_keys = ["high_priority", "medium_priority", "low_priority"]
    for key in test_keys:
        start = time.time()
        result = data_generator(key)
        duration = time.time() - start
        status = "HIT" if duration < 0.01 else "MISS"
        print(f"   {key}: {status} ({duration:.3f}s)")

def demo_cache_analytics():
    """Demo comprehensive cache analytics"""
    print("\n📊 Testing Cache Analytics...")
    
    manager = smart_cache_manager()
    
    # Warm up cache
    warmed = manager.warm_up_common_patterns()
    print(f"   Warmed up cache with {warmed} common patterns")
    
    # Get analytics
    analytics = manager.get_analytics()
    print(f"   Current hit rate: {analytics['performance']['hit_rate']}")
    print(f"   Cache entries: {analytics['size_metrics']['entries']}")
    print(f"   Memory usage: {analytics['size_metrics']['memory_mb']}")
    
    # Optimize cache
    optimization = manager.optimize()
    print(f"   Optimization applied: {len(optimization['recommendations'])} recommendations")
    for rec in optimization['recommendations'][:2]:
        print(f"     • {rec}")
    
    # Adaptive resize test
    resize_result = manager.adaptive_resize()
    print(f"   Adaptive resize: {resize_result}")
    
    # Export performance report
    report = manager.export_performance_report()
    print(f"   Performance report generated with {len(report['cache_analytics'])} metrics")

def demo_persistence():
    """Demo cache persistence"""
    print("\n💾 Testing Cache Persistence...")
    
    # Create cache with persistence
    persistent_cache = IntelligentCache(max_size=50, enable_persistence=True)
    
    @persistent_cache.cached()
    def persistent_data(key):
        time.sleep(0.1)
        return f"persistent_value_{key}"
    
    # Generate some data
    for i in range(5):
        result = persistent_data(f"key_{i}")
    
    print("   Generated persistent data")
    
    # Save and clear
    persistent_cache.clear(save_to_persistence=True)
    print("   Cache cleared and saved to persistence")
    
    # Create new cache instance (simulates restart)
    new_cache = IntelligentCache(max_size=50, enable_persistence=True)
    
    # Check if data was restored
    stats = new_cache.get_stats()
    print(f"   Restored cache entries: {stats['size_metrics']['entries']}")

def main():
    """Run smart caching demonstrations"""
    print("🚀 SecureScout Smart Caching System Demo")
    print("=" * 50)
    
    try:
        # Basic caching
        cache = demo_basic_caching()
        
        # Smart features
        demo_smart_features(cache)
        
        # Predictive caching
        demo_predictive_caching(cache)
        
        # Smart eviction
        demo_smart_eviction(cache)
        
        # Analytics
        demo_cache_analytics()
        
        # Persistence
        demo_persistence()
        
        print("\n✅ Smart Caching Demo Complete!")
        
        # Final stats
        final_stats = cache.get_stats()
        print(f"\nFinal Performance:")
        print(f"   Hit Rate: {final_stats['performance']['hit_rate']}")
        print(f"   Predictive Success: {final_stats['performance']['predictive_rate']}")
        print(f"   Adaptive TTL Usage: {final_stats['performance']['adaptive_rate']}")
        print(f"   Memory Usage: {final_stats['size_metrics']['memory_mb']}")
        
    except Exception as e:
        logger.error(f"Demo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()