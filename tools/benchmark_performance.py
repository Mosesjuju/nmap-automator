#!/usr/bin/env python3
"""
Performance Benchmark Script for NMAP Automator v1.2.1
Compare performance between optimized and standard versions
"""

import asyncio
import time
import subprocess
import json
import statistics
from datetime import datetime
from pathlib import Path
import argparse

class PerformanceBenchmark:
    """Performance benchmarking suite"""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'benchmarks': {},
            'system_info': self.get_system_info()
        }
        
    def get_system_info(self):
        """Collect system information"""
        try:
            import psutil
            return {
                'cpu_count': psutil.cpu_count(),
                'memory_total_gb': psutil.virtual_memory().total / 1024**3,
                'python_version': subprocess.check_output(['python3', '--version']).decode().strip()
            }
        except:
            return {'error': 'Could not collect system info'}
            
    def benchmark_scan_performance(self, target="scanme.nmap.org", iterations=3):
        """Benchmark scan performance"""
        
        print(f"🎯 Benchmarking scan performance on {target} ({iterations} iterations)")
        
        # Test configurations
        configs = {
            'standard_fast': ['python3', 'nmap_automator_new.py', '--fast-scan', target],
            'optimized_fast': ['python3', 'nmap_automator_optimized.py', '--fast-scan', target],
            'optimized_async': ['python3', 'nmap_automator_optimized.py', '--async-mode', '--fast-scan', target],
            'optimized_masscan': ['python3', 'nmap_automator_optimized.py', '--masscan-fast', target]
        }
        
        for config_name, cmd in configs.items():
            print(f"\n⚡ Testing {config_name}...")
            times = []
            
            for i in range(iterations):
                print(f"   Run {i+1}/{iterations}...", end=' ')
                
                start_time = time.time()
                try:
                    result = subprocess.run(cmd + ['--dry-run'], 
                                          capture_output=True, text=True, timeout=60)
                    end_time = time.time()
                    
                    if result.returncode == 0:
                        duration = end_time - start_time
                        times.append(duration)
                        print(f"{duration:.2f}s ✅")
                    else:
                        print(f"❌ Failed: {result.stderr}")
                        
                except subprocess.TimeoutExpired:
                    print("⏰ Timeout")
                    
                except Exception as e:
                    print(f"❌ Error: {e}")
            
            if times:
                self.results['benchmarks'][config_name] = {
                    'iterations': len(times),
                    'times': times,
                    'avg_time': statistics.mean(times),
                    'min_time': min(times),
                    'max_time': max(times),
                    'std_dev': statistics.stdev(times) if len(times) > 1 else 0
                }
                
                print(f"   📊 Average: {statistics.mean(times):.2f}s")
                
    def benchmark_memory_usage(self):
        """Benchmark memory usage patterns"""
        
        print("\n🧠 Benchmarking memory usage...")
        
        # Memory test script
        memory_test_script = '''
import sys
sys.path.append('.')
from performance_optimizer import global_cache, performance_profiler
import time

# Simulate cache usage
for i in range(1000):
    global_cache.set(f"key_{i}", f"value_{i}" * 100)

# Get memory stats
stats = performance_profiler.memory_optimizer.get_memory_stats()
print(f"Memory usage: {stats['process_usage_mb']:.2f} MB")
print(f"Tracked objects: {stats['tracked_objects']}")
'''
        
        try:
            result = subprocess.run(['python3', '-c', memory_test_script], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.results['memory_benchmark'] = {
                    'output': result.stdout.strip(),
                    'status': 'success'
                }
                print(f"   ✅ {result.stdout.strip()}")
            else:
                print(f"   ❌ Memory test failed: {result.stderr}")
                
        except Exception as e:
            print(f"   ❌ Memory test error: {e}")
            
    def benchmark_async_performance(self):
        """Benchmark async operations"""
        
        print("\n⚡ Benchmarking async performance...")
        
        async_test_script = '''
import asyncio
import sys
sys.path.append('.')
from async_scan_engine import async_quick_scan
import time

async def test_async():
    targets = ["127.0.0.1", "localhost"]
    start = time.time()
    results = await async_quick_scan(targets, [22, 80, 443])
    end = time.time()
    print(f"Async scan time: {end - start:.2f}s")
    print(f"Results: {len(results)} targets processed")

asyncio.run(test_async())
'''
        
        try:
            result = subprocess.run(['python3', '-c', async_test_script], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.results['async_benchmark'] = {
                    'output': result.stdout.strip(),
                    'status': 'success'
                }
                print(f"   ✅ {result.stdout.strip()}")
            else:
                print(f"   ❌ Async test failed: {result.stderr}")
                
        except Exception as e:
            print(f"   ❌ Async test error: {e}")
            
    def benchmark_caching_effectiveness(self):
        """Test caching performance"""
        
        print("\n💾 Benchmarking cache effectiveness...")
        
        cache_test_script = '''
import sys
sys.path.append('.')
from performance_optimizer import global_cache
import time

# Clear cache
global_cache.clear()

# Test cache misses
start = time.time()
for i in range(100):
    result = global_cache.get(f"test_key_{i}")
miss_time = time.time() - start

# Populate cache
for i in range(100):
    global_cache.set(f"test_key_{i}", f"test_value_{i}")

# Test cache hits
start = time.time()
for i in range(100):
    result = global_cache.get(f"test_key_{i}")
hit_time = time.time() - start

stats = global_cache.get_stats()
print(f"Cache misses (100 ops): {miss_time:.4f}s")
print(f"Cache hits (100 ops): {hit_time:.4f}s")
print(f"Speed improvement: {(miss_time / hit_time):.2f}x faster")
print(f"Hit rate: {stats['hit_rate']}")
'''
        
        try:
            result = subprocess.run(['python3', '-c', cache_test_script], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.results['cache_benchmark'] = {
                    'output': result.stdout.strip(),
                    'status': 'success'
                }
                print(f"   ✅ Cache Performance:")
                for line in result.stdout.strip().split('\n'):
                    print(f"      {line}")
            else:
                print(f"   ❌ Cache test failed: {result.stderr}")
                
        except Exception as e:
            print(f"   ❌ Cache test error: {e}")
            
    def generate_performance_comparison(self):
        """Generate performance comparison report"""
        
        if 'benchmarks' not in self.results or not self.results['benchmarks']:
            print("❌ No benchmark data available for comparison")
            return
            
        print(f"\n📊 PERFORMANCE COMPARISON REPORT")
        print("="*60)
        
        benchmarks = self.results['benchmarks']
        
        # Find baseline (standard_fast)
        baseline_name = 'standard_fast'
        if baseline_name in benchmarks:
            baseline_time = benchmarks[baseline_name]['avg_time']
            
            print(f"Baseline ({baseline_name}): {baseline_time:.2f}s")
            print("-" * 40)
            
            for name, data in benchmarks.items():
                if name != baseline_name:
                    avg_time = data['avg_time']
                    improvement = ((baseline_time - avg_time) / baseline_time) * 100
                    
                    status = "🚀" if improvement > 0 else "🐌"
                    print(f"{status} {name:20}: {avg_time:6.2f}s ({improvement:+5.1f}%)")
        else:
            print("📊 Individual Results:")
            for name, data in benchmarks.items():
                print(f"   {name}: {data['avg_time']:.2f}s ±{data['std_dev']:.2f}s")
                
    def save_results(self, filename="performance_benchmark.json"):
        """Save benchmark results"""
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
            
        print(f"\n💾 Results saved to {filename}")
        
    def run_full_benchmark(self, target="scanme.nmap.org"):
        """Run complete performance benchmark suite"""
        
        print(f"🚀 NMAP Automator v1.2.1 Performance Benchmark")
        print(f"Target: {target}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        # Run all benchmarks
        self.benchmark_scan_performance(target)
        self.benchmark_memory_usage()
        self.benchmark_async_performance()
        self.benchmark_caching_effectiveness()
        
        # Generate comparison report
        self.generate_performance_comparison()
        
        # Save results
        self.save_results()
        
        print(f"\n✅ Benchmark completed!")


def main():
    parser = argparse.ArgumentParser(description='NMAP Automator Performance Benchmark')
    parser.add_argument('--target', default='scanme.nmap.org', 
                       help='Target for benchmark scans')
    parser.add_argument('--iterations', type=int, default=3,
                       help='Number of benchmark iterations')
    parser.add_argument('--quick', action='store_true',
                       help='Run quick benchmark (fewer tests)')
    
    args = parser.parse_args()
    
    benchmark = PerformanceBenchmark()
    
    if args.quick:
        print("⚡ Running quick benchmark...")
        benchmark.benchmark_scan_performance(args.target, iterations=1)
        benchmark.benchmark_caching_effectiveness()
        benchmark.generate_performance_comparison()
    else:
        benchmark.run_full_benchmark(args.target)


if __name__ == '__main__':
    main()