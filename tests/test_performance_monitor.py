from performance_monitor import profiler
import time

def test_func():
    time.sleep(0.2)
    return "done"

test_func = profiler.profile_function(test_func)

if __name__ == "__main__":
    print("Testing performance monitoring...")
    result = test_func()
    print(f"Result: {result}")
