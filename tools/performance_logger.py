#!/usr/bin/env python3
"""
Performance Logger for NMAP Automator
Detailed performance tracking and logging system
"""

import json
import logging
import time
import psutil
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

@dataclass
class PerformanceEvent:
    """Single performance event record"""
    timestamp: str
    event_type: str  # scan_start, scan_end, tool_start, tool_end, etc.
    operation: str   # nmap, nikto, gobuster, etc.
    target: str
    duration: Optional[float] = None
    memory_mb: Optional[float] = None
    cpu_percent: Optional[float] = None
    status: str = "success"
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}

class DetailedPerformanceLogger:
    """Comprehensive performance logging system"""
    
    def __init__(self, log_dir: str = "results/performance_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.current_operations = {}  # Track ongoing operations
        self.performance_events = []
        self._lock = threading.RLock()
        
        # Setup performance log file
        self.log_file = self.log_dir / f"performance_{datetime.now().strftime('%Y%m%d')}.log"
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup detailed performance logging"""
        self.logger = logging.getLogger('performance_logger')
        self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # File handler
        file_handler = logging.FileHandler(self.log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler for important events
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter('📊 %(message)s')
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.INFO)
        self.logger.addHandler(console_handler)
    
    def start_operation(self, operation: str, target: str, details: Dict[str, Any] = None) -> str:
        """Start tracking a performance operation"""
        with self._lock:
            operation_id = f"{operation}_{target}_{int(time.time())}"
            
            event = PerformanceEvent(
                timestamp=datetime.now().isoformat(),
                event_type="operation_start",
                operation=operation,
                target=target,
                details=details or {}
            )
            
            self.current_operations[operation_id] = {
                'start_time': time.time(),
                'start_memory': psutil.virtual_memory().used / 1024 / 1024,
                'event': event
            }
            
            self.performance_events.append(event)
            self.logger.info(f"Started {operation} operation on {target}")
            
            return operation_id
    
    def end_operation(self, operation_id: str, status: str = "success", 
                     details: Dict[str, Any] = None) -> Optional[PerformanceEvent]:
        """End tracking a performance operation"""
        with self._lock:
            if operation_id not in self.current_operations:
                self.logger.warning(f"Operation {operation_id} not found in tracking")
                return None
            
            op_data = self.current_operations[operation_id]
            start_event = op_data['event']
            
            # Calculate metrics
            end_time = time.time()
            duration = end_time - op_data['start_time']
            current_memory = psutil.virtual_memory().used / 1024 / 1024
            memory_delta = current_memory - op_data['start_memory']
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            end_event = PerformanceEvent(
                timestamp=datetime.now().isoformat(),
                event_type="operation_end",
                operation=start_event.operation,
                target=start_event.target,
                duration=duration,
                memory_mb=memory_delta,
                cpu_percent=cpu_percent,
                status=status,
                details=details or {}
            )
            
            self.performance_events.append(end_event)
            
            # Log performance summary
            self.logger.info(
                f"Completed {start_event.operation} on {start_event.target} - "
                f"Duration: {duration:.2f}s, Memory: {memory_delta:+.1f}MB, "
                f"CPU: {cpu_percent:.1f}%, Status: {status}"
            )
            
            # Remove from tracking
            del self.current_operations[operation_id]
            
            return end_event
    
    def log_event(self, event_type: str, operation: str, target: str,
                  details: Dict[str, Any] = None):
        """Log a standalone performance event"""
        with self._lock:
            event = PerformanceEvent(
                timestamp=datetime.now().isoformat(),
                event_type=event_type,
                operation=operation,
                target=target,
                memory_mb=psutil.virtual_memory().used / 1024 / 1024,
                cpu_percent=psutil.cpu_percent(interval=0.1),
                details=details or {}
            )
            
            self.performance_events.append(event)
            self.logger.info(f"Event: {event_type} - {operation} - {target}")
    
    def get_performance_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get performance summary for specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_events = [
            e for e in self.performance_events
            if datetime.fromisoformat(e.timestamp) > cutoff_time
        ]
        
        if not recent_events:
            return {"message": f"No events in last {hours} hours"}
        
        # Calculate statistics
        completed_operations = [
            e for e in recent_events 
            if e.event_type == "operation_end" and e.duration is not None
        ]
        
        if completed_operations:
            durations = [op.duration for op in completed_operations]
            avg_duration = sum(durations) / len(durations)
            max_duration = max(durations)
            min_duration = min(durations)
            
            memory_usage = [op.memory_mb for op in completed_operations if op.memory_mb]
            avg_memory = sum(memory_usage) / len(memory_usage) if memory_usage else 0
            
            # Group by operation type
            by_operation = {}
            for op in completed_operations:
                if op.operation not in by_operation:
                    by_operation[op.operation] = []
                by_operation[op.operation].append(op.duration)
            
            operation_stats = {}
            for op_type, durations in by_operation.items():
                operation_stats[op_type] = {
                    'count': len(durations),
                    'avg_duration': sum(durations) / len(durations),
                    'total_duration': sum(durations)
                }
        else:
            avg_duration = max_duration = min_duration = avg_memory = 0
            operation_stats = {}
        
        return {
            'time_period_hours': hours,
            'total_events': len(recent_events),
            'completed_operations': len(completed_operations),
            'performance_metrics': {
                'avg_duration_seconds': round(avg_duration, 2),
                'max_duration_seconds': round(max_duration, 2),
                'min_duration_seconds': round(min_duration, 2),
                'avg_memory_delta_mb': round(avg_memory, 2)
            },
            'by_operation': operation_stats,
            'success_rate': self._calculate_success_rate(completed_operations)
        }
    
    def _calculate_success_rate(self, operations: List[PerformanceEvent]) -> float:
        """Calculate success rate percentage"""
        if not operations:
            return 100.0
        
        successful = sum(1 for op in operations if op.status == "success")
        return round((successful / len(operations)) * 100, 2)
    
    def export_performance_data(self, format_type: str = "json", 
                               hours: int = 24) -> str:
        """Export performance data in specified format"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_events = [
            e for e in self.performance_events
            if datetime.fromisoformat(e.timestamp) > cutoff_time
        ]
        
        if format_type == "json":
            export_data = {
                'export_time': datetime.now().isoformat(),
                'time_period_hours': hours,
                'summary': self.get_performance_summary(hours),
                'events': [asdict(event) for event in recent_events]
            }
            return json.dumps(export_data, indent=2)
        
        elif format_type == "csv":
            csv_lines = [
                "timestamp,event_type,operation,target,duration,memory_mb,cpu_percent,status"
            ]
            for event in recent_events:
                csv_lines.append(
                    f"{event.timestamp},{event.event_type},{event.operation},"
                    f"{event.target},{event.duration or ''},"
                    f"{event.memory_mb or ''},{event.cpu_percent or ''},{event.status}"
                )
            return '\n'.join(csv_lines)
        
        else:  # text format
            summary = self.get_performance_summary(hours)
            report = f"""
PERFORMANCE REPORT - Last {hours} Hours
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

SUMMARY:
- Total Events: {summary.get('total_events', 0)}
- Completed Operations: {summary.get('completed_operations', 0)}
- Success Rate: {summary.get('success_rate', 0)}%

PERFORMANCE METRICS:
- Average Duration: {summary.get('performance_metrics', {}).get('avg_duration_seconds', 0):.2f}s
- Maximum Duration: {summary.get('performance_metrics', {}).get('max_duration_seconds', 0):.2f}s
- Average Memory Delta: {summary.get('performance_metrics', {}).get('avg_memory_delta_mb', 0):.2f}MB

BY OPERATION:
"""
            
            for op_type, stats in summary.get('by_operation', {}).items():
                report += f"- {op_type.upper()}: {stats['count']} operations, "
                report += f"avg {stats['avg_duration']:.2f}s\n"
            
            return report
    
    def save_performance_report(self, format_type: str = "json", 
                               hours: int = 24) -> str:
        """Save performance report to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"performance_report_{timestamp}.{format_type}"
        file_path = self.log_dir / filename
        
        report_content = self.export_performance_data(format_type, hours)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        self.logger.info(f"Performance report saved: {filename}")
        return str(file_path)
    
    def cleanup_old_events(self, days: int = 7):
        """Clean up events older than specified days"""
        cutoff_time = datetime.now() - timedelta(days=days)
        
        original_count = len(self.performance_events)
        self.performance_events = [
            e for e in self.performance_events
            if datetime.fromisoformat(e.timestamp) > cutoff_time
        ]
        
        removed_count = original_count - len(self.performance_events)
        if removed_count > 0:
            self.logger.info(f"Cleaned up {removed_count} old performance events")


# Global performance logger instance
performance_logger = DetailedPerformanceLogger()


class PerformanceContext:
    """Context manager for performance tracking"""
    
    def __init__(self, operation: str, target: str, details: Dict[str, Any] = None):
        self.operation = operation
        self.target = target
        self.details = details or {}
        self.operation_id = None
    
    def __enter__(self):
        self.operation_id = performance_logger.start_operation(
            self.operation, self.target, self.details
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        status = "success" if exc_type is None else "error"
        if self.operation_id:
            performance_logger.end_operation(self.operation_id, status)


def track_performance(operation: str, target: str):
    """Decorator for performance tracking"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with PerformanceContext(operation, target):
                return func(*args, **kwargs)
        return wrapper
    return decorator


def main():
    """Demo function for performance logger"""
    print("📊 NMAP Automator Performance Logger Demo")
    print("=" * 50)
    
    # Demo performance tracking
    with PerformanceContext("nmap", "example.com", {"scan_type": "fast"}):
        time.sleep(2)  # Simulate scan
        performance_logger.log_event("vulnerability_found", "nmap", "example.com", 
                                   {"severity": "medium"})
    
    # Show summary
    summary = performance_logger.get_performance_summary(1)
    print("\nPerformance Summary (Last Hour):")
    print(json.dumps(summary, indent=2))
    
    # Save report
    report_path = performance_logger.save_performance_report("json", 1)
    print(f"\n📄 Performance report saved: {report_path}")


if __name__ == "__main__":
    main()