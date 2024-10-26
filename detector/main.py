import os
import time
from watchdog.observers import Observer
from .file_monitor import FileMonitor

def start_monitoring(directory_path):
    """Start the ransomware detection monitoring system."""
    print("🛡️ Starting Ransomware Detection System")
    print(f"📁 Monitoring directory: {directory_path}")
    print("Press Ctrl+C to stop monitoring\n")
    
    event_handler = FileMonitor(directory_path)
    observer = Observer()
    observer.schedule(event_handler, directory_path, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n🛑 Monitoring stopped")
    observer.join()

if __name__ == "__main__":
    watch_directory = os.getenv('WATCH_DIR', '.')
    start_monitoring(watch_directory)