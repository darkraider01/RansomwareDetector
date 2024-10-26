import os
import hashlib
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import json

class RansomwareDetector(FileSystemEventHandler):
    def __init__(self, watch_directory):
        self.watch_directory = watch_directory
        self.suspicious_extensions = {'.encrypted', '.locked', '.crypto'}
        self.suspicious_patterns = [
            b'DECRYPT_INSTRUCTION',
            b'YOUR_FILES_ARE_ENCRYPTED',
            b'bitcoin',
            b'ransom'
        ]
        
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def check_file_content(self, file_path):
        """Check file content for suspicious patterns."""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                return any(pattern in content for pattern in self.suspicious_patterns)
        except:
            return False
    
    def on_created(self, event):
        if event.is_directory:
            return
            
        file_path = event.src_path
        file_ext = os.path.splitext(file_path)[1]
        
        # Check for suspicious activity
        is_suspicious = False
        
        # Check file extension
        if file_ext in self.suspicious_extensions:
            is_suspicious = True
            
        # Check file content
        if self.check_file_content(file_path):
            is_suspicious = True
            
        if is_suspicious:
            detection = {
                'file_path': file_path,
                'file_hash': self.calculate_file_hash(file_path),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'reason': 'Suspicious file detected'
            }
            self.report_detection(detection)
    
    def report_detection(self, detection):
        """Report detection to the blockchain (mock implementation)."""
        print(f"ALERT: Potential ransomware activity detected!")
        print(f"File: {detection['file_path']}")
        print(f"Hash: {detection['file_hash']}")
        print(f"Time: {detection['timestamp']}")
        print(f"Reason: {detection['reason']}")
        
        # In a real implementation, this would interact with the smart contract
        # through web3.py to report the detection

def start_monitoring(directory_path):
    event_handler = RansomwareDetector(directory_path)
    observer = Observer()
    observer.schedule(event_handler, directory_path, recursive=True)
    observer.start()
    
    try:
        print(f"Started monitoring directory: {directory_path}")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nMonitoring stopped")
    observer.join()

if __name__ == "__main__":
    watch_directory = "." # Monitor current directory
    start_monitoring(watch_directory)