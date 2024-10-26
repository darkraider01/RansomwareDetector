import os
import hashlib
from watchdog.events import FileSystemEventHandler
from .threat_analyzer import ThreatAnalyzer
from .response_handler import ResponseHandler

class FileMonitor(FileSystemEventHandler):
    def __init__(self, watch_directory):
        self.watch_directory = watch_directory
        self.threat_analyzer = ThreatAnalyzer()
        self.response_handler = ResponseHandler()
        
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Error calculating hash for {file_path}: {str(e)}")
            return None
    
    def on_created(self, event):
        if event.is_directory:
            return
            
        file_path = event.src_path
        threat_level = self.threat_analyzer.analyze_file(file_path)
        
        if threat_level > 0:
            detection = {
                'file_path': file_path,
                'file_hash': self.calculate_file_hash(file_path),
                'timestamp': self.threat_analyzer.get_timestamp(),
                'threat_level': threat_level,
                'reason': self.threat_analyzer.get_threat_reason()
            }
            self.response_handler.handle_threat(detection)