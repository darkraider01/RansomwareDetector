import os
import time
from datetime import datetime
from .config import SUSPICIOUS_EXTENSIONS, SUSPICIOUS_PATTERNS
from .ml_detector import MLDetector

class ThreatAnalyzer:
    def __init__(self):
        self.last_threat_reason = ""
        self.ml_detector = MLDetector()
        
    def get_timestamp(self):
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
    def get_threat_reason(self):
        return self.last_threat_reason
        
    def analyze_file(self, file_path):
        """
        Analyzes a file for potential ransomware threats.
        Returns threat level: 0 (safe) to 3 (critical)
        """
        threat_level = 0
        reasons = []
        
        # ML-based threat detection
        ml_threat_level = self.ml_detector.predict_threat(file_path)
        if ml_threat_level > 0:
            threat_level = max(threat_level, ml_threat_level)
            reasons.append(f"ML Detection: Threat Level {ml_threat_level}")
        
        # Traditional pattern-based detection
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in SUSPICIOUS_EXTENSIONS:
            threat_level = max(threat_level, 2)
            reasons.append(f"Suspicious extension: {file_ext}")
            
        # Check file content
        try:
            if os.path.getsize(file_path) < 10 * 1024 * 1024:  # Only check files < 10MB
                with open(file_path, 'rb') as f:
                    content = f.read()
                    pattern_matches = [p for p in SUSPICIOUS_PATTERNS if p in content]
                    if pattern_matches:
                        threat_level = max(threat_level, 2)
                        reasons.append(f"Suspicious patterns: {', '.join(p.decode() for p in pattern_matches)}")
                        
                    # Check for high entropy (possible encryption)
                    if self._check_high_entropy(content):
                        threat_level = max(threat_level, 1)
                        reasons.append("High entropy content detected")
        except Exception as e:
            print(f"Error analyzing file {file_path}: {str(e)}")
            
        # Check for rapid file modifications
        if self._check_rapid_modifications(file_path):
            threat_level = max(threat_level, 3)
            reasons.append("Rapid file modifications detected")
            
        self.last_threat_reason = " | ".join(reasons)
        
        # Update ML model if high confidence detection
        if threat_level >= 2:
            self.ml_detector.update_model(file_path, True)
        elif threat_level == 0:
            self.ml_detector.update_model(file_path, False)
            
        return threat_level
        
    def _check_high_entropy(self, data, sample_size=1024):
        """Check if file content has high entropy (indicating possible encryption)."""
        if len(data) == 0:
            return False
            
        # Take a sample of the data
        sample = data[:sample_size]
        byte_counts = {}
        
        # Count byte frequencies
        for byte in sample:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / len(sample)
            entropy -= probability * (probability.bit_length())
            
        return entropy > 7.0  # High entropy threshold
        
    def _check_rapid_modifications(self, file_path):
        """Check if there are rapid modifications to files in the same directory."""
        directory = os.path.dirname(file_path)
        current_time = time.time()
        modification_times = []
        
        for f in os.listdir(directory):
            try:
                full_path = os.path.join(directory, f)
                if os.path.isfile(full_path):
                    mod_time = os.path.getmtime(full_path)
                    if current_time - mod_time < 60:  # Check last minute
                        modification_times.append(mod_time)
            except Exception:
                continue
                
        return len(modification_times) > 10  # More than 10 files modified in last minute