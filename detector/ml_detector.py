import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime
import magic
import math

class MLDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self._initialize_model()
        
    def _initialize_model(self):
        """Initialize or load the ML model."""
        model_path = 'models/ransomware_detector.joblib'
        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
        else:
            self.model = self._train_initial_model()
            os.makedirs('models', exist_ok=True)
            joblib.dump(self.model, model_path)
    
    def _train_initial_model(self):
        """Train initial model with known ransomware patterns."""
        # Initialize Random Forest Classifier
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        # Train with basic known patterns
        X = np.array([
            # [entropy, file_ops_per_sec, size_change_ratio, is_encrypted]
            [7.9, 50, 0.9, 1],  # Ransomware pattern
            [7.8, 45, 0.85, 1],  # Ransomware pattern
            [5.2, 2, 0.1, 0],   # Normal file
            [5.0, 3, 0.15, 0],  # Normal file
        ])
        y = np.array([1, 1, 0, 0])  # 1 for ransomware, 0 for normal
        
        # Fit the model
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        model.fit(X_scaled, y)
        
        return model
    
    def extract_features(self, file_path):
        """Extract features from a file for ML analysis."""
        features = {}
        
        try:
            # File entropy
            features['entropy'] = self._calculate_entropy(file_path)
            
            # File operations frequency
            features['file_ops'] = self._get_file_operations_frequency(file_path)
            
            # File size change ratio
            features['size_change'] = self._get_size_change_ratio(file_path)
            
            # File type analysis
            features['is_encrypted'] = self._check_encryption_indicators(file_path)
            
            return np.array([[
                features['entropy'],
                features['file_ops'],
                features['size_change'],
                features['is_encrypted']
            ]])
            
        except Exception as e:
            print(f"Error extracting features: {str(e)}")
            return None
    
    def _calculate_entropy(self, file_path):
        """Calculate Shannon entropy of file content."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                if not data:
                    return 0
                    
                # Calculate byte frequency
                byte_counts = {}
                for byte in data:
                    byte_counts[byte] = byte_counts.get(byte, 0) + 1
                
                # Calculate entropy
                entropy = 0
                for count in byte_counts.values():
                    probability = count / len(data)
                    entropy -= probability * math.log2(probability)
                    
                return entropy
                
        except Exception:
            return 0
    
    def _get_file_operations_frequency(self, file_path):
        """Analyze file operations frequency."""
        try:
            stat = os.stat(file_path)
            current_time = datetime.now().timestamp()
            time_diff = current_time - stat.st_mtime
            
            # Check modifications in last minute
            if time_diff <= 60:
                return 1.0
            return 0.0
            
        except Exception:
            return 0.0
    
    def _get_size_change_ratio(self, file_path):
        """Analyze file size changes."""
        try:
            current_size = os.path.getsize(file_path)
            # Compare with typical size for file type
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            
            # Define expected sizes for different file types
            expected_sizes = {
                'text/plain': 1024 * 10,  # 10KB
                'text/html': 1024 * 50,   # 50KB
                'image/jpeg': 1024 * 500, # 500KB
                'image/png': 1024 * 200,  # 200KB
                'application/pdf': 1024 * 1024, # 1MB
            }
            
            expected_size = expected_sizes.get(file_type, current_size)
            if expected_size == 0:
                return 0
                
            return abs(current_size - expected_size) / expected_size
            
        except Exception:
            return 0
    
    def _check_encryption_indicators(self, file_path):
        """Check for indicators of encryption."""
        try:
            # Check file type
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            
            # Check entropy
            entropy = self._calculate_entropy(file_path)
            
            # High entropy and unrecognized format often indicate encryption
            return 1.0 if (entropy > 7.5 and 'application/octet-stream' in file_type) else 0.0
            
        except Exception:
            return 0
    
    def predict_threat(self, file_path):
        """Predict if a file is potentially ransomware."""
        features = self.extract_features(file_path)
        if features is None:
            return 0
            
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Get prediction and probability
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0][1]
        
        # Return threat level based on probability
        if probability > 0.8:
            return 3  # Critical threat
        elif probability > 0.6:
            return 2  # High threat
        elif probability > 0.4:
            return 1  # Low threat
        return 0  # No threat
    
    def update_model(self, file_path, is_ransomware):
        """Update the model with new data."""
        features = self.extract_features(file_path)
        if features is None:
            return
            
        # Update model with new data
        X = features
        y = np.array([1 if is_ransomware else 0])
        
        # Retrain model
        X_scaled = self.scaler.transform(X)
        self.model.fit(X_scaled, y)
        
        # Save updated model
        joblib.dump(self.model, 'models/ransomware_detector.joblib')