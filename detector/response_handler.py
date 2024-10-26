from detector.blockchain_reporter import BlockchainReporter


def __init__(self):
        self._setup_quarantine()
        self.blockchain_reporter = BlockchainReporter()  # Initialize blockchain reporter
        
def handle_threat(self, detection):
        """Handle detected ransomware threat."""
        self._log_detection(detection)
        
        # Report to blockchain for high and critical threats
        if detection['threat_level'] >= 2:
            self.blockchain_reporter.report_detection(
                detection['file_hash'],
                detection['timestamp']
            )
        
        # Rest of the threat handling logic...