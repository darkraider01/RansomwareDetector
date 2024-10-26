# Enhanced Ransomware Detection System

This system combines blockchain technology with local file monitoring to detect and respond to potential ransomware activity.

## Components

1. Smart Contract (`contracts/RansomwareDetection.sol`):
   - Stores and manages ransomware detection records on the blockchain
   - Implements a trusted reporter system
   - Provides verification and confirmation mechanisms

2. Python Detection System:
   - `config.py`: Configuration settings and patterns
   - `file_monitor.py`: File system monitoring
   - `threat_analyzer.py`: Threat detection and analysis
   - `response_handler.py`: Threat response system
   - `main.py`: Main application entry point

## Features

### Detection
- Real-time file system monitoring
- Extensive suspicious file extension detection
- Advanced content pattern analysis
- High entropy detection for encrypted files
- Rapid file modification detection
- Blockchain-based reporting system

### Response System
- Threat level classification (0-3)
- Automatic file quarantine
- Emergency network disconnection
- Email notifications
- Detailed logging
- Blockchain reporting integration

## Setup

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure the system:
   - Update `config.py` with your settings
   - Set up email notifications
   - Configure blockchain integration

3. Start the monitoring system:
   ```bash
   python -m detector.main
   ```

## Security Notes

- This system should be used as part of a comprehensive security strategy
- Regular backups are essential
- Keep all security tools and systems updated
- Monitor system logs regularly
- Test and update detection patterns periodically

## Response Levels

1. **Critical Threat (Level 3)**:
   - Immediate file quarantine
   - Network disconnection
   - Emergency notifications
   - Blockchain reporting
   - System shutdown if configured

2. **High Threat (Level 2)**:
   - File quarantine
   - Administrator notification
   - Detailed logging
   - Blockchain reporting

3. **Low Threat (Level 1)**:
   - Enhanced monitoring
   - Logging
   - Optional notifications#   R a n s o m w a r e D e t e c t o r  
 