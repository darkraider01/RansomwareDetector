# Detection configuration
SUSPICIOUS_EXTENSIONS = {
    '.encrypted', '.locked', '.crypto', '.crypted', '.crypt', 
    '.vault', '.onion', '.wncry', '.locky', '.wannacry',
    '.wcry', '.keybtc@inbox_com', '.key', '.ecc', '.encrypted',
    '.ezz', '.ecc', '.exx', '.zzz', '.xyz', '.aaa', '.abc', 
    '.ccc', '.vvv', '.xxx', '.ttt', '.micro', '.encrypted',
    '.locked', '.crypto', '_crypt', '.crinf', '.r5a', '.XRNT',
    '.XTBL', '.crypt', '.R16M01D05', '.pzdc', '.good', '.LOL!',
    '.OMG!', '.RDM', '.RRK', '.encryptedRSA', '.crjoker',
    '.EnCiPhErEd', '.LeChiffre'
}

SUSPICIOUS_PATTERNS = [
    b'DECRYPT_INSTRUCTION',
    b'YOUR_FILES_ARE_ENCRYPTED',
    b'bitcoin',
    b'ransom',
    b'decrypt',
    b'encrypted files',
    b'pay',
    b'bitcoin wallet',
    b'recovery files',
    b'how to decrypt',
    b'your personal files',
    b'your documents',
    b'send money',
    b'payment'
]

# Response configuration
BACKUP_DIR = "quarantine"
MAX_FILE_SIZE_MB = 100
NOTIFICATION_EMAIL = "admin@example.com"
SYSTEM_COMMANDS = {
    'windows': {
        'network_disconnect': 'netsh interface set interface "Ethernet" disable',
        'shutdown': 'shutdown /s /t 0',
    },
    'linux': {
        'network_disconnect': 'sudo ifconfig eth0 down',
        'shutdown': 'sudo shutdown now',
    }
}