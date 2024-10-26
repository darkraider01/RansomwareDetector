from web3 import Web3
import json
import os

class BlockchainReporter:
    def __init__(self):
        # Connect to local Ganache instance
        self.w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
        
        # Load contract ABI and address
        with open('build/contracts/RansomwareDetection.json') as f:
            contract_data = json.load(f)
            self.contract_abi = contract_data['abi']
            
        # Get deployed contract address from Truffle deployment
        self.contract_address = self._get_contract_address()
        
        # Initialize contract
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.contract_abi
        )
        
        # Set default account
        self.w3.eth.default_account = self.w3.eth.accounts[0]
        
    def _get_contract_address(self):
        """Get contract address from Truffle deployment."""
        network_id = self.w3.net.version
        with open('build/contracts/RansomwareDetection.json') as f:
            contract_data = json.load(f)
            return contract_data['networks'][network_id]['address']
            
    def report_detection(self, file_hash, timestamp):
        """Report ransomware detection to blockchain."""
        try:
            tx_hash = self.contract.functions.reportDetection(
                file_hash,
                timestamp
            ).transact()
            
            # Wait for transaction receipt
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"Detection reported to blockchain. Transaction hash: {tx_hash.hex()}")
            return tx_receipt
            
        except Exception as e:
            print(f"Error reporting to blockchain: {str(e)}")
            return None