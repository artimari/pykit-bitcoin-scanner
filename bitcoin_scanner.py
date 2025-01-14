#!/usr/bin/env python3

import os
import sys
import time
import logging
import hashlib
import binascii
from datetime import datetime
from pathlib import Path
from tqdm import tqdm
import stat
import json
import signal

# Constants
BLOCK_SIZE = 4096
# Enhanced Bitcoin markers
BITCOIN_MARKERS = {
    # Wallet Format Markers
    'wallet_dat': b'wallet.dat',
    'berkeley_db': b'berkeley',
    'sqlite_wallet': b'SQLite format 3',
    
    # Bitcoin Core Specific
    'bitcoin_core': b'bitcoin',
    'minikey': b'S',  # Casascius minikey format
    'bitcoin_msg': b'Bitcoin Signed Message:',
    
    # Key Formats
    'pkh_script': b'\x76\xa9\x14',  # OP_DUP OP_HASH160 Push20
    'p2sh_script': b'\xa9\x14',     # OP_HASH160 Push20
    'p2wpkh': b'\x00\x14',          # Witness v0 keyhash
    'p2wsh': b'\x00\x20',           # Witness v0 scripthash
    
    # Private Key Formats
    'pk_der': b'\x30\x81\x84',      # DER signature prefix
    'pk_pem': b'-----BEGIN PRIVATE KEY-----',
    'pk_enc': b'-----BEGIN ENCRYPTED PRIVATE KEY-----',
    'bip38': b'\x01\x42',           # BIP38 encrypted key prefix
    'pk_pkcs8': b'\x02\x01\x01',    # PKCS8 private key header
    
    # WIF Format Markers
    'wif_uncompressed': b'\x80',     # Mainnet uncompressed
    'wif_compressed': b'\x80\x01',   # Mainnet compressed
    'wif_testnet': b'\xef',         # Testnet
    
    # HD Wallet Markers
    'xprv': b'xprv',                # BIP32 private key
    'xpub': b'xpub',                # BIP32 public key
    'yprv': b'yprv',                # BIP49 private key
    'ypub': b'ypub',                # BIP49 public key
    'zprv': b'zprv',                # BIP84 private key
    'zpub': b'zpub',                # BIP84 public key
    
    # Backup Markers
    'seed_encrypt': b'Salted__',     # OpenSSL encryption marker
    'electrum': b'electrum',
    'armory': b'armory',
    'multibit': b'multibit',
    
    # Blockchain Data
    'block_magic': b'\xf9\xbe\xb4\xd9',  # Mainnet block marker
    'testnet_magic': b'\x0b\x11\x09\x07', # Testnet block marker
    
    # Common Patterns
    'base58_chars': b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    'hex_privkey': b'[0-9a-fA-F]{64}',
    
    # Wallet Software Specific
    'blockchain_info': b'blockchain.info',
    'mycelium': b'mycelium',
    'breadwallet': b'breadwallet',
    'coinbase': b'coinbase',
}

# Specific markers for pre-2012 Bitcoin Core wallet.dat
BITCOIN_MARKERS = {
    # Berkeley DB markers (wallet.dat was a Berkeley DB file)
    'berkeley_header': b'\x00\x05\x31\x62',  # Berkeley DB 4.8 header
    'berkeley_btree': b'\x00\x05\x31\x63',   # Berkeley DB B-tree magic
    
    # Bitcoin Core wallet.dat specific strings
    'wallet_name': b'wallet.dat\x00',
    'defaultkey': b'defaultkey',             # Common wallet.dat field
    'name': b'name\x00',                     # Key/value pair marker
    'version': b'version\x00',               # Wallet version marker
    
    # Key markers specific to early Bitcoin Core
    'private_key': b'\x04\x20',              # Private key length marker
    'public_key': b'\x04\x41',               # Uncompressed public key marker
    
    # Early Bitcoin address format markers (P2PKH)
    'key_header': b'\x80\x01\x01\x04',       # Private key header
    'addr_header': b'\x00\x14',              # Public key hash header
}

class BitcoinScanner:

    def get_device_name(self):
        """Get a human-readable name for the device being scanned"""
        # Check if it's a generic block device name
        generic_patterns = [
            r'^/dev/sd[a-z]\d*$',
            r'^/dev/hd[a-z]\d*$',
            r'^/dev/nvme\d+n\d+p?\d*$',
            r'^/dev/xvd[a-z]\d*$',
            r'^/dev/vd[a-z]\d*$'
        ]
        
        import re
        is_generic = any(re.match(pattern, self.input_path) for pattern in generic_patterns)
        
        if is_generic:
            print("\nScanning a block device with generic name:", self.input_path)
            while True:
                name = input("Please provide a descriptive name for this device (e.g., 'laptop_ssd_2019'): ").strip()
                if name:
                    if re.match(r'^[a-zA-Z0-9_-]+$', name):
                        return name
                    else:
                        print("Name can only contain letters, numbers, underscores, and hyphens.")
                else:
                    print("Name cannot be empty.")
        
        return os.path.basename(self.input_path)

    def __init__(self, input_path):
        self.input_path = input_path
        self.input_type = self._check_input_type()
        if self.input_type == 'unknown':
            raise ValueError(f"Input {input_path} is not a block device, disk image, or directory")
        
        # Get device name before setting up logging and results dir
        self.device_name = self.get_device_name()
        
        self.setup_logging()
        self.results_dir = self.setup_results_dir()
        self.potential_wallets = set()
        self.min_wallet_size = 16384
        self.resume_file = Path('bitcoin_scan_resume.json')
        self.current_offset = self.check_resume_point()
        self.setup_signal_handler()
        
    def _check_if_block_device(self):
        """Check if input is a block device or directory"""
        try:
            return stat.S_ISBLK(os.stat(self.input_path).st_mode)
        except:
            return False

    def _check_input_type(self):
        """Determine if input is a block device, bin file, or directory"""
        try:
            if stat.S_ISBLK(os.stat(self.input_path).st_mode):
                return 'block'
            elif self.input_path.endswith('.bin') or self.input_path.endswith('.img') or \
                self.input_path.endswith('.raw') or self.input_path.endswith('.dd'):
                return 'image'
            elif os.path.isdir(self.input_path):
                return 'directory'
            else:
                return 'unknown'
        except:
            return 'unknown'

    def setup_logging(self):
        """Configure logging with timestamp-based files"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_dir = Path('bitcoin_scan_logs')
        log_dir.mkdir(exist_ok=True)
        
        # Use device_name instead of input_path for logging
        self.logger = logging.getLogger(f'scanner_{self.device_name}')
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        fh = logging.FileHandler(log_dir / f'scan_{self.device_name}_{timestamp}.log')
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def setup_results_dir(self):
        """Create results directory structure"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_dir = Path(f'bitcoin_scan_results/{self.device_name}_{timestamp}')
        results_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (results_dir / 'fragments').mkdir(exist_ok=True)
        (results_dir / 'wallets').mkdir(exist_ok=True)
        (results_dir / 'keys').mkdir(exist_ok=True)
        
        return results_dir

    def setup_signal_handler(self):
        """Setup handler for SIGINT (Ctrl+C)"""
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signum, frame):
        """Handle Ctrl+C by saving resume point"""
        print("\n\nInterrupt received, saving resume point...")
        self.save_resume_point()
        print("\nResume point saved. Run the same command again to resume.")
        sys.exit(1)

    def save_resume_point(self):
        """Save current scanning position"""
        resume_data = {
            'input_path': self.input_path,
            'device_name': self.device_name,
            'input_type': self.input_type,
            'offset': getattr(self, 'current_offset', 0),
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            existing_data = {}
            if self.resume_file.exists():
                with open(self.resume_file, 'r') as f:
                    existing_data = json.load(f)
            
            # Store under both input_path and device_name for better lookup
            existing_data[self.input_path] = resume_data
            existing_data[self.device_name] = resume_data
            
            with open(self.resume_file, 'w') as f:
                json.dump(existing_data, f, indent=4)
            
            self.logger.info(f'Resume point saved at offset: {resume_data["offset"]}')
        except Exception as e:
            self.logger.error(f'Error saving resume point: {e}')

    def check_resume_point(self):
        """Check if a resume point exists for this input"""
        try:
            if self.resume_file.exists():
                with open(self.resume_file, 'r') as f:
                    resume_data = json.load(f)
                    
                if self.input_path in resume_data:
                    point = resume_data[self.input_path]
                    if point['input_type'] == self.input_type:
                        timestamp = datetime.fromisoformat(point['timestamp'])
                        age = datetime.now() - timestamp
                        
                        print(f"\nFound resume point for {self.input_path}")
                        print(f"Offset: {point['offset']:,} bytes")
                        print(f"Age: {age.total_seconds():.0f} seconds")
                        
                        while True:
                            response = input("\nWould you like to resume from this point? (y/n): ").lower()
                            if response in ['y', 'n']:
                                break
                        
                        if response == 'y':
                            return point['offset']
                        else:
                            # Remove the resume point if not using it
                            del resume_data[self.input_path]
                            with open(self.resume_file, 'w') as f:
                                json.dump(resume_data, f, indent=4)
            
            return 0
        except Exception as e:
            self.logger.error(f'Error checking resume point: {e}')
            return 0

    def save_fragment(self, data, offset, marker_type):
        """Save found data fragments"""
        fragment_hash = hashlib.sha256(data).hexdigest()[:16]
        fragment_path = self.results_dir / 'fragments' / f'{marker_type}_{offset}_{fragment_hash}.bin'
        
        with open(fragment_path, 'wb') as f:
            f.write(data)
        
        self.logger.debug(f'Saved fragment: {fragment_path.name}')
        return fragment_path

    def scan_block_device(self):
        """Scan a block device for Bitcoin-related data"""
        try:
            with open(self.input_path, 'rb') as device:
                device.seek(0, 2)  # Seek to end
                device_size = device.tell()
                device.seek(0)  # Reset to beginning
                
                self.logger.info(f'Device size: {device_size} bytes')
                
                # Setup progress bar
                pbar = tqdm(total=device_size, unit='B', unit_scale=True, 
                          desc=f"Scanning {self.input_path}")
                
                offset = 0
                while offset < device_size:
                    try:
                        device.seek(offset)
                        block = device.read(BLOCK_SIZE)
                        
                        if not block:
                            break
                            
                        self.analyze_block(block, offset)
                        
                        offset += len(block)
                        pbar.update(len(block))
                            
                    except IOError as e:
                        self.logger.error(f'Error reading block at offset {offset}: {e}')
                        offset += BLOCK_SIZE  # Skip problematic block
                        pbar.update(BLOCK_SIZE)
                        continue
                
                pbar.close()
                        
        except Exception as e:
            self.logger.error(f'Fatal error scanning device: {e}')
            raise

    def scan_directory(self):
        """Scan a directory recursively for Bitcoin-related data"""
        self.logger.info("Starting directory scan...")
        
        # First pass: collect all files and their sizes
        files_to_scan = []
        print("Collecting files to scan...")
        with tqdm(desc="Collecting files", unit="files") as pbar:
            for file_path in Path(self.input_path).rglob('*'):
                if file_path.is_file():
                    try:
                        size = file_path.stat().st_size
                        files_to_scan.append((file_path, size))
                        pbar.update(1)
                    except (PermissionError, OSError) as e:
                        self.logger.error(f'Error accessing file {file_path}: {e}')
                        continue

        total_size = sum(size for _, size in files_to_scan)
        processed_size = 0
        
        self.logger.info(f"Found {len(files_to_scan)} files, total size: {total_size/1024/1024:.2f} MB")
        
        # Second pass: analyze files
        with tqdm(total=total_size, unit='B', unit_scale=True,
                 desc="Analyzing files") as pbar:
            
            for file_path, file_size in files_to_scan:
                try:
                    self.logger.debug(f'Scanning file: {file_path}')
                    
                    # Skip very large files or zero-byte files
                    if file_size > 1024*1024*1024:  # 1GB
                        self.logger.warning(f'Skipping large file {file_path} ({file_size/1024/1024:.2f} MB)')
                        pbar.update(file_size)
                        continue
                    
                    if file_size == 0:
                        continue

                    with open(file_path, 'rb') as f:
                        offset = 0
                        while offset < file_size:
                            block = f.read(BLOCK_SIZE)
                            if not block:
                                break
                            
                            self.analyze_block(block, offset, str(file_path))
                            offset += len(block)
                            processed_size += len(block)
                            pbar.update(len(block))
                            
                except (PermissionError, OSError) as e:
                    self.logger.error(f'Error processing file {file_path}: {e}')
                    pbar.update(file_size - (offset if 'offset' in locals() else 0))
                    continue
    
    def analyze_block(self, block_data, offset, file_path=None):
        """Analyze a block for Bitcoin Core pre-2012 wallet data"""
        
        # Check for Berkeley DB headers first
        if BITCOIN_MARKERS['berkeley_header'] in block_data or \
           BITCOIN_MARKERS['berkeley_btree'] in block_data:
            
            # Look for additional wallet.dat indicators
            wallet_indicators = 0
            for marker_name in ['wallet_name', 'defaultkey', 'name', 'version']:
                if BITCOIN_MARKERS[marker_name] in block_data:
                    wallet_indicators += 1
            
            # If we have multiple indicators, this is likely a wallet
            if wallet_indicators >= 2:
                location = f"offset {offset}" if not file_path else f"file {file_path} at offset {offset}"
                self.logger.info(f'Found potential wallet.dat at {location}')
                
                # Extract larger context for wallet candidate
                context_start = max(0, offset - 1024)
                context_end = min(offset + len(block_data) + 1024, 
                                os.path.getsize(self.input_path))
                
                self.extract_wallet_candidate(context_start, context_end, location)
                
        # Look for key data only if we're near a wallet candidate
        if any(abs(offset - wallet_start) < 32768 
               for wallet_start in self.potential_wallets):
            
            for key_marker in ['private_key', 'public_key', 'key_header']:
                if BITCOIN_MARKERS[key_marker] in block_data:
                    self.analyze_potential_key(block_data, offset, key_marker)

    def extract_wallet_candidate(self, start_offset, end_offset, location):
        """Extract potential wallet file with proper size checks"""
        
        # Add to potential wallet locations
        self.potential_wallets.add(start_offset)
        
        try:
            with open(self.input_path, 'rb') as f:
                f.seek(start_offset)
                wallet_data = f.read(end_offset - start_offset)
                
                # Basic validation of wallet data
                if len(wallet_data) < self.min_wallet_size:
                    return
                
                # Check for Berkeley DB structure
                if not (BITCOIN_MARKERS['berkeley_header'] in wallet_data[:1024] or
                       BITCOIN_MARKERS['berkeley_btree'] in wallet_data[:1024]):
                    return
                
                # Save the wallet candidate
                wallet_hash = hashlib.sha256(wallet_data[:1024]).hexdigest()[:16]
                wallet_path = self.results_dir / 'wallets' / f'wallet_{wallet_hash}.dat'
                
                with open(wallet_path, 'wb') as wf:
                    wf.write(wallet_data)
                
                self.logger.info(f'Extracted potential wallet: {wallet_path.name}')
                self.logger.info(f'Found at: {location}')
                self.logger.info(f'Size: {len(wallet_data)} bytes')
                
        except Exception as e:
            self.logger.error(f'Error extracting wallet at {location}: {e}')

    def analyze_potential_key(self, data, offset, marker_type):
        """Analyze potential key data with stricter validation"""
        try:
            marker_pos = data.index(BITCOIN_MARKERS[marker_type])
            
            # Extract key context
            context_start = max(0, marker_pos - 32)
            context_end = min(len(data), marker_pos + 96)  # Most keys were 65-73 bytes
            key_data = data[context_start:context_end]
            
            # Basic key format validation
            if marker_type == 'private_key':
                if len(key_data) < 32:  # Private keys were at least 32 bytes
                    return
            elif marker_type == 'public_key':
                if len(key_data) < 65:  # Uncompressed public keys were 65 bytes
                    return
            
            # Save validated key data
            key_hash = hashlib.sha256(key_data).hexdigest()[:16]
            key_path = self.results_dir / 'keys' / f'{marker_type}_{key_hash}.bin'
            
            with open(key_path, 'wb') as f:
                f.write(key_data)
            
            self.logger.info(f'Saved potential {marker_type}: {key_path.name}')
            
        except Exception as e:
            self.logger.error(f'Error analyzing key data: {e}')
    
    def scan(self):
        """Main scan method that determines scan type and executes it"""
        self.logger.info(f'Starting scan of {self.input_path} (Type: {self.input_type})')
        
        try:
            if self.input_type in ['block', 'image']:
                self.scan_raw_device()
            elif self.input_type == 'directory':
                self.scan_directory()
            else:
                raise ValueError(f"Unsupported input type: {self.input_type}")
                
        except Exception as e:
            self.logger.error(f'Error during scan: {e}')
            raise
    
        self.logger.info(f'Scan completed for {self.input_path}')

    def scan_raw_device(self):
        """Scan a block device or disk image for Bitcoin-related data"""
        try:
            with open(self.input_path, 'rb') as device:
                device.seek(0, 2)  # Seek to end
                device_size = device.tell()
                device.seek(0)  # Reset to beginning
                
                self.logger.info(f'Device/Image size: {device_size:,} bytes '
                            f'({device_size/1024/1024/1024:.2f} GB)')
                
                if self.current_offset > 0:
                    self.logger.info(f'Resuming from offset: {self.current_offset:,} bytes')
                
                
                # Setup progress bar with device name
                with tqdm(total=device_size, unit='B', unit_scale=True,
                    initial=self.current_offset,
                    desc=f"Scanning {self.device_name}") as pbar:
                        
                    offset = self.current_offset
                    while offset < device_size:
                        try:
                            device.seek(offset)
                            block = device.read(BLOCK_SIZE)
                            
                            if not block:
                                break
                                
                            self.analyze_block(block, offset)
                            
                            offset += len(block)
                            self.current_offset = offset  # Update current position
                            pbar.update(len(block))
                                
                        except IOError as e:
                            self.logger.error(f'Error reading block at offset {offset}: {e}')
                            offset += BLOCK_SIZE  # Skip problematic block
                            self.current_offset = offset
                            pbar.update(BLOCK_SIZE)
                            continue
                
                # Clear resume point upon successful completion
                self.clear_resume_point()
                                
        except Exception as e:
            self.logger.error(f'Fatal error scanning device/image: {e}')
            raise

    def clear_resume_point(self):
        """Clear resume point after successful completion"""
        try:
            if self.resume_file.exists():
                with open(self.resume_file, 'r') as f:
                    resume_data = json.load(f)
                
                if self.input_path in resume_data:
                    del resume_data[self.input_path]
                    
                    with open(self.resume_file, 'w') as f:
                        json.dump(resume_data, f, indent=4)
        except Exception as e:
            self.logger.error(f'Error clearing resume point: {e}')

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 bitcoin_scanner.py <path>")
        print("Path can be:")
        print("  - Block device (/dev/sdX)")
        print("  - Disk image (.bin, .img, .raw, .dd)")
        print("  - Directory")
        sys.exit(1)
        
    input_path = sys.argv[1]
    
    if not os.path.exists(input_path):
        print(f"Error: Path {input_path} not found")
        sys.exit(1)
        
    if not os.access(input_path, os.R_OK):
        print(f"Error: No permission to read {input_path}")
        sys.exit(1)

    try:
        scanner = BitcoinScanner(input_path)
        scanner.scan()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
