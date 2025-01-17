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
import math

# Constants
BLOCK_SIZE = 4096

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
    
    'bitcoinj_header': b'\x00\x00\x00\x20',  # BitcoinJ header marker
    'uncompressed_pubkey': b'\x04',  # Uncompressed public key marker
    'compressed_pubkey_even': b'\x02',  # Compressed public key (even y)
    'compressed_pubkey_odd': b'\x03',  # Compressed public key (odd y)
    'berkeley_btree_magic': b'\x00\x05\x31\x63',  # Berkeley DB B-tree magic
    'berkeley_48_header': b'\x00\x05\x31\x62',  # Berkeley DB 4.8 header
    
     # HD Wallet Markers
    'xprv': b'xprv',
    'xpub': b'xpub',
    'yprv': b'yprv',
    'ypub': b'ypub', 
    'zprv': b'zprv',
    'zpub': b'zpub',
}

class BitcoinScanner:

    def get_file_size(self, path):
        """Get file size safely"""
        try:
            return os.path.getsize(path)
        except (OSError, IOError):
            return 0

    def is_valid_file(self, path):
        """Check if file is valid and readable"""
        return os.path.isfile(path) and os.access(path, os.R_OK)

    def format_size(self, size):
        """Format size in bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024

    def __init__(self, input_path):


        self.input_path = input_path
        self.input_type = self._check_input_type()
        if self.input_type == 'unknown':
            raise ValueError(f"Input {input_path} is not a block device, disk image, or directory")

        # Get device name before setting up logging and results dir
        self.device_name = self.get_device_name()
        self.logger = logging.getLogger(f'scanner_{self.device_name}')

        self.setup_logging()
        self.results_dir = self.setup_results_dir()
        self.potential_wallets = set()
        self.min_wallet_size = 16384
        self.resume_file = Path('bitcoin_scan_resume.json')
        self.current_offset = self.check_resume_point()
        self.setup_signal_handler()
        
        self.stats = {
            'keys_recovered': 0,
            'pending_pub': 0,
            'pending_priv': 0,
            'duplicates': 0
        }
        
        self.total_size = 0  # Will be set when scanning starts
        self.potential_matches = []  # For storing potential key pairs
        
         # Add key tracking
        self.found_keys = {
            'private': set(),
            'public': set(),
            'hd': set(),
            'private_key': set(),
            'public_key': set()
        }
        
        self.key_pairs = []  # For matching pub/priv pairs

    def extract_berkeley_db(self, data, offset):
        """Extract and save potential Berkeley DB wallet data"""
        try:
            # Look for DB header and footer markers
            header_pos = -1
            for marker in [BITCOIN_MARKERS['berkeley_48_header'], 
                        BITCOIN_MARKERS['berkeley_btree_magic']]:
                if marker in data:
                    header_pos = data.index(marker)
                    break
                    
            if header_pos == -1:
                return
                
            # Extract reasonable chunk of data around marker
            extract_start = max(0, header_pos - 4096)
            extract_end = min(len(data), header_pos + 32768)
            
            db_data = data[extract_start:extract_end]
            
            # Save extracted data
            db_hash = hashlib.sha256(db_data[:1024]).hexdigest()[:16]
            db_path = self.results_dir / 'wallets' / f'berkeley_db_{db_hash}.dat'
            
            with open(db_path, 'wb') as f:
                f.write(db_data)
                
            self.logger.info(f'Extracted potential Berkeley DB data to: {db_path}')
            
        except Exception as e:
            self.logger.error(f'Error extracting Berkeley DB data: {e}') 
        
    def show_progress(self):
        """Show scanning progress and statistics"""
        progress = 100.0 * (self.current_offset / self.total_size)
        print(f"\r{progress:.1f}% scanned, {self.stats['keys_recovered']} keys found "
                f"({self.stats['pending_pub']} pub, {self.stats['pending_priv']} priv pending) "
                f"{self.stats['duplicates']} duplicates", end='')
        
    def match_key_pairs(self):
        """Try to match public and private keys"""
        for pub_key, priv_key in self.potential_matches:
            try:
                # Verify the key pair matches
                if self.verify_key_pair(pub_key, priv_key):
                    self.logger.info("Found matching key pair")
                    self.save_key_pair(pub_key, priv_key)
                    self.stats['keys_recovered'] += 1
            except:
                continue
            
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

    def scan_block_device(self):
        """Scan a block device for Bitcoin-related data"""
        try:
            
            last_progress_update = time.time()
            progress_interval = 5  # seconds
            
            with tqdm(total=self.total_size, unit='B', unit_scale=True,
                initial=self.current_offset,
                desc=f"Scanning {self.device_name}") as pbar:
                    
                offset = self.current_offset
                while offset < self.total_size:
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
                                device.seek(offset)
                                block = device.read(BLOCK_SIZE)
                                
                                if not block:
                                    break
                                    
                                self.analyze_block(block, offset)
                                
                                offset += len(block)
                                pbar.update(len(block))
                                
                                # Show periodic progress updates
                                current_time = time.time()
                                if current_time - last_progress_update > progress_interval:
                                    self.show_progress()
                                    last_progress_update = current_time
                    except IOError as e:
                        self.logger.error(f'Error reading block at offset {offset}: {e}')
                        offset += BLOCK_SIZE  # Skip problematic block
                        pbar.update(BLOCK_SIZE)
                        continue
                
                pbar.close()
                        
        except Exception as e:
            self.logger.error(f'Fatal error scanning device: {e}')
            raise

    def check_encryption(self, data):
        """Check if wallet data appears to be encrypted"""
        encryption_markers = [
            b'encrypted',
            b'Salted__',
            b'BerkeleyDB',
        ]
        
        is_encrypted = any(marker in data for marker in encryption_markers)
        if is_encrypted:
            self.logger.info("Found potential encrypted wallet data")
        return is_encrypted

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

                # Check if wallet appears encrypted
                is_encrypted = self.check_encryption(wallet_data)
                if is_encrypted:
                    wallet_path = wallet_path.with_suffix('.encrypted.dat')

                with open(wallet_path, 'wb') as wf:
                    wf.write(wallet_data)
                
                self.logger.info(f'Extracted potential wallet: {wallet_path.name}')
                self.logger.info(f'Found at: {location}')
                self.logger.info(f'Size: {len(wallet_data)} bytes')
                
        except Exception as e:
            self.logger.error(f'Error extracting wallet at {location}: {e}')

    def validate_hd_key(self, data, key_type):
        """Validate HD wallet key format"""
        try:
            if not data.startswith(BITCOIN_MARKERS[key_type]):
                return False
                
            # Check basic length requirements
            if len(data) < 111:  # Minimum length for HD keys
                return False
                
            # Could add more specific validation here
            return True
            
        except Exception as e:
            self.logger.error(f'Error validating HD key: {e}')
            return False

    def get_device_hash(self):
        """Generate unique hash for block device"""
        try:
            # Read first and last 1MB of device
            with open(self.input_path, 'rb') as f:
                start_data = f.read(1024 * 1024)  # First 1MB
                f.seek(-1024 * 1024, 2)  # Last 1MB
                end_data = f.read()
                
                # Get device size
                f.seek(0, 2)
                size = f.tell()
            
            # Combine unique device characteristics
            device_info = f"{start_data}{end_data}{size}".encode()
            device_hash = hashlib.sha256(device_info).hexdigest()[:12]
            
            return device_hash
        except Exception as e:
            raise ValueError(f"Error getting device hash: {e}")

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
            
            # Get device hash as default name
            device_hash = self.get_device_hash()
            default_name = f"device_{device_hash}" if device_hash else "unknown_device"
            
            while True:
                name = input(f"Please provide a descriptive name for this device\n"
                            f"(Press Enter to use '{default_name}'): ").strip()
                
                if not name:
                    return default_name
                    
                if re.match(r'^[a-zA-Z0-9_-]+$', name):
                    return name
                else:
                    print("Name can only contain letters, numbers, underscores, and hyphens.")
        
        return os.path.basename(self.input_path)

    def validate_private_key(self, data):
        """
        Validate a potential private key with very strict checks
        """
        try:
            # Must be exactly 32 bytes
            if len(data) != 32:
                return False

            # Convert to integer
            key_int = int.from_bytes(data, 'big')

            # Check if key is in valid range for Bitcoin
            if not (0x1000000000000000 < key_int < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141):
                return False

            # Entropy must be very high for real private keys
            entropy = self.calculate_entropy(data)
            if entropy < 7.0:  # Requiring very high entropy
                return False

            # Check for common patterns that indicate false positives

            # No byte should appear more than 4 times
            byte_counts = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
                if byte_counts[byte] > 4:
                    return False

            # No sequences of same byte
            for i in range(len(data) - 2):
                if data[i] == data[i + 1] == data[i + 2]:
                    return False

            # Check surrounding bytes for context
            if self.check_surrounding_bytes(data):
                return False

            return True

        except Exception as e:
            self.logger.error(f'Error in private key validation: {e}')
            return False

    def validate_public_key(self, data):
        """
        Validate a potential public key with very strict checks
        """
        try:
            # Must match exact formats
            if len(data) not in (33, 65):
                return False

            # Verify point is on secp256k1 curve
            p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

            # Uncompressed public key
            if len(data) == 65:
                if data[0] != 0x04:
                    return False

                x = int.from_bytes(data[1:33], 'big')
                y = int.from_bytes(data[33:65], 'big')

                # y² = x³ + 7 (mod p)
                left = (y * y) % p
                right = ((x * x * x) + 7) % p
                if left != right:
                    return False

            # Compressed public key
            elif len(data) == 33:
                if data[0] not in (0x02, 0x03):
                    return False

                x = int.from_bytes(data[1:], 'big')
                if not (0 < x < p):
                    return False

            # Check for common false positive patterns
            if self.check_surrounding_bytes(data):
                return False

            return True

        except Exception as e:
            self.logger.error(f'Error in public key validation: {e}')
            return False

    def check_surrounding_bytes(self, key_data, window=16):
        """
        Check bytes before and after the key for patterns indicating false positive
        """
        try:
            with open(self.input_path, 'rb') as f:
                # Get current position
                current_pos = f.tell()

                # Read bytes before
                f.seek(max(0, current_pos - window))
                before = f.read(window)

                # Read bytes after
                f.seek(current_pos + len(key_data))
                after = f.read(window)

                # Patterns that suggest false positives
                suspicious_patterns = [
                    b'\x00\x00\x00\x00',  # Null sequences
                    b'\xFF\xFF\xFF\xFF',  # FF sequences
                    b'0000',  # ASCII number sequences
                    b'1111',
                    b'2222',
                    b'9999',
                    b'aaaa',  # Repeated ASCII letters
                    b'ffff',
                    b'AAAA',
                    b'FFFF',
                ]

                # Check for suspicious patterns in surrounding data
                surrounding = before + after
                return any(pattern in surrounding for pattern in suspicious_patterns)

        except Exception as e:
            self.logger.error(f'Error checking surrounding bytes: {e}')
            return False

    def analyze_potential_key(self, data, offset, marker_type):
        """
        Analyze potential key data with much stricter validation
        """
        try:
            marker_pos = data.index(BITCOIN_MARKERS[marker_type])

            # Require specific byte patterns before/after markers
            if marker_type == 'private_key':
                # Look for standard Bitcoin private key format
                if not (marker_pos >= 1 and data[marker_pos - 1] == 0x80):
                    return

                if marker_pos + 32 > len(data):
                    return

                key_data = data[marker_pos:marker_pos + 32]

                # Must have valid checksum after key
                if marker_pos + 36 <= len(data):
                    key_with_checksum = data[marker_pos - 1:marker_pos + 36]
                    if not self.verify_checksum(key_with_checksum):
                        return

                if not self.validate_private_key(key_data):
                    return

            elif marker_type == 'public_key':
                # Must be preceded by specific markers
                valid_prefixes = [b'\x21\x03', b'\x21\x02', b'\x41\x04']
                prefix_found = False

                for prefix in valid_prefixes:
                    if marker_pos >= len(prefix) and data[marker_pos - len(prefix):marker_pos] == prefix:
                        prefix_found = True
                        break

                if not prefix_found:
                    return

                # Extract key based on format
                if data[marker_pos] == 0x04:  # Uncompressed
                    if marker_pos + 65 > len(data):
                        return
                    key_data = data[marker_pos:marker_pos + 65]
                else:  # Compressed
                    if marker_pos + 33 > len(data):
                        return
                    key_data = data[marker_pos:marker_pos + 33]

                if not self.validate_public_key(key_data):
                    return

            elif marker_type == 'key_header':
                self.logger.warning(f'Key header: {marker_type} is not handled')

            # Generate hash of key data
            key_hash = hashlib.sha256(key_data).hexdigest()[:16]

            # Check if already found
            if key_hash in self.found_keys[marker_type]:
                self.stats['duplicates'] += 1
                return

            # Additional context validation
            if self.check_surrounding_bytes(key_data):
                return

            # Save validated key
            self.found_keys[marker_type].add(key_hash)
            key_path = self.results_dir / 'keys' / f'{marker_type}_{key_hash}.bin'

            with open(key_path, 'wb') as f:
                f.write(key_data)

            self.logger.info(f'Found new {marker_type} at offset {offset}: {key_hash}')

            if marker_type == 'private_key':
                self.stats['pending_priv'] += 1
            else:
                self.stats['pending_pub'] += 1

        except Exception as e:
            self.logger.error(f'Error analyzing key data at offset {offset}: {e}')

    def verify_checksum(self, data):
        """
        Verify Bitcoin-style double SHA256 checksum
        """
        try:
            if len(data) < 4:
                return False

            # Last 4 bytes should be first 4 bytes of double SHA256
            checksum = data[-4:]
            payload = data[:-4]

            hash1 = hashlib.sha256(payload).digest()
            hash2 = hashlib.sha256(hash1).digest()

            return hash2[:4] == checksum

        except Exception as e:
            self.logger.error(f'Error verifying checksum: {e}')
            return False

    def calculate_entropy(self, data):
        """
        Calculate Shannon entropy of byte sequence to detect randomness
        """
        if not data:
            return 0

        # Calculate byte frequencies
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0
        for count in freq.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

        return entropy

    def scan_raw_device(self):
        """Scan a raw device or disk image"""
        try:
            with open(self.input_path, 'rb') as device:
                device.seek(0, 2)
                self.total_size = device.tell()
                device.seek(0)
                
                self.logger.info(f'Device/Image size: {self.total_size:,} bytes '
                            f'({self.total_size/1024/1024/1024:.2f} GB)')
                
                if self.current_offset > 0:
                    self.logger.info(f'Resuming from offset: {self.current_offset:,} bytes')
                
                with tqdm(total=self.total_size, unit='B', unit_scale=True,
                    initial=self.current_offset,
                    desc=f"Scanning {self.device_name}") as pbar:
                        
                    offset = self.current_offset
                    while offset < self.total_size:
                        try:
                            device.seek(offset)
                            block = device.read(BLOCK_SIZE)
                            
                            if not block:
                                break
                                
                            self.analyze_block(block, offset)
                            
                            offset += len(block)
                            self.current_offset = offset
                            pbar.update(len(block))
                                
                        except IOError as e:
                            self.logger.error(f'Error reading block at offset {offset}: {e}')
                            offset += BLOCK_SIZE
                            self.current_offset = offset
                            pbar.update(BLOCK_SIZE)
                            continue
                
                # Clear resume point upon successful completion
                self.clear_resume_point()
                                
        except Exception as e:
            self.logger.error(f'Fatal error scanning device/image: {e}')
            raise

    def analyze_berkeley_db(self, data, offset):
        """Analyze potential Berkeley DB wallet structures"""
        try:
            if (BITCOIN_MARKERS['berkeley_48_header'] in data or 
                BITCOIN_MARKERS['berkeley_btree_magic'] in data):
                
                # Look for wallet.dat indicators
                indicators = 0
                for marker in ['wallet_name', 'defaultkey', 'name', 'version']:
                    if BITCOIN_MARKERS[marker] in data:
                        indicators += 1
                        
                if indicators >= 2:
                    self.logger.info(f'Found likely Berkeley DB wallet.dat at offset {offset}')
                    
                    # Extract reasonable chunk around the markers
                    extract_start = max(0, offset - 4096)
                    extract_end = min(len(data), offset + 32768)
                    wallet_data = data[extract_start:extract_end]
                    
                    # Save the wallet candidate
                    wallet_hash = hashlib.sha256(wallet_data[:1024]).hexdigest()[:16]
                    wallet_path = self.results_dir / 'wallets' / f'wallet_{wallet_hash}.dat'
                    
                    with open(wallet_path, 'wb') as f:
                        f.write(wallet_data)
                        
                    self.logger.info(f'Saved potential wallet to: {wallet_path}')
                    
        except Exception as e:
            self.logger.error(f'Error analyzing Berkeley DB data: {e}')

    def analyze_block(self, block_data, offset, file_path=None):
        """Analyze a block of data for Bitcoin wallet artifacts"""
        try:
            # Check for Berkeley DB wallet format
            if (BITCOIN_MARKERS['berkeley_48_header'] in block_data or 
                BITCOIN_MARKERS['berkeley_btree_magic'] in block_data):
                self.analyze_berkeley_db(block_data, offset)
                
            # Check for BitcoinJ format
            if BITCOIN_MARKERS['bitcoinj_header'] in block_data:
                self.analyze_bitcoinj_format(block_data, offset)
                
            # Look for raw keys
            for key_marker in ['private_key', 'public_key', 'key_header']:
                if BITCOIN_MARKERS[key_marker] in block_data:
                    self.analyze_potential_key(block_data, offset, key_marker)
                    
            # Check for HD wallet markers
            for hd_marker in ['xprv', 'xpub', 'yprv', 'ypub', 'zprv', 'zpub']:
                if BITCOIN_MARKERS[hd_marker] in block_data:
                    if self.validate_hd_key(block_data, hd_marker):
                        self.logger.info(f'Found valid HD wallet marker {hd_marker} at offset {offset}')
                        self.save_fragment(block_data, offset, f'hd_{hd_marker}')
                        
        except Exception as e:
            self.logger.error(f'Error analyzing block at offset {offset}: {e}')

    def scan(self):
        """Main scanning method"""
        start_time = time.time()
        self.logger.info(f'Starting scan of {self.input_path} (Type: {self.input_type})')
        
        try:
            if self.input_type in ['block', 'image']:
                self.scan_raw_device()
            elif self.input_type == 'directory':
                self.scan_directory()
            else:
                raise ValueError(f"Unsupported input type: {self.input_type}")
                
            # Print scan summary
            duration = time.time() - start_time
            self.logger.info("\nScan Summary:")
            self.logger.info(f"Duration: {duration:.1f} seconds")
            self.logger.info(f"Data scanned: {self.total_size/1024/1024/1024:.2f} GB")
            self.logger.info(f"Keys recovered: {self.stats['keys_recovered']}")
            self.logger.info(f"Wallets found: {len(self.potential_wallets)}")
            self.logger.info(f"Results saved to: {self.results_dir}")
                
        except Exception as e:
            self.logger.error(f'Error during scan: {e}')
            raise

    def save_key_pair(self, pubkey, privkey):
        """Save a matched public-private key pair"""
        try:
            # Generate unique filename based on key hash
            key_hash = hashlib.sha256(pubkey + privkey).hexdigest()[:16]
            key_path = self.results_dir / 'keys' / f'keypair_{key_hash}.bin'
            
            # Create keys directory if it doesn't exist
            key_path.parent.mkdir(exist_ok=True)
            
            # Save both keys together
            with open(key_path, 'wb') as f:
                f.write(b'PUBLIC KEY:\n')
                f.write(pubkey)
                f.write(b'\nPRIVATE KEY:\n')
                f.write(privkey)
                
            self.logger.info(f'Saved key pair to: {key_path}')
            self.stats['keys_recovered'] += 1
            
        except Exception as e:
            self.logger.error(f'Error saving key pair: {e}')

    def save_fragment(self, data, offset, marker_type):
        """Save found data fragments"""
        try:
            fragment_hash = hashlib.sha256(data).hexdigest()[:16]
            fragment_path = self.results_dir / 'fragments' / f'{marker_type}_{offset}_{fragment_hash}.bin'
            
            # Create fragments directory if it doesn't exist
            fragment_path.parent.mkdir(exist_ok=True)
            
            with open(fragment_path, 'wb') as f:
                f.write(data)
            
            self.logger.debug(f'Saved fragment: {fragment_path.name}')
            return fragment_path
            
        except Exception as e:
            self.logger.error(f'Error saving fragment: {e}')
            return None

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

    def verify_key_pair(self, pub_key, priv_key):
        """Verify that a public-private key pair matches"""
        try:
            # Basic validation first
            if not self.validate_public_key(pub_key):
                return False
            if not self.validate_private_key(priv_key):
                return False
                
            # TODO: Add cryptographic verification of key pair
            # This would require implementing Bitcoin-specific key pair validation
            # For now, we just do basic format validation
            
            return True
            
        except Exception as e:
            self.logger.error(f'Error verifying key pair: {e}')
            return False
    
    def analyze_bitcoinj_format(self, data, offset):
        """Look for BitcoinJ wallet format keys"""
        try:
            # Look for public key marker
            if b'\x04' in data:
                pub_pos = data.index(b'\x04')
                if pub_pos + 65 <= len(data):  # Full public key
                    pubkey = data[pub_pos:pub_pos+65]
                    
                    # Look backwards for private key
                    for i in range(max(0, pub_pos-64), pub_pos-37):
                        if data[i:i+4] == b'\x00\x00\x00\x20':
                            privkey = data[i+4:i+36]
                            if self.validate_private_key(privkey):  # Use self.
                                self.logger.info(f'Found potential BitcoinJ key pair at offset {offset+i}')
                                self.save_key_pair(pubkey, privkey)
        except Exception as e:
            self.logger.error(f'Error analyzing BitcoinJ format: {e}')

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
