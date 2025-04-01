class SHA256:
    """Custom implementation of SHA-256 hashing algorithm"""
    def __init__(self):
        # SHA-256 initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        # SHA-256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
    
    def rotr(self, x, n):
        """Rotate right: circular right shift"""
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    
    def ch(self, x, y, z):
        """Ch: Choose function"""
        return (x & y) ^ (~x & z)
    
    def maj(self, x, y, z):
        """Maj: Majority function"""
        return (x & y) ^ (x & z) ^ (y & z)
    
    def sigma0(self, x):
        """Σ0: Sigma0 function"""
        return self.rotr(x, 2) ^ self.rotr(x, 13) ^ self.rotr(x, 22)
    
    def sigma1(self, x):
        """Σ1: Sigma1 function"""
        return self.rotr(x, 6) ^ self.rotr(x, 11) ^ self.rotr(x, 25)
    
    def gamma0(self, x):
        """γ0: Gamma0 function"""
        return self.rotr(x, 7) ^ self.rotr(x, 18) ^ (x >> 3)
    
    def gamma1(self, x):
        """γ1: Gamma1 function"""
        return self.rotr(x, 17) ^ self.rotr(x, 19) ^ (x >> 10)
    
    def pad_message(self, message):
        """Pad the message according to SHA-256 specifications"""
        # Convert message to binary
        message_bin = ''.join(format(ord(char), '08b') for char in message)
        msg_len = len(message_bin)
        
        # Append bit '1'
        message_bin += '1'
        
        # Append '0's until message length ≡ 448 (mod 512)
        message_bin += '0' * ((448 - (msg_len + 1) % 512) % 512)
        
        # Append original message length as 64-bit big-endian
        message_bin += format(msg_len, '064b')
        
        # Split into 512-bit blocks
        blocks = [message_bin[i:i+512] for i in range(0, len(message_bin), 512)]
        return blocks
    
    def process_block(self, block):
        """Process a single 512-bit block"""
        # Convert 512-bit block to 16 32-bit words
        w = [int(block[i:i+32], 2) for i in range(0, 512, 32)]
        
        # Extend 16 words to 64 words
        for i in range(16, 64):
            w.append((self.gamma1(w[i-2]) + w[i-7] + self.gamma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF)
        
        # Initialize working variables
        a, b, c, d, e, f, g, h = self.h
        
        # Main loop
        for i in range(64):
            t1 = (h + self.sigma1(e) + self.ch(e, f, g) + self.k[i] + w[i]) & 0xFFFFFFFF
            t2 = (self.sigma0(a) + self.maj(a, b, c)) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF
        
        # Update hash values
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF
    
    def hash(self, message):
        """Hash a message using SHA-256"""
        # Reset hash values
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        # Pad message and process each block
        blocks = self.pad_message(message)
        for block in blocks:
            self.process_block(block)
        
        # Concatenate hash values to get final hash
        return ''.join(format(h, '08x') for h in self.h)

class Block:
    """Block is a storage container"""
    def __init__(self, Height, Blocksize, BlockHeader, TxCount, Txs):
        self.Height = Height
        self.Blocksize = Blocksize
        self.BlockHeader = BlockHeader
        self.TxCount = TxCount
        self.Txs = Txs

class BlockHeader:
    """Header information for a block"""
    def __init__(self, previous_hash, merkle_root, timestamp, nonce=0):
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.nonce = nonce
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        # Use custom SHA-256 implementation
        header_string = f"{self.previous_hash}{self.merkle_root}{self.timestamp}{self.nonce}"
        sha = SHA256()
        return sha.hash(header_string)
    
    def mine_block(self, difficulty):
        # Proof of work algorithm: find hash with leading zeros
        target = '0' * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        return self.hash

class Transaction:
    """Represents a simple transaction"""
    def __init__(self, sender, recipient, amount):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
    
    def __str__(self):
        return f"{self.sender} sent {self.amount} coins to {self.recipient}"

def calculate_merkle_root(transactions):
    """Calculate a merkle root from transaction list using SHA-256"""
    if not transactions:
        return "0" * 64  # Empty root
    
    # Create SHA-256 hasher
    sha = SHA256()
    
    # Hash all transactions
    tx_hashes = []
    for tx in transactions:
        tx_string = f"{tx.sender}{tx.recipient}{tx.amount}"
        tx_hashes.append(sha.hash(tx_string))
    
    # Combine hashes until we have a single root
    while len(tx_hashes) > 1:
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1])  # Duplicate last hash if odd
        
        new_level = []
        for i in range(0, len(tx_hashes), 2):
            combined = tx_hashes[i] + tx_hashes[i+1]
            new_level.append(sha.hash(combined))
        
        tx_hashes = new_level
    
    return tx_hashes[0]

class Blockchain:
    """Manages the blockchain"""
    def __init__(self, difficulty=3):
        self.chain = []
        self.difficulty = difficulty
        self.pending_transactions = []
        self.block_reward = 10
        self.timestamp_counter = 0
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_tx = Transaction("System", "Genesis", 0)
        transactions = [genesis_tx]
        
        # Create header for genesis block
        block_header = BlockHeader(
            previous_hash="0" * 64,
            merkle_root=calculate_merkle_root(transactions),
            timestamp=self.get_next_timestamp()
        )
        
        # Mine genesis block
        print("Mining genesis block...")
        block_header.mine_block(self.difficulty)
        
        # Create complete genesis block
        genesis_block = Block(
            Height=0,
            Blocksize=len(transactions),
            BlockHeader=block_header,
            TxCount=len(transactions),
            Txs=transactions
        )
        
        self.chain.append(genesis_block)
        print(f"Genesis block created with hash: {block_header.hash}")
    
    def get_next_timestamp(self):
        """Simple timestamp simulator"""
        self.timestamp_counter += 1
        return self.timestamp_counter
    
    def get_latest_block(self):
        """Return the most recent block"""
        return self.chain[-1]
    
    def add_transaction(self, sender, recipient, amount):
        """Add transaction to pending list"""
        transaction = Transaction(sender, recipient, amount)
        self.pending_transactions.append(transaction)
        return self.get_latest_block().Height + 1
    
    def mine_pending_transactions(self, miner_reward_address):
        """Mine a new block with all pending transactions"""
        # Add mining reward
        reward_tx = Transaction("System", miner_reward_address, self.block_reward)
        self.pending_transactions.append(reward_tx)
        
        # Create new block
        block_height = len(self.chain)
        transactions = self.pending_transactions.copy()
        
        # Create and mine block header
        block_header = BlockHeader(
            previous_hash=self.get_latest_block().BlockHeader.hash,
            merkle_root=calculate_merkle_root(transactions),
            timestamp=self.get_next_timestamp()
        )
        
        print(f"Mining block #{block_height}...")
        block_header.mine_block(self.difficulty)
        
        # Create full block
        new_block = Block(
            Height=block_height,
            Blocksize=len(transactions),
            BlockHeader=block_header,
            TxCount=len(transactions),
            Txs=transactions
        )
        
        # Add to chain and clear pending transactions
        self.chain.append(new_block)
        self.pending_transactions = []
        
        print(f"Block #{block_height} mined with hash: {block_header.hash}")
        return new_block
    
    def is_chain_valid(self):
        """Verify the integrity of the entire blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Verify hash of current block
            if current_block.BlockHeader.hash != current_block.BlockHeader.calculate_hash():
                print(f"Block #{current_block.Height} hash is invalid")
                return False
            
            # Verify previous hash reference
            if current_block.BlockHeader.previous_hash != previous_block.BlockHeader.hash:
                print(f"Block #{current_block.Height} has broken chain link")
                return False
            
            # Verify proof of work
            if not current_block.BlockHeader.hash.startswith('0' * self.difficulty):
                print(f"Block #{current_block.Height} doesn't have valid proof of work")
                return False
        
        return True
    
    def display_chain(self):
        """Display all blocks in the blockchain"""
        for block in self.chain:
            print("\n" + "="*50)
            print(f"Block #{block.Height}")
            print(f"Hash: {block.BlockHeader.hash}")
            print(f"Previous Hash: {block.BlockHeader.previous_hash}")
            print(f"Merkle Root: {block.BlockHeader.merkle_root}")
            print(f"Timestamp: {block.BlockHeader.timestamp}")
            print(f"Nonce: {block.BlockHeader.nonce}")
            print(f"Transactions ({block.TxCount}):")
            for tx in block.Txs:
                print(f"  - {tx}")
            print("="*50)

# Demo usage
if __name__ == "__main__":
    # Create blockchain with difficulty 3
    coin = Blockchain(difficulty=3)
    
    # Add transactions
    print("\nAdding transactions...")
    coin.add_transaction("Alice", "Bob", 50)
    coin.add_transaction("Bob", "Charlie", 25)
    
    # Mine block
    coin.mine_pending_transactions("Miner1")
    
    # Add more transactions
    print("\nAdding more transactions...")
    coin.add_transaction("Charlie", "Dave", 10)
    coin.add_transaction("Alice", "Eve", 30)
    
    # Mine another block
    coin.mine_pending_transactions("Miner2")
    
    # Display the blockchain
    print("\nBlockchain:")
    coin.display_chain()
    
    # Verify integrity
    print(f"\nIs blockchain valid? {coin.is_chain_valid()}")
