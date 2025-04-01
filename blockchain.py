class Block:
    def __init__(self, index, previous_hash, data, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.data = data
        self.nonce = nonce
        self.hash = self.compute_hash()
    
    def compute_hash(self):
        # Custom hash function using ASCII values of the block content
        block_string = f"{self.index}{self.previous_hash}{self.data}{self.nonce}"
        # Create a unique hash value by summing ASCII values
        return sum(ord(char) for char in block_string)

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        # First block in the blockchain with arbitrary previous hash
        genesis_block = Block(0, "0", "Genesis Block")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)
    
    def get_latest_block(self):
        return self.chain[-1]
    
    def add_block(self, data):
        # Create a new block with reference to the previous block
        previous_block = self.get_latest_block()
        new_block = Block(len(self.chain), previous_block.hash, data)
        # Perform proof of work before adding to the chain
        new_block.hash = self.proof_of_work(new_block)
        self.chain.append(new_block)
    
    def proof_of_work(self, block):
        # Simple proof of work: find a hash with specific pattern
        difficulty = 2  # Number of leading zeros required in the hash
        block.nonce = 0
        computed_hash = block.compute_hash()
        
        while not str(computed_hash).startswith('0' * difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()
        
        return computed_hash
    
    def is_chain_valid(self):
        # Verify integrity of the entire blockchain
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Verify current block hash
            if current.hash != current.compute_hash():
                print("Current block hash is invalid")
                return False
            
            # Verify chain linkage
            if current.previous_hash != previous.hash:
                print("Block chain connection broken")
                return False
        
        return True
    
    def display_chain(self):
        # Display the entire blockchain
        for block in self.chain:
            print(f"Index: {block.index}")
            print(f"Previous Hash: {block.previous_hash}")
            print(f"Data: {block.data}")
            print(f"Nonce: {block.nonce}")
            print(f"Hash: {block.hash}")
            print("-" * 30)

# Example usage
blockchain = Blockchain()
print("Mining block 1...")
blockchain.add_block("First transaction data")
print("Mining block 2...")
blockchain.add_block("Second transaction data")
print("Mining block 3...")
blockchain.add_block("Third transaction data")

print("\nBlockchain:")
blockchain.display_chain()

print(f"Is blockchain valid? {blockchain.is_chain_valid()}")
