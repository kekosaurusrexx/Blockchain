import hashlib
import time

miningdifficulty = 5

class Block:
    def __init__(self, index, prevHash, timestamp, data, proof):
        self.index = index
        self.prevHash = prevHash
        self.timestamp = timestamp
        self.data = data
        self.proof = proof

    def hash(self):
        block_string = f"{self.index}{self.prevHash}{self.timestamp}{self.data}{self.proof}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def getdict(self):
        return {
            'index': self.index,
            'prevHash': self.prevHash,
            'timestamp': self.timestamp,
            'data': self.data,
            'proof': self.proof
        }
    def setloaddict(self, dictonary):
        self.index = dictonary["index"]
        self.prevHash = dictonary["prevHash"]
        self.timestamp = dictonary["timestamp"]
        self.data = dictonary["data"]
        self.proof = dictonary["proof"]


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis = Block(0, "0", int(time.time()), "Genesis Block", 0)
        self.chain.append(genesis)

    def get_last_block(self):
        return self.chain[-1]

    def add_block(self, data, proof):
        index = len(self.chain)
        previous_hash = self.get_last_block().hash()
        timestamp = int(time.time())
        new_block = Block(index, previous_hash, timestamp, data, proof)
        self.chain.append(new_block)

    def dict(self):
        return [block.getdict() for block in self.chain]

def proof_of_work(last_proof):
    proof = 0
    while not is_valid_proof(last_proof, proof):
        proof += 1
    return proof

def is_valid_proof(last_proof, proof):
    guess = f"{last_proof}{proof}".encode()
    guess_hash = hashlib.sha256(guess).hexdigest()
    return guess_hash[:miningdifficulty] == "0"*miningdifficulty

if __name__ == "__main__":
    blockchain = Blockchain()
    last_block = blockchain.get_last_block()
    last_proof = 0

    while True:
        proof = proof_of_work(last_proof)
        blockchain.add_block(f"Block #{last_block.index + 1}", proof)
        last_block = blockchain.get_last_block()
        last_proof = proof
        print(last_block.getdict())