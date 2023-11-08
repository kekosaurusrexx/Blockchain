import hashlib
import time
import pickle

miningdifficulty = 5
blockchainfolder = "blockchain"


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

    def dump(self):
        output = open(blockchainfolder + "/" + str(self.index), "wb")
        pickle.dump(self, output)
        output.close()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis = Block(0, "0", int(time.time()), "Genesis Block", 0)
        self.chain.append(genesis)

    def get_last_block(self):
        return self.chain[-1]

    def addBlock(self, data):
        index = len(self.chain)
        prevHash = self.get_last_block().hash()
        timestamp = int(time.time())

        proof = 0
        while True:
            newBlock = Block(index, prevHash, timestamp, data, proof)
            proof += 1
            if(validProof(newBlock)):
                break

        self.chain.append(newBlock)

    def dump(self):
        for block in self.chain:
            block.dump()

def validProof(block):
    guessHash = block.hash()
    return (guessHash[:miningdifficulty] == "0"*miningdifficulty)

if __name__ == "__main__":
    blockchain = Blockchain()

    while True:
        lastBlock = blockchain.get_last_block()
        blockchain.addBlock("Block #" + str(lastBlock.index))
        print(lastBlock.index)
        print(lastBlock.prevHash)
        if lastBlock.index==100:
            break
    blockchain.dump()
