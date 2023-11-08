import hashlib
import time
import pickle
from os.path import exists
import os
###Settings for this script
miningdifficulty = 5            #Set mining difficulty
blockchainfolder = "blockchain" #Set path to blockchain folder
showInfo = True                 #Enable information messages in console

def info(information):
    if showInfo:
        print("[INFO] " + information)

def validProof(block):
    guessHash = block.hash()
    return (guessHash[:miningdifficulty] == "0"*miningdifficulty)

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
        if (exists(blockchainfolder)):
            if (exists(blockchainfolder + "/0")):
                info("Blockchain found")
                self.load()
            else:
                info("No Blockchain found")
                self.create_genesis_block()
        else:
            info("No Blockchain found")
            os.mkdir(blockchainfolder)


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

    def load(self):
        nBlock = 0
        while True:
            if exists(blockchainfolder+"/"+str(nBlock)):
                nBlock += 1
            else:
                break
        nBlock -= 1
        for i in range(nBlock):
            with open(blockchainfolder+"/"+str(nBlock), 'rb') as file:
                block = pickle.load(file)
            self.chain.append(block)
        info(str(nBlock) + " blocks loaded")

if __name__ == "__main__":  #Main function
    blockchain = Blockchain()

    while True:
        lastBlock = blockchain.get_last_block()
        blockchain.addBlock("Block #" + str(lastBlock.index))
        info("Block #" + str(lastBlock.index) + " mined with hash " + str(lastBlock.hash()))
    blockchain.dump()
    info("Blockchain saved")
