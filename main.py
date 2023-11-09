import hashlib
import time
import pickle
from os.path import exists
import os
import keyboard
import random
###Settings for this script
miningdifficulty = 5            #Set mining difficulty
blockchainfolder = "blockchain" #Set path to blockchain folder
showInfo = True                 #Enable information messages
showWarn = True                 #Enable warning messages
showErr = True                  #Enable error messages
showSys = True                  #Enable system messages

def info(information):
    if showInfo:
        print("[INFO] " + information)

def warning(warning):
    if showWarn:
        print("[WARN] " + warning)

def err(error):
    if showErr:
        print("[ERR] " + error)
    exit()

def sys(sysmsg):
    if showSys:
        print("[SYS] " + sysmsg)

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
                self.load()
            else:
                sys("No Blockchain found")
                self.create_genesis_block()
        else:
            sys("No Blockchain found")
            os.mkdir(blockchainfolder)

    def create_genesis_block(self):
        genesis = Block(0, "0", int(time.time()), "Genesis Block", 0)
        info("Genesis block created")
        self.chain.append(genesis)

    def get_last_block(self):
        return self.chain[-1]

    def addBlock(self, data):
        index = len(self.chain)
        prevHash = self.get_last_block().hash()
        timestamp = int(time.time())
        counter = 0
        beginTime = time.time()
        while True:
            proof = random.randint(0,999999999999999)
            newBlock = Block(index, prevHash, timestamp, data, proof)
            counter += 1
            if(validProof(newBlock)):
                endTime = time.time()
                usedTime= endTime-beginTime
                hashSpeed = counter/usedTime
                info("Block #" + str(index) + " mined with Hashspeed: " + str(round(hashSpeed/1000)) + "kH/s")
                self.chain.append(newBlock)
                break

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
            with open(blockchainfolder+"/"+str(i), 'rb') as file:
                block = pickle.load(file)
                file.close()
            self.chain.append(block)
        sys(str(nBlock) + " blocks loaded")

    def validate(self):
        for i in range(1,len(self.chain)):
            if not self.chain[i].prevHash==self.chain[i-1].hash():
                return False
        return True

if __name__ == "__main__":
    blockchain = Blockchain()
    #Validate Blockchain loaded from files
    if blockchain.validate():
        sys("Blockchain validated")
    else:
        err("Blockchain invalid")
    #Main loop
    while True:
        lastBlock = blockchain.get_last_block()
        data = "Block #" + str(lastBlock.index)
        blockchain.addBlock(data)


        if(keyboard.is_pressed("q")):
            break

    blockchain.dump()
    sys("Blockchain saved")
