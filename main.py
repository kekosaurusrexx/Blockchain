import hashlib
import time
import pickle
from os.path import exists
import os
import keyboard
import random
import json
import rsa
###Settings for this script
miningdifficulty = 5            #Set mining difficulty
blockchainfolder = "blockchain" #Set path to blockchain folder
showInfo = True                 #Enable information messages
showWarn = True                 #Enable warning messages
showErr = True                  #Enable error messages
showSys = True                  #Enable system messages
enableBlockchain = True         #Enable Blockchain, used for development
enableMining = True             #enable Mining, used for development

def info(information):
    if showInfo:
        print("[INFO] " + information)

def warning(warning):
    if showWarn:
        print("[WARN] " + warning)

def err(error):
    if showErr:
        print("[ERR] " + error)
    exit(69)

def sys(sysmsg):
    if showSys:
        print("[SYS] " + sysmsg)

def validProof(block):
    guessHash = block.hash()
    return (guessHash[:miningdifficulty] == "0"*miningdifficulty)

class Block:#Class to create a single block
    def __init__(self, index, prevHash, timestamp, data, proof):
        self.index = index
        self.prevHash = prevHash
        self.timestamp = timestamp
        self.data = data
        self.proof = proof

    def hash(self):
        blockString = f"{self.index}{self.prevHash}{self.timestamp}{self.data}{self.proof}"
        return hashlib.sha256(blockString.encode()).hexdigest()

    def dump(self):
        output = open(blockchainfolder + "/" + str(self.index), "wb")
        pickle.dump(self, output)
        output.close()

class Blockchain:#Class to store and use the blockchain
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

class Data:#Class to create and store block-data
    def __init__(self):
        self.datachain = []

    def dump(self):
        dataStr = json.dumps(self.datachain)
        return(dataStr)

    def add(self, newData):
        self.datachain.append(newData)

    def newText(self, text, sender):
        textData = {"type": "text", "sender": sender, "content": str(text)}
        self.add(textData)

    def newTransaction(self,transaction):
        transactionData = {
            "type": "transaction",
            "sender": transaction.sender,
            "receiver": transaction.receiver,
            "value": transaction.value,
            "signature": transaction.signature.decode("utf-8",errors="ignore")}
        self.add(transactionData)

class Keypair:#Class to store and use keypairs
    def __init__(self):
        self.publicKey = ""
        self.privateKey = ""
        self.publicKeyStr = ""
        self.privateKeyStr = ""

    def new(self):
        (self.publicKey, self.privateKey) = rsa.newkeys(2048)
        self.string()

    def string(self):
        self.publicKeyStr = rsa.PublicKey.save_pkcs1(self.publicKey).decode('utf-8')
        self.privateKeyStr = rsa.PrivateKey.save_pkcs1(self.privateKey).decode('utf-8')

    def sign(self, dataToSign):
        signature = rsa.sign(dataToSign.encode(), self.privateKey, "SHA-256")
        return(signature)

    def verify(self, dataToVerify, signature):
        try:
            rsa.verify(dataToVerify.encode(), signature, self.publicKey)
            return True
        except:
            return False

    def loadString(self, publicKeyStr, privateKeyStr):
        self.publicKey = rsa.PublicKey.load_pkcs1(publicKeyStr)
        self.privateKey = rsa.PrivateKey.load_pkcs1(privateKeyStr)
        self.string()

class Transaction:#Class to store and execute a transaction
    def __init__(self, sender, receiver, value):
        self.sender = sender
        self.receiver = receiver
        self.value = value
        self.signature = ""

    def hash(self):
        transactionString = f"{self.sender}{self.receiver}{self.value}"
        return hashlib.sha256(transactionString.encode()).hexdigest()

    def verify(self, keypair, signature):
        return(keypair.verify(self.hash(),signature))

    def sign(self, keypair):
        self.signature = keypair.sign(self.hash())

info("Creating Keypair 1")
keypair1 = Keypair()
keypair1.new()

#Blockchain and mining loop
if __name__ == "__main__" and enableBlockchain:
    blockchain = Blockchain()       #Setup Blockchain
    if not blockchain.validate():   #Validate Blockchain
        err("Blockchain invalid")

    while True and enableMining:    #Main mining-loop
        lastBlock = blockchain.get_last_block()
        data = Data()
        #Trigger a transaction by pressing t
        if (keyboard.is_pressed("t")):
            sys("Transaction triggered")
            transaction = Transaction("A", "B", "1000")
            transaction.sign(keypair1)
            data.newTransaction(transaction)
        #New Block gets created and mined
        data.newText("Block #" + str(lastBlock.index), "Kekosaurusrexx")
        blockchain.addBlock(data.dump())
        #Quit loop by pressing q
        if(keyboard.is_pressed("q")):
            sys("Quitting...")
            break

    blockchain.dump()
    sys("Blockchain saved")
