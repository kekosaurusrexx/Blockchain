import hashlib, time
import pickle
from os.path import exists
import os
import keyboard
import random
import json
import rsa
import threading
###Settings for this script
miningdifficulty = 5            #Set mining difficulty
blockchainfolder = "blockchain" #Set path to blockchain folder
dataperblock = 4                #Number of datapoints per block
keyfile = "keys"                #Set name of key file
showInfo = True                 #Enable information messages
showWarn = True                 #Enable warning messages
showErr = True                  #Enable error messages
showSys = True                  #Enable system messages
enableBlockchain = True         #Enable Blockchain, used for development
enableMining = True             #enable Mining, used for development
###Predefinded variables
exitMining = False
newDataChain = []
dataLock = False

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

class Block:#Class to create a single block
    def __init__(self, index, prevHash, timestamp, data, proof):
        self.index = index
        self.prevHash = prevHash
        self.timestamp = timestamp
        self.data = data
        self.dataHash = ""
        self.proof = proof

    def hash(self):
        blockString = f"{self.index}{self.prevHash}{self.timestamp}{self.dataHash}{self.proof}"
        return hashlib.sha256(blockString.encode()).hexdigest()

    def hashData(self):
        self.dataHash = hashlib.sha256(self.data.encode()).hexdigest()

    def size(self):
        return(len(f"{self.index}{self.prevHash}{self.timestamp}{self.data}{self.proof}"))

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
        proof = 0
        newBlock = Block(index, prevHash, timestamp, data, proof)
        newBlock.hashData()
        while True:
            proof = random.randint(0,999999999999999)
            newBlock.proof = proof
            counter += 1
            if(validProof(newBlock)):
                endTime = time.time()
                try:
                    usedTime= endTime-timestamp
                    hashSpeed = counter/usedTime
                    info("Block #" + str(index) + " mined | Hashspeed: " + str(round(hashSpeed / 1000)) + "kH/s in " + str(round(usedTime,2)) + "s | Size: " + str(newBlock.size()) + " bytes")
                except:
                    warning("Could not calculate Hashspeed")
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

    def minerData(self, adress):
        minerData = {"type": "miner", "adress": adress}
        self.add(minerData)

    def newText(self, text, sender):
        textData = {"type": "text", "sender": sender, "content": str(text)}
        self.add(textData)

    def newTransaction(self,transaction):
        transactionData = {
            "type": "transaction",
            "sender": transaction.sender,
            "receiver": transaction.receiver,
            "value": transaction.value,
            "signature": transaction.signature}
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
        self.publicKeyStr = rsa.PublicKey.save_pkcs1(self.publicKey).decode("utf-8")
        self.privateKeyStr = rsa.PrivateKey.save_pkcs1(self.privateKey).decode("utf-8")

    def sign(self, dataToSign):
        signature = rsa.sign(dataToSign.encode(), self.privateKey, "SHA-256").decode("latin-1")
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

    def dump(self,filename):
        output = open(filename, "wb")
        pickle.dump(self, output)
        output.close()

    def load(self,filename):
        with open(filename, 'rb') as file:
            loadedkey = pickle.load(file)
            file.close()
        self.publicKey = loadedkey.publicKey
        self.publicKeyStr = loadedkey.publicKeyStr
        self.privateKey = loadedkey.privateKey
        self.privateKeyStr = loadedkey.privateKeyStr

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

def validProof(block):
    guessHash = block.hash()
    return (guessHash[:miningdifficulty] == "0"*miningdifficulty)

def mining():
    sys("Mining thread active")
    while True:
        lastBlock = blockchain.get_last_block()
        data = Data()
        data.minerData(minerKeys.publicKeyStr)
        for datapoint in getNewData():
            data.add(datapoint)
        blockchain.addBlock(data.dump())
        if(exitMining):
            break
    blockchain.dump()
    sys("Blockchain saved")

def pushToMiner(data):
    global dataLock
    global newDataChain
    while (dataLock):
        info("NewData is locked...")
    newDataChain.append(data.datachain[0])

def getNewData():
    global dataLock
    global newDataChain
    i = 0
    outputChain = []
    dataLock = True
    for dataPoint in newDataChain:
        if(i<dataperblock):
            outputChain.append(dataPoint)
            newDataChain.pop()
        i += 1
    dataLock = False
    return(outputChain)

#Blockchain and mining loop
if __name__ == "__main__":
    minerKeys = Keypair()
    if (exists(keyfile)):
        sys("Keyfile found")
        try:
            minerKeys.load(keyfile)
        except exception:
            err("Could not load minerkeys")
    else:
        sys("New keys are generated")
        minerKeys.new()
        minerKeys.dump(keyfile)

    keypair1 = Keypair()
    keypair1.new()
    keypair2 = Keypair()
    keypair2.new()

    if enableBlockchain:
        blockchain = Blockchain()       #Setup Blockchain
        if not blockchain.validate():   #Validate Blockchain
            err("Blockchain invalid")
        #Setup mining thread
        miningThread = threading.Thread(target=mining)
        miningThread.start()
        madeTransaction = False
        #Main Loop with keyboard triggers
        while True:
            if(keyboard.is_pressed("t")):
                madeTransaction = True
                sys("Transaction triggered")
                #Create new transaction
                transaction = Transaction(keypair1.publicKeyStr, keypair2.publicKeyStr, "1000")
                newData = Data()
                #Push transaction data to miner-thread
                transaction.sign(keypair1)
                newData.newTransaction(transaction)
                pushToMiner(newData)

            if(keyboard.is_pressed("q")):
                exitMining = True
                miningThread.join()
                break
