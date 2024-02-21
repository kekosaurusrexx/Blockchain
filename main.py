import hashlib, time
import pickle
from os.path import exists
from queue import Queue
import os
import keyboard
import random
import json
import rsa
import threading
import socket
import re
###Configuration for this node
miningdifficulty = 5            #Set mining difficulty
blockchainfolder = "blockchain" #Set path to blockchain folder
dataperblock = 4                #Number of datapoints per block
keyfile = "keys"                #Set name of key file
socketServerHost = "127.0.0.1"  #Socket server host
socketServerPort = 6969         #Socket server port
socketServerClients = 10        #Socket server max. clients
showInfo = True                 #Enable information messages
showWarn = True                 #Enable warning messages
showErr = True                  #Enable error messages
showSys = True                  #Enable system messages
###Predefinded variables
exitFlag, newDataChain, nodeList, minerQueue = False, [], [], Queue()
##Logging functions
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
#Block class, includes hashing and self
class Block:#Class to create a single block
    def __init__(self, index, prevHash, timestamp, data, proof):#Initialize the block
        self.index = index
        self.prevHash = prevHash
        self.timestamp = timestamp
        self.data = data
        self.dataHash = ""
        self.proof = proof
        self.size = len(f"{self.index}{self.prevHash}{self.timestamp}{self.data}{self.proof}")

    def hash(self):#Create hash of the block but using hashData instead of hashing the data again
        blockString = f"{self.index}{self.prevHash}{self.timestamp}{self.dataHash}{self.proof}"
        return hashlib.sha256(blockString.encode()).hexdigest()

    def hashData(self):#Prevents to have the whole data hashed again, this hash can be used for efficency with no tradeoffs
        self.dataHash = hashlib.sha256(self.data.encode()).hexdigest()

    def dump(self):#Writing the block to file
        output = open(blockchainfolder + "/" + str(self.index), "wb")
        pickle.dump(self, output)
        output.close()

    def validProof(self):
        guessHash = self.hash()
        return (guessHash[:miningdifficulty] == "0"*miningdifficulty)

class Blockchain:#Class to store and use the blockchain
    def __init__(self):#Initialize the blockchain
        self.chain = []#Creating the blockchain list
        if (exists(blockchainfolder)):#Checking if blockchainfolder exists
            if (exists(blockchainfolder + "/0")):#Checking if genesis block exists
                self.load()
            else:#If no genesis block exists, create one
                sys("No Blockchain found")
                self.createGenesisBlock()
        else:#If no blockchain exists, create folder and genesis block
            sys("No Blockchain found")
            os.mkdir(blockchainfolder)
            self.createGenesisBlock()

    def createGenesisBlock(self):#Create genesis block with no data
        genesis = Block(0, "0", int(time.time()), "Genesis Block", 0)
        info("Genesis block created")
        self.chain.append(genesis)

    def getLastBlock(self):#Return last block of blockchain
        return self.chain[-1]

    def addBlock(self, data):#Add block to blockchain, actually includes the mining algorithm
        index = len(self.chain)
        prevHash = self.getLastBlock().hash()
        timestamp = int(time.time())
        counter = 0
        proof = 0
        newBlock = Block(index, prevHash, timestamp, data, proof)
        newBlock.hashData()
        while True:#Bruteforce valid proof
            proof = random.randint(0,999999999999999)
            newBlock.proof = proof
            counter += 1
            if(newBlock.validProof()):#Check if proof is valid
                endTime = time.time()
                try:
                    usedTime= endTime-timestamp
                    hashSpeed = counter/usedTime
                    info("Block #" + str(index) + " mined | Hashspeed: " + str(round(hashSpeed / 1000)) + "kH/s in " + str(round(usedTime,2)) + "s | Size: " + str(newBlock.size) + " bytes")
                except:
                    warning("Could not calculate Hashspeed")
                self.chain.append(newBlock)
                break

    def dump(self):#Go trough each block and dump it to disk
        for block in self.chain:
            block.dump()

    def load(self):#Load blockchain from disk
        nBlock = 0
        while True:#Find the highest id of blocks in the blockchain
            if exists(blockchainfolder+"/"+str(nBlock)):
                nBlock += 1
            else:
                break
        nBlock -= 1
        for i in range(nBlock):#load the blocks from disk
            with open(blockchainfolder+"/"+str(i), 'rb') as file:
                block = pickle.load(file)
                file.close()
            self.chain.append(block)
        sys(str(nBlock) + " blocks loaded")

    def validate(self):#Validate blockchain
        for i in range(1,len(self.chain)):
            if not self.chain[i].prevHash==self.chain[i-1].hash():
                return False
        return True

class Data:#Class to create and store data inside a block
    def __init__(self):#Initialize datachain
        self.datachain = []

    def dump(self):#Dump data to json
        dataStr = json.dumps(self.datachain)
        return(dataStr)

    def add(self, newData):#Add new raw data to datachain
        self.datachain.append(newData)

    def minerData(self, adress):#Add info about miner to datachain
        minerData = {"type": "miner", "adress": adress}
        self.add(minerData)

    def newText(self, text, sender):#Add text to datachain
        textData = {"type": "text", "sender": sender, "content": str(text[:512])}
        self.add(textData)

    def newTransaction(self,transaction):#Add transaction to datachain
        transactionData = {
            "type": "transaction",
            "sender": transaction.sender,
            "receiver": transaction.receiver,
            "value": transaction.value,
            "signature": transaction.signature,
            "timestamp": str(time.time())}
        self.add(transactionData)

class Keypair:#Class to store and use keypairs
    def __init__(self):#Initialize ke   ypair
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

class Node:
    def __init__(self):
        self.ipaddress = ""
        self.port = 0
        self.lastTimestamp = 0
        self.chainSize = 0

    def getChainSize(self):
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverAddress = (self.ipaddress, self.port)
        clientSocket.connect(serverAddress)
        clientSocket.sendall("chainsize".encode('utf-8'))
        data = clientSocket.recv(64)
        self.chainSize = int(data.decode('utf-8'))
        clientSocket.close()

    def getChain(self):
        self.getChainSize()
        i = 0
        receivedBlockchain = Blockchain()
        while i < self.chainSize:
            i += 1
            try:
                clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                clientSocket.connect(self.serverAddress)
                clientSocket.sendall(("block_" + str(i)).encode("utf-8"))
                receivedData = b""
                while True:
                    chunk = clientSocket.recv(1024)
                    if not chunk:
                        break
                    receivedData += chunk
                block = pickle.loads(receivedData)
                receivedBlockchain.chain.append(block)
                clientSocket.close()
            except Exception as e:
                print("Block #" + str(i) + " Exception: " + str(e))
        return(receivedBlockchain)

    def getNodeList(self):
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverAddress = (self.ipaddress, self.port)
        clientSocket.connect(serverAddress)
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect(serverAddress)
        clientSocket.sendall("nodeslist".encode("utf-8"))

        receivedData = b""
        while True:
            chunk = clientSocket.recv(1024)
            if not chunk:
                break
            receivedData += chunk
        newNodesList = pickle.loads(receivedData)
        return(newNodesList)
#Mining function, 
def functionMiner():
    sys("Mining thread active")
    while True:
        lastBlock = blockchain.getLastBlock()
        data = Data()
        data.minerData(minerKeys.publicKeyStr)
        while not minerQueue.empty():
            data.add(minerQueue.get())
        blockchain.addBlock(data.dump())
        if(exitFlag):
            break
    blockchain.dump()
    sys("Blockchain saved")

def functionServer():
    #Setting up the server side
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind((socketServerHost, socketServerPort))
    serverSocket.listen(socketServerClients)
    sys(f"Server active on {socketServerHost}:{socketServerPort}")
    while True:
        #If a connection sends bad data that crashes the server, it will just close the connection
        try:
            clientSocket, addr = serverSocket.accept()
            receivedData = clientSocket.recv(64).decode("utf-8")
            #Send size of current chain if requested
            if(receivedData=="chainsize"):
                info("Sending chainsize")
                clientSocket.send(str(len(blockchain.chain)-1).encode("utf-8"))
            #Send block with id x
            if(receivedData.startswith("block")):
                pattern = re.compile(r'^block_(\d+)')
                match = pattern.match(receivedData)
                if match:
                    number = int(match.group(1))
                    info("Sending Block #" + str(number))
                clientSocket.send(pickle.dumps(blockchain.chain[number]))

            if(receivedData=="nodeslist"):
                clientSocket.send(pickle.dumps(nodeList))

            if(receivedData=="stop"):
                sys("Exit triggered")
                exitFlag = True
            
            clientSocket.close()
            if(exitFlag==True):
                sys("Closing socket server")
                break
        except Exception as e:
            sys("Socket connection crashed with exception " + str(e))

def functionClient():
    try:
        testNode = Node()
        testNode.ipaddress = "127.0.0.1"
        testNode.port = 6969
        nodeList.append(testNode)
        time.sleep(3)
        #for node in nodeList:
            ###
            ###
            ###
    except Exception as e:
        sys("Socket client crashed with Exception: " + str(e))

minerKeys = Keypair()
if (exists(keyfile)):
    sys("Keyfile found")
    try:
        minerKeys.load(keyfile)
    except Exception:
        err("Could not load minerkeys")
else:
    sys("New keys are generated")
    minerKeys.new()
    minerKeys.dump(keyfile)

blockchain = Blockchain()       #Setup Blockchain
if not blockchain.validate(): err("Blockchain invalid") #If blockchain not valid, stop
#Create all threads for mining and networking
threadMining = threading.Thread(target=functionMiner)
threadServer = threading.Thread(target=functionServer)
threadClient = threading.Thread(target=functionClient)
#Start the threads
threadMining.start()
threadServer.start()
#threadClient.start()
while True:
    if(keyboard.is_pressed("t")):
        sys("Transaction triggered")
        keypair1 = Keypair()
        keypair1.new()
        keypair2 = Keypair()
        keypair2.new()
        transaction = Transaction(keypair1.publicKeyStr, keypair2.publicKeyStr, "1000")
        newData = Data()
        transaction.sign(keypair1)
        newData.newTransaction(transaction)
        minerQueue.put(newData)

    if(exitFlag):
        break
