from tracemalloc import start
from config import *
from queue import Queue
import hashlib
import time
import pickle
import random
import json
import rsa
import threading
import socket
import re
import sqlite3

class Log:          #Logging functions
    def info(information):
        print("[INFO] " + information)

    def warning(warning):
        print("[WARN] " + warning)

    def error(error):
        print("[ERROR] " + error)
        exit(69)

    def debug(sysmsg):
        if debugMode:
            print("[DEBUG] " + sysmsg)

class Connection:   #Networking functions
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def fetch(self,command):
        try:
            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverAddress = (self.ip, self.port)
            clientSocket.settimeout(15)
            clientSocket.connect(serverAddress)
            clientSocket.sendall(command.encode('utf-8'))
            receivedData = b""
            while True:
                chunk = clientSocket.recv(1024)
                if not chunk:
                    break
                receivedData += chunk
            clientSocket.close() 
            return receivedData.decode("UTF-8")
        except Exception as e:
            Log.debug("Fetch failed" + e)

    def fetchobj(self, command):
        try:
            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverAddress = (self.ip, self.port)
            clientSocket.settimeout(15)
            clientSocket.connect(serverAddress)
            clientSocket.sendall(command.encode('utf-8'))
            receivedData = b""
            while True:
                chunk = clientSocket.recv(1024)
                if not chunk:
                    break
                receivedData += chunk
            clientSocket.close() 
            return pickle.loads(receivedData)
        except Exception as e:
            Log.debug("Fetch failed" + e)


class Block:        #Block class for hashing
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

    def validProof(self, proof):
        self.proof = proof
        guessHash = self.hash()
        return (guessHash[:miningdifficulty] == "0"*miningdifficulty)

class Blockchain:   #Class to store and use the blockchain
    def __init__(self): #Initialize the blockchain
        dbcon = sqlite3.connect(blockchaindb)
        dbcur = dbcon.cursor()
        dbcur.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name= '{blockchaintable}'")
        result = dbcur.fetchone()
        if not result:  #When table does not exist
            dbcur.execute(f"""CREATE TABLE {blockchaintable} (id INTEGER PRIMARY KEY AUTOINCREMENT, object TEXT NOT NULL)""")
        dbcon.close()

    def read(self, id):#Read a block form database
        dbcon = sqlite3.connect(blockchaindb)
        dbcur = dbcon.cursor()
        dbcur.execute(f"""SELECT object FROM {blockchaintable} WHERE id=?""", (id,))
        result = dbcur.fetchone()
        dbcon.close()
        if result: return(pickle.loads(result[0]))

    def write(self, obj):#Append a block to database
        dbcon = sqlite3.connect(blockchaindb)
        dbcur = dbcon.cursor()
        serialized_obj_bin = pickle.dumps(obj)
        dbcur.execute(f"""INSERT INTO {blockchaintable} (object) VALUES (?)""", (serialized_obj_bin,))
        dbcon.commit()
        dbcon.close()

    def getlength(self):#Get length of chain
        dbcon = sqlite3.connect(blockchaindb)
        dbcur = dbcon.cursor()
        dbcur.execute(f"SELECT COUNT(*) FROM {blockchaintable}")
        length = int(dbcur.fetchone()[0])
        dbcon.close()
        return(length)

    def createGenesisBlock(self):#Create genesis block
        genesis = Block(1, "0", int(time.time()), "Genesis Block", 0)
        Log.debug("Genesis block created")
        self.write(genesis)

    def validate(self,stop=False):#Validate current blockchain
        if(self.getlength()==0):
            self.createGenesisBlock()
        for i in range(2,self.getlength()):
            if not self.read(i).prevHash==self.read(i-1).hash():
                if stop:
                    Log.error("Blockchain invalid")
                return False
        return True

    def getLastBlock(self):#Return latest block of blockchain
        return self.read(self.getlength())

    def addBlock(self, data):#Mine block and add to blockchain
        global kHashPerSec
        index = self.getlength()+1
        prevHash = self.getLastBlock().hash()
        timestamp = int(time.time())
        counter = 0
        newBlock = Block(index, prevHash, timestamp, data, 0)
        newBlock.hashData()
        while True:
            counter += 1
            if(newBlock.validProof(random.randint(0,999999999999999))):#Check if proof is valid
                endTime = time.time()
                try:#Sometimes the calculation fails for unexplaineable reason
                    usedTime= endTime-timestamp
                    kHashPerSec = str(round(counter/usedTime/1000))
                    Log.debug(f"Block #{str(index)} mined | Hashspeed: {kHashPerSec}kH/s in {str(round(usedTime,2))}s | Size: {str(newBlock.size)} bytes")
                except:
                    pass
                self.write(newBlock)
                break
    
class Data:         #Class that handles the data in a block
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

class Keypair:      #Class to store and use keypairs
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

    def minerkeys(self):
        if (exists(keyfile)):
            Log.debug("Keyfile found")
            try:
                self.load(keyfile)
            except Exception:
                Log.error("Could not load minerkeys")
        else:
            Log.info("New keys are generated")
            self.new()
            self.dump(keyfile)

class Transaction:  #Class to store and execute a transaction
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

class Node:         #Class to manage node connections
    def __init__(self, ip, port):
        self.connection = Connection(ip, port)
        self.lastTimestamp = 0
        self.chainSize = 0

    def getChainSize(self):
        data = self.connection.fetch("chainsize")
        self.chainSize = int(data)

    def getChain(self):
        self.getChainSize()
        self.recChain = Blockchain()
        for i in range(self.chainSize):
            data = self.connection.fetch("block_" + str(i))
            block = pickle.loads(data)
            self.recChain.chain.append(block)
        return(self.recChain)

    def getNodeList(self):
        data = self.connection.fetch("nodeslist")
        newNodesList = pickle.loads(data)
        return(newNodesList)
