from config import *
###Predefinded variables
exitFlag = False
exitMining = False
exitServer = False
exitClient = False
errorSocketServerThread = False
errorSocketClientThread = False
errorMiningThread = False
dataLock = False
newDataChain = []
nodeList = []

#Important classes for all objects
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
        textData = {"type": "text", "sender": sender, "content": str(text[:512])}
        self.add(textData)

    def newTransaction(self,transaction):
        transactionData = {
            "type": "transaction",
            "sender": transaction.sender,
            "receiver": transaction.receiver,
            "value": transaction.value,
            "signature": transaction.signature,
            "timestamp": str(time.time())}
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
                clientSocket.connect(serverAddress)
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


#Important assisting functions
def validProof(block):
    guessHash = block.hash()
    return (guessHash[:miningdifficulty] == "0"*miningdifficulty)

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

#Single thread functions
def miner():
    try:
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
    except Exception as e:
        errorMiningThread = True
        sys("Mining Thread crashed with exception " + str(e))

def socketServer():
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

            clientSocket.close()
            if(exitFlag==True):
                sys("Closing socket server")
                break
        except Exception as e:
            sys("Socket connection crashed with exception " + str(e))

def socketClient():
    try:
        testNode = Node()
        testNode.ipaddress = "127.0.0.1"
        testNode.port = 6969
        nodeList.append(testNode)
        time.sleep(3)
        for node in nodeList:
            ###
            ###
            ###
    except Exception as e:
        sys("Socket client crashed with Exception: " + str(e))

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

    #Main loop
    if enableBlockchain:
        blockchain = Blockchain()       #Setup Blockchain
        if not blockchain.validate(): err("Blockchain invalid")

        miningThread = threading.Thread(target=miner)
        socketServer = threading.Thread(target=socketServer)
        socketClient = threading.Thread(target=socketClient)

        if(enableServer): socketServer.start()
        if(enableMining): miningThread.start()
        if(enableClient): socketClient.start()

        while True:
            if(errorSocketServerThread): exitFlag = True
            if(errorMiningThread): exitFlag = True
            if(errorSocketClientThread): exitFlag = True
            if(keyboard.is_pressed("q")):
                sys("Exit triggered")
                exitFlag = True

            if(keyboard.is_pressed("t") and enableMining):
                sys("Transaction triggered")
                keypair1 = Keypair()
                keypair1.new()
                keypair2 = Keypair()
                keypair2.new()
                #Create new transaction
                transaction = Transaction(keypair1.publicKeyStr, keypair2.publicKeyStr, "1000")
                newData = Data()
                #Push transaction data to miner-thread
                transaction.sign(keypair1)
                newData.newTransaction(transaction)
                pushToMiner(newData)

            if(exitFlag):
                exitMining = True
                exitServer = True
                exitClient = True
                break
