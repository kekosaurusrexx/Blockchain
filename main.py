from modules import *

def functionMiner():#Mining function
    global exitFlag
    global minerQueue
    global blockchain
    Log.debug("Mining thread active")
    while not exitFlag:
        try:
            data = Data()
            data.minerData(minerKeys.publicKeyStr)
            while not minerQueue.empty():
                data.add(minerQueue.get())
            blockchain.addBlock(data.dump())
        except Exception as e:
            Log.debug(str(e))

def functionServer():#Socket server function
    global exitFlag
    global minerQueue
    global blockchain
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind((socketServerHost, socketServerPort))
    serverSocket.listen(socketServerClients)
    Log.debug(f"Server thread active on {socketServerHost}:{socketServerPort}")
    while not exitFlag:
        try:
            clientSocket, addr = serverSocket.accept()
            receivedData = clientSocket.recv(128).decode("utf-8")
            #Send size of current chain if requested
            if(receivedData=="chainsize"):
                Log.debug("Requested: chainsize")
                clientSocket.send(str(blockchain.getlength()).encode("utf-8"))
            #Send block with id x
            if(receivedData.startswith("block")):
                pattern = re.compile(r'^block_(\d+)')
                match = pattern.match(receivedData)
                if match:
                    number = int(match.group(1))
                    Log.debug("Requested: Block " + str(number))
                clientSocket.send(pickle.dumps(blockchain.read(number)))
            #Send list of nodes
            if(receivedData=="nodeslist"):
                Log.debug("Requested: Nodeslist")
                clientSocket.send(pickle.dumps(nodeList))
            #Add data of no type to the blockchain
            if(debugMode):
                if(receivedData=="hashrate"):
                    connec
                if(receivedData.startswith("data_")):
                    Log.debug("Data received")
                    receivedData[5:]
                    newData = Data()
                    newData.add(receivedData)
                    minerQueue.put(newData.datachain[0])
                #Only for testing, stop server with this command
                if(receivedData=="stop"):
                    Log.debug("Stop triggered")
                    exitFlag = True
                #Only for testing, trigger test transaction
                if(receivedData=="tt"):
                    Log.debug("Transaction triggered")
                    keypair1 = Keypair()
                    keypair2 = Keypair()
                    keypair1.new()
                    keypair2.new()
                    transaction = Transaction(keypair1.publicKeyStr, keypair2.publicKeyStr, "1000")
                    transaction.sign(keypair1)
                    newData = Data()
                    newData.newTransaction(transaction)
                    minerQueue.put(newData.datachain[0])
            clientSocket.close()
        except Exception as e:
            Log.warning("Socket server crashed with Exception: " + str(e))
    Log.debug("Server closed")

def functionClient():#Socket client function
    global exitFlag

if __name__ == "__main__":
    #Variables, do not change
    nodeList = []
    exitFlag = False
    minerQueue = Queue()
    blockchain = Blockchain()
    minerKeys = Keypair()
    #Validating blockchain & keys
    blockchain.validate(True)
    minerKeys.minerkeys()
    #Setting up the threads
    threadMining = threading.Thread(target=functionMiner)
    threadServer = threading.Thread(target=functionServer)
    threadClient = threading.Thread(target=functionClient)
    #Starting all threads
    threadMining.start()
    threadServer.start()
    threadClient.start()
    Log.info("Started successful")
    #Waiting for the threads
    threadMining.join()
    threadServer.join()
    threadClient.join()
    Log.info("Stopped succesful")
