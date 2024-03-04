import configparser
from os.path import exists

configfilename = "config.ini"
debugMode = True

config = configparser.ConfigParser()
if not exists(configfilename):
    config["DEFAULT"]["miningdifficulty"] = "5"
    config["DEFAULT"]["blockchaindb"] = "blockchain.db"
    config["DEFAULT"]["blockchaintable"] = "chain"
    config["DEFAULT"]["keyfile"] = "miner.keys"
    config["DEFAULT"]["socketServerHost"] = "localhost"
    config["DEFAULT"]["socketServerPort"] = "420"
    config["DEFAULT"]["socketServerClients"] = "10"
    with open(configfilename, 'w') as configfile:
        config.write(configfile)

config.read(configfilename)
miningdifficulty = int(config["DEFAULT"]["miningdifficulty"])       #Set mining difficulty
blockchaindb = config["DEFAULT"]["blockchaindb"]                    #Set path to blockchain database
blockchaintable = config["DEFAULT"]["blockchaintable"]              #Set name of blockchain table in database
keyfile = config["DEFAULT"]["keyfile"]                              #Set name of key file
socketServerHost = config["DEFAULT"]["socketServerHost"]            #Socket server host
socketServerPort = int(config["DEFAULT"]["socketServerPort"] )      #Socket server port
socketServerClients = int(config["DEFAULT"]["socketServerClients"]) #Socket server max. clients
