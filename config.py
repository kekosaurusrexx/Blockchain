import hashlib, time
import pickle
from os.path import exists
import os
import keyboard
import random
import json
import rsa
import threading
import socket
import re

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
enableBlockchain = True         #Enable Blockchain, used for development
enableMining = True             #enable Mining, used for development