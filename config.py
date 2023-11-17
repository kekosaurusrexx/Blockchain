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
enableBlockchain = True         #Enable blockchain, used for development
enableMining = True             #Enable mining, used for development
enableServer = True             #Enable socket server, used for development
enableClient = True             #Enable socket client, used for development

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
