import socket

host = "127.0.0.1"
port = 420

while True:
    inputstr = input()
    try:
        s = socket.socket()
        s.connect((host, port))
        s.send(inputstr.encode("UTF-8"))
        s.close()
    except:
        print("Could not send command")
