from modules import *
con = Connection("localhost",420)
while True:
    inputstr = input(">> ")
    try:
        print(f"< {con.fetch(inputstr)}")
    except:
        print("< Error sending command")
