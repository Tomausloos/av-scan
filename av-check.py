#!/usr/bin/env python3

import sys
import os
import psutil

print ("Loading known AV-processes...")
AV_Check = []
try:
	file = open("known-av-processes.txt", "r")
	content = file.read()
	AV_Check = content.split("\n")
except IOError as e:
   print ("I/O error({0}): {1}".format(e.errno, e.strerror))
except: 
   print ("Unexpected error:", sys.exc_info()[0])
print ("done")
print ("AV-Scan Running...")

found = {}

status = False

for proc in psutil.process_iter(['pid', 'name']):
	if proc.info['name'] in AV_Check:
		found[proc.info['pid']] = proc.info['name']
		status = True

if status == False:
	print ("No Anti-Virus Software found.")
else:
	print ("Found " + str(len(found)) + " Anti-Virus processes running:")
	for key, value in found.items():
		print(key, ' : ', value)

