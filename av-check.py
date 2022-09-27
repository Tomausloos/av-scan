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

AV_Check_static = ["efpeadm.exe", "cfp.exe","fsdfwd.exe", "fsguiexe.exe","blackd.exe","kpf4gui.exe","nisum.exe","smc.exe","persfw.exe",
		"pccpfw.ex","msmpeng.exe", "navapsvc.exe", "avkwctl.exe","fsav32.exe", "mcshield.exe", 
		"ntrtscan.exe","avguard.exe", "ashServ.exe", "AVENGINE.EXE",
		"avgemc.exe", "tmntsrv.exe", "MsMpEng.exe", "AdAwareService.exe", "afwServ.exe", "avguard.exe", "AVGSvc.exe", 
            "bdagent.exe", "BullGuardCore.exe", "ekrn.exe", "fshoster32.exe", "GDScan.exe", 
            "avp.exe", "K7CrvSvc.exe", "McAPExe.exe", "NortonSecurity.exe", "PavFnSvr.exe", 
            "SavService.exe", "EnterpriseService.exe", "WRSA.exe", "ZAPrivacyService.exe"]

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

