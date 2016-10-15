#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import threading
import re
import socksChecker

userAgent={"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36"}
foundIP=[]
foundPort=[]

def fromGatherProxies():
	req = requests.get("http://www.gatherproxy.com/sockslist", headers=userAgent)
	raw_html = req.text
	soup = BeautifulSoup(raw_html, "html.parser")
	soup2 = soup.findAll("script")
	for tag in soup2:
		ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(tag))
		port = re.findall(r'[0-9]{4}', str(tag))
		if len(ip)!=0:
			foundIP.append(ip)
		if len(port)!=0:
			foundPort.append(port)


def fromXroxy():
	pass

def fromSpysRu():
	pass

def fromSamair():
	pass

def printProxychainsConf():
	template = open("template.conf", 'r')
	"""with open("proxychains.conf", "a") as conf:
		for each in template:
			conf.write(each)

		numbersFound=len(foundIP)
		for x in range(0, numbersFound):
			conf.write("socks4  " + str(foundIP[x])[2:-2] + " " + str(foundPort[x])[2:-2] + "\n")
			"""

def testProxies():
	amount=len(foundIP)
	with open("toTesting.txt", "a") as testingFactory:
		for x in range(0,amount):
			testingFactory.write(str(foundIP[x])[2:-2] + ":" + str(foundPort[x])[2:-2] + "\n")
	try:
		socksChecker.wT.start()
	except:
		pass

def main():
	fromGatherProxies()
	testProxies()

	#printProxychainsConf()

if __name__ == "__main__":
	main()
