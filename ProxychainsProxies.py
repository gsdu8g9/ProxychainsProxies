#!/bin python
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import re
import socksChecker #from https://github.com/BeastsMC/SOCKS-Proxy-Checker
import os
import subprocess

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
		port = re.findall(r'[0-9]{4,5}', str(tag))
		if len(ip)!=0:
			foundIP.append(ip[0])
		if len(port)!=0:
			foundPort.append(port[0])


def fromXroxy():
	for page in range(0,5):
		req = requests.get("http://www.xroxy.com/proxylist.php?port=&type=Socks4&ssl=&country=&latency=&reliability=&sort=reliability&desc=true&pnum="+str(page)+"#table", headers=userAgent)
		raw_html = req.text
		soup = BeautifulSoup(raw_html, "html.parser")
		trs = soup.find_all('tr', {"class" : "row0"})
		for tr in trs:
			ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(tr))
			port = re.findall(r'[0-9]{4,5}', str(tr))
			if len(ip) != 0:
				foundIP.append(ip[0])
			if len(port) != 0:
				foundPort.append(port[3])
		trs2 = soup.find_all('tr', {"class" : "row1"})
		for tr in trs2:
			ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(tr))
			port = re.findall(r'[0-9]{4,5}', str(tr))
			if len(ip) != 0:
				foundIP.append(ip[0])
			if len(port) != 0:
				foundPort.append(port[3])


def fromSamair():
	for page in range(0,5):
		req = requests.get("http://www.samair.ru/proxy/socks0"+str(page)+".htm", headers=userAgent)
		raw_html = req.text
		soup = BeautifulSoup(raw_html, "html.parser")

def printProxychainsConf():
	template = open("template.conf", 'r')
	try:
		with open("ok.txt", 'r') as niceProxies:
			proxies=niceProxies.readlines()

		with open("proxychains.conf", "a") as conf:
			for each in template:
				conf.write(each)
			for singleproxy in proxies:
				singleIP=singleproxy.split(":")
				conf.write("socks4  " + str(singleIP[0]) + " " + str(singleIP[1]))
	except Exception as e:
		print "something failed in the printProxychainsConf-function: " + str(e)

def testProxies():
	amount=len(foundIP)
	with open("toTesting.txt", "a") as testingFactory:
		for x in range(0,amount):
			print "To testing factory: " + str(foundIP[x])
			testingFactory.write(str(foundIP[x]) + ":" + str(foundPort[x]) + "\n")
	try:
		subprocess.call("./bin/python ./socksChecker.py", cwd='./', shell=True)
	except Exception as e:
		print "Could not validate proxies: " + str(e)


def fromSpysRu():
	pass

def createFiles():
	if os.path.exists("ok.txt"):
		pass
	else:
		file("ok.txt", 'w').close()

	if os.path.exists("toTesting.txt"):
		pass
	else:
		file("toTesting.txt", 'w').close()

def emptyFiles():
	try:
		with open("toTesting.txt", 'w+') as testing:
			testing.seek(0)
			testing.truncate()
			testing.close()
	except Exception as e:
		print "Didn't delete any file called toTesting.txt: " + str(e)

	try:
		with open("ok.txt", "w+") as ok:
			ok.seek(0)
			ok.truncate()
			ok.close()
	except Exception as e:
		print "Didn't delete any file called ok.txt: " + str(e)


def main():
	#createFiles()
	fromGatherProxies()
	fromXroxy()
	#fromSamair()
	testProxies()

	printProxychainsConf()
	#emptyFiles()

if __name__ == "__main__":
	main()


"""
Notes to self:
Sen ska Samair fixas
Se om det är en socks4 eller socks5 och lägga till i proxyconf-fien
Ska göra så att funktionen createFiles fungerar
Göra så subprocess ej behöver användas
"""