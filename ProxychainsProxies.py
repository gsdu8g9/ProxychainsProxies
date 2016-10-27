#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import re
import socksChecker #from https://github.com/BeastsMC/SOCKS-Proxy-Checker
import os
import socket
from struct import *

userAgent={"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36"}
foundProxy={}

def fromGatherProxies():
	req = requests.get("http://www.gatherproxy.com/sockslist", headers=userAgent)
	raw_html = req.text
	soup = BeautifulSoup(raw_html, "html.parser")
	soup2 = soup.findAll("script")
	ipx = ""
	portx = ""
	for tag in soup2:
		ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(tag))
		port = re.findall(r'[0-9]{4,5}', str(tag))
		if len(ip) != 0:
			ipx = ip[0]
		if len(port) != 0:
			portx = port[0]
		foundProxy[str(ipx)] = str(portx)


def fromXroxy():
	for page in range(0,5):
		req = requests.get("http://www.xroxy.com/proxylist.php?port=&type=Socks4&ssl=&country=&latency=&reliability=&sort=reliability&desc=true&pnum="+str(page)+"#table", headers=userAgent)
		raw_html = req.text
		soup = BeautifulSoup(raw_html, "html.parser")
		trs = soup.find_all('tr', {"class" : "row0"})
		ipx = ""
		portx = ""
		for tr in trs:
			ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(tr))
			port = re.findall(r'[0-9]{4,5}', str(tr))
			if len(ip) != 0:
				ipx = ip[0]
			if len(port) != 0:
				portx = port[3]
			foundProxy[str(ipx)] = str(portx)
		trs2 = soup.find_all('tr', {"class" : "row1"})
		for tr in trs2:
			ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(tr))
			port = re.findall(r'[0-9]{4,5}', str(tr))
			if len(ip) != 0:
				ipx = ip[0]
			if len(port) != 0:
				portx = port[3]
			foundProxy[str(ipx)] = str(portx)

def fromSamair():
	try:
		for page in range(1,7):
			req = requests.get("http://www.samair.ru/proxy/socks0"+str(page)+".htm", headers=userAgent)
			raw_html = req.text
			soup = BeautifulSoup(raw_html, "html.parser")
			soup2 = soup.findAll("td")
			ipx = ""
			portx = ""
			for page in soup2:
				ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(page))
				port = re.findall(r'[0-9]{4,5}', str(page))
				if len(ip) != 0:
					ipx = ip[0]
				if len(port) != 0:
					portx = port[0]
				foundProxy[str(ipx)] = str(portx)

	except Exception as e:
		print "Could not connect to Samair: " + str(e)

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
				socksVerison=getSocksVersion(singleIP[0], int(singleIP[1].strip()))
				if socksVerison!=0:
					conf.write("socks"+str(socksVerison)+"  " + str(singleIP[0]) + " " + str(singleIP[1]))
	except Exception as e:
		print "something failed in the printProxychainsConf-function: " + str(e)

def testProxies():
	try:
		with open("toTesting.txt", "a") as testingFactory:
			print "Sending " + str(len(foundProxy)) + " proxies to the doctor for diagnosis"
			for ip, port in foundProxy.items():
				if len(ip) > 1:
					testingFactory.write(str(ip) + ":" + str(port) + "\n")
	except Exception as e:
		print "Got the following error while sending proxies for lookup: " + str(e)
	try:
		os.system("./bin/python ./socksChecker.py")
	except Exception as e:
		print "Could not validate proxies: " + str(e)



####Code from socksChecker###
def isSocks4(host, port, soc):
	ipaddr = socket.inet_aton(host)
	packet4 = "\x04\x01" + pack(">H", port) + ipaddr + "\x00"
	soc.sendall(packet4)
	data = soc.recv(8)
	if (len(data) < 2):
		# Null response
		return False
	if data[0] != "\x00":
		# Bad data
		return False
	if data[1] != "\x5A":
		# Server returned an error
		return False
	return True

def isSocks5(host, port, soc):
	soc.sendall("\x05\x01\x00")
	data = soc.recv(2)
	if (len(data) < 2):
		# Null response
		return False
	if data[0] != "\x05":
		# Not socks5
		return False
	if data[1] != "\x00":
		# Requires authentication
		return False
	return True

def getSocksVersion(proxy, port):
	host = proxy.split(":")[0]
	try:
		port = int(proxy.split(":")[1])
		if port < 0 or port > 65536:
			print "Invalid: " + proxy
			return 0
	except:
		print "Invalid: " + proxy
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(10)
	try:
		s.connect((host, port))
		if (isSocks4(host, port, s)):
			s.close()
			return 4
		elif (isSocks5(host, port, s)):
			s.close()
			return 5
		else:
			("Not a SOCKS: " + proxy)
			s.close()
			return 0
	except socket.timeout:
		print "Timeout: " + proxy
		s.close()
		return 0
	except socket.error:
		print "Connection refused: " + proxy
		s.close()
		return 0
####

def createFiles():
	if os.path.exists("ok.txt"):
		pass
	else:
		file("ok.txt", 'w').close()

	if os.path.exists("toTesting.txt"):
		pass
	else:
		file("toTesting.txt", 'w').close()

	if os.path.exists("proxychains.conf"):
		pass
	else:
		file("proxychains.conf", 'w').close()

	#copying old proxyfile if any and making space for a new one if necessary
	if os.stat("proxychains.conf").st_size > 2:
		try:
			os.remove("proxychains.conf.old")
		except:
			pass
		os.rename("proxychains.conf", "proxychains.conf.old")
		file("proxychains.conf", "w").close()


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
	createFiles()
	fromXroxy()
	fromSamair()
	fromGatherProxies()
	testProxies()
	printProxychainsConf()
	emptyFiles()



if __name__ == "__main__":
	main()


"""
Todo:
- Check if empty files are available, if not, create them for writing
- Getting "invalid: <ip>" when checking proxies, needs a fixer-upper.
"""