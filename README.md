# Strutsy
Strutsy - Mass exploitation of Apache Struts (CVE-2017-5638) vulnerability. Includes **blind** and **time based code injection** techniques which significantly reduces false negatives. Other features include mass URL imports to scan multiple targets in one go.

## Usage: 
### python strutsy.py <urls.txt> <windows/linux/default> <ip-address>

*All parameters are required.*

1. urls.txt - file containing the urls that are to be tested.
2. platform - should include either windows/linux/default.
3. ip-address - public facing ip-address required to test blind injection. Please note apache should be installed and the apache log files should be readable in-order to read the http request. If you donot wish to test against this feature input an arbitary ip-address.  

urls.txt:
1. Search for vulnerable struts application from Google dork: 
Google Dork syntax: inurl:"struts" filetype:action 
   I used pagodo (https://github.com/opsdisk/pagodo)to save the output: 
   python pagodo.py  -g dork.txt -l 200 -s -e 35.0 -j 1.1 >> urls.txt

2. Import URLs from Burp Suite after crawling your target.

3. Include the URL you wish to scan by manually including it in url.txt file.

This module exploits vulnerable Apache Struts (CVE-2017-5638) which fails to validate Content-Type HTTP headers resulting in arbitrary command execution. 
The original exploit (https://www.exploit-db.com/exploits/41570/) has been modified to include blind and time based blind command injection for windows and linux platforms. 
Please note the exploit actively exploits the remote system hence please ensure you have permission to scan the target first before using this tool. 
 
Vulnerable Apache struts versions:  2.3.5 through 2.3.31 and 2.5 through 2.5.10.

Tested on Windows 2008 and linux platforms.
