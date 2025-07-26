## Glassfish 6.2.5 Server Side Request Forgery Vulnerability ( CVE-2024-9408 )

SSRF (Server-Side Request Forgery) is a vulnerability that allows an attacker to force the application to send requests from the server to internal or external resources of the attacker's choosing. This can enable the attacker to perform internal port scanning, discover services accessible only from the server, and bypass firewalls to reach otherwise restricted systems.

**Vulnerable Path** : https://[targetexample]:4848/download/log/?contentSourceId=LogViewer&restUrl=https%3A%2F%2F[evilpayload]

**Research Os** : Ubuntu 22.04 , Windows Server 2019  

**Vulnerable Parameter** : restUrl

### Impact
------------------------------------------------               
- [x] Port Scan and Network Discovery
- [x] Information disclosure
- [x] File Discovery


### Sample Attack Scenario
--------------------------------------------
![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/glassfish%20Scenario.jpg)

On GlassFish version 6.2.5, an attacker can exploit the ```restUrl``` parameter within the admin panel to trigger an SSRF vulnerability. In addition to performing port and subnet enumeration, the attacker can leverage the vulnerable GlassFish server to interact with their own machine listening within the network, leading to further exploitation such as path disclosure and file discovery. This significantly expands the attack surface.

### Vulnerability Discovery and Port Scanning
------------------------------------------------
**Attacker Ip:** 192.168.81.187

**Glassfish Server Ip:** 192.168.81.129 - Ubuntu(researchServer) Server Glassfish 6.2.5 


![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/port-scan1.png)

![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/port-scan2.png)

![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/port-scan3.png)

![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/port-scan4.png)

### Obtain gfresttoken 
------------------------------------------------
**Attacker Ip:** 192.168.81.187

**Glassfish Server Ip:** 192.168.81.129 - Ubuntu(researchServer) Server Glassfish 6.2.5 

![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/gfresttoken1.PNG)


![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/gfresttoken2.PNG)

### Path Disclosure
------------------------------------------------
**Attacker Ip:** 192.168.81.187

**Glassfish Server Ip:** 192.168.81.160 -  Windows Server Glassfish 6.2.5

![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/pathdisclosure.PNG)

### File Discovery 
------------------------------------------------
**Attacker Ip:** 192.168.81.187

**Glassfish Server Ip:** 192.168.81.129 - Windows Server Glassfish 6.2.5

![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/filediscovery1.PNG)

![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/filediscovery2.PNG)

![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/filediscovery3.PNG)

![](https://github.com/mustgundogdu/Glassfish-SSRF/blob/main/ss/filediscovery4.PNG)


