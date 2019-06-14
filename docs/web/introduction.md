[EN](./introduction.md) | [ZH](./introduction-zh.md)
With the birth of a series of new Internet products such as WEB 2.0, social network, Weibo, etc., Internet applications based on WEB environment are more and more extensive. In the process of enterprise informationization, various applications are set up on WEB platform, WEB business. The rapid development has also aroused strong concern of hackers. What followed is the emergence of WEB security threats. Hackers use the vulnerability of the operating system and the vulnerability of the WEB service program to gain control of the WEB server, and tamper with the content of the webpage. Stealing important internal data, and more serious, is to embed malicious code in web pages, causing website visitors to be compromised.


In the CTF competition, WEB is also one of the most important directions. The WEB category has a wide variety of topics, and the knowledge points are fragmented and time-sensitive. It can keep up with the current hotspots and be close to actual combat.


Topics in the WEB class include, but are not limited to, SQL injection, XSS cross-site scripting, CSRF cross-site request forgery, file uploading, file inclusion, framework security, PHP common vulnerabilities, code auditing, and more.


## SQL Injection


By injecting SQL syntax into user-controllable parameters, the original SQL structure is destroyed, and the attack behavior of unexpected results when writing the program is achieved. The cause can be attributed to the superposition of the following two reasons:


1. The programmer writes the SQL statement using string concatenation when dealing with application and database interactions.
2. The user controllable parameters are not filtered enough to splicing the parameters into the SQL statement.


## XSS Cross-site scripting attack


Cross Site Scripting is abbreviated to the abbreviation of Cascading Style Sheets (CSS), so the cross-site scripting attack is abbreviated as XSS. A malicious attacker inserts malicious HTML code into the WEB page. When the user browses the page, the HTML code embedded in the Web will be executed, thereby achieving the special purpose of maliciously attacking the user.


## Command Execution


When an application needs to call some external program to process the content, some functions that execute system commands are used. For example, `system`, `exec`, `shell_exec`, etc. in PHP, when the user can control the parameters in the command execution function, the malicious system command can be injected into the normal command, causing the command execution attack. Here is mainly the introduction of command execution vulnerabilities mainly in PHP, and the details of Java and other applications are to be added.


## File contains


If the client user input is allowed to control the files dynamically included in the server, it will lead to the execution of malicious code and the disclosure of sensitive information, mainly including local file inclusion and remote file inclusion.


## CSRF Cross-site request forgery


Cross-Site Request Forgery (CSRF) is an attack that causes a logged-in user to perform some action without their knowledge. Because the attacker does not see the response to the fake request, the CSRF attack is mainly used to perform actions instead of stealing user data. When the victim is a normal user, CSRF can transfer the user&#39;s funds, send mail, etc. without their knowledge; but if the victim is a user with administrator rights, CSRF may threaten the entire WEB system. Safety.


## SSRF server-side request forgery


SSRF (Server-Side Request Forgery) is a security vulnerability that is constructed by an attacker to form a request initiated by a server. In general, the target of an SSRF attack is an internal system that is inaccessible from the external network.


## File Upload


In the operation of the website, it is inevitable to update some pages or contents of the website, and then the function of uploading files to the website is needed. If you do not restrict the restrictions or the restrictions are bypassed, this feature may be used to upload executable files, scripts to the server, and further cause the server to fall.


## Click to hijack


Clickjacking was first created in 2008 by Internet security experts Robert Hansen and Jeremiah Grausman.


It is a kind of visual spoofing. On the WEB side, the iframe is nested with a transparent and invisible page, so that the user can click on the location where the attacker wants to trick the user into clicking without knowing it.


Due to the appearance of clickjacking, there is a way of anti-frame nesting, because clickjacking requires iframe nested pages to attack.


The following code is the most common example of preventing frame nesting:


`` `js
if(top.location!=location)

    top.location=self.location;

```



## VPS Virtual Private Server


VPS (Virtual Private Server) technology, which divides a server into high-quality services for multiple virtual private servers. The technology for implementing VPS is divided into container technology and virtualization technology. In a container or virtual machine, each VPS can be assigned a separate public IP address, a separate operating system, and achieve isolation between different VPS disk space, memory, CPU resources, processes, and system configurations, simulating exclusive use for users and applications. The experience of using computing resources. VPS can reinstall the operating system, install programs, and restart the server separately, just like a standalone server. VPS provides users with the freedom to manage configurations for enterprise virtualization or for IDC resource leases.


IDC resource rental, provided by the VPS provider. The difference in hardware VPS software used by different VPS providers and the different sales strategies, the VPS experience is also quite different. Especially when the VPS provider is oversold, the VPS performance will be greatly affected when the physical server is overloaded. Relatively speaking, container technology is more efficient and more expensive than virtual machine technology hardware, so the price of container VPS is generally lower than the price of virtual machine VPS.


## Conditional competition


A conditional contention vulnerability is a server-side vulnerability. Because the server side processes concurrently when processing requests from different users, such problems may occur if the concurrent processing is improper or the logical sequence design of the related operations is unreasonable. .


## XXE


XXE Injection is XML External Entity Injection, which is an XML external entity injection attack. Vulnerabilities are security issues caused when processing non-secure external entity data.


In the XML 1.0 standard, the concept of entities is defined in the XML document structure. Entities can be called in the document by pre-definition, and the identifier of the entity can access local or remote content. If &quot;pollution&quot; is introduced in the process Sources, after processing XML documents, can lead to security issues such as information leakage.


## XSCH


Due to the negligence of web developers in the development process using Flash, Silverlight, etc., the correct configuration of the cross-domain policy file (crossdomain.xml) did not cause problems. E.g:


```xml

<cross-domain-policy>

    <allow-access-from domain=“*”/>

</cross-domain-policy>

```



Because the cross-domain policy file is configured as `*`, it means that any domain Flash can interact with it, which can initiate requests and get data.


## 越权 (function level access missing)


An unauthorized vulnerability is a common security vulnerability in web applications. Its threat is that an account can control the total station user data. Of course, this data is limited to the data corresponding to the vulnerability feature. The cause of the ultra-authority vulnerability is mainly because the developer over-trusts the data requested by the client when adding, deleting, modifying, and querying the data, and misses the authority. So testing over-authorization is a process of careful planning with developers.


## Sensitive information disclosure


Sensitive information refers to information that is not known to the public, has actual and potential use value, and is harmless to society, business or individuals due to loss, improper use or unauthorized access. Including: personal privacy information, business operations information, financial information, personnel information, IT operation and maintenance information.
Leaks include Github, Baidu Library, Google code, website directories, and more.


## Incorrect security configuration


Security Misconfiguration: Sometimes, using the default security configuration can make your application vulnerable to multiple attacks. It is important to use the best security configuration available in deployed applications, web servers, database servers, operating systems, code libraries, and all application-related components.


## WAF


Web application protection system (also known as: Web application level intrusion prevention system. English: Web Application Firewall, referred to as: WAF). Take advantage of an internationally accepted statement: WEB Application Firewall is a product that specifically protects WEB applications by implementing a series of security policies for HTTP/HTTPS.


## IDS



IDS is the abbreviation of English Intrusion Detection Systems, which means &quot;intrusion detection system&quot; in Chinese. Professionally speaking, according to a certain security policy, through the software and hardware, the network and system operation status are monitored, and various attack attempts, attacks or attack results are found as much as possible to ensure the confidentiality and integrity of the network system resources. And availability. To make an image metaphor: If the firewall is the door lock of a building, IDS is the monitoring system in this building. Once the thief climbs into the building, or the insider has an out-of-bounds behavior, only the real-time monitoring system can detect the situation and issue a warning.


## IPS



Intrusion Prevention System (IPS) is a computer network security facility that complements Antivirus Programs and Packet Filters (Application Gateways). Intrusion-prevention system is a computer network security device that can monitor the network data transmission behavior of a network or network device, and can instantly interrupt, adjust or isolate some abnormal or harmful network data transmission behavior. .


## References


- [WEB 渗透 Wiki](http://wiki.jeary.org/#!websec.md)
