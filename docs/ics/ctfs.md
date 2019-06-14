[EN](./ctfs.md) | [ZH](./ctfs-zh.md)
&gt; The content of this column, the content of the ICS CTF competition comes from the author&#39;s own experience in playing the game. If it is not right, please criticize and correct the teacher.


## Domestic industrial control competition inspection point


Using the CTF classification model to summarize and analyze the key points in the current industrial control ICS competition


|Competition Type|Investigation Point|Similar to CTF|
|-------|------|-------|

|Intranet penetration|Web-side penetration testing, CMS system, industrial control release display system, database system|related to Web penetration
| Reverse Analysis | Firmware Analysis, Industrial Control Software Reverse | Actual Scene Reverse |
| Industrial Control Protocol | Industrial Control Flow Analysis, Misc Class | Misc Flow Analysis, Industrial Control Flow Characteristics |
| Industrial Control Programming | PLC Configuration, HMI Configuration, RTU Configuration, etc. | Industrial Control Configuration Software Use, Ladder Recognition and Analysis |


According to the type of vulnerability, it is also possible to distinguish the types of refinement topics, including common Web injection classes, firmware weak passwords, backdoor programs, protocol replay and logic issues, configuration deployment issues, and other common industrial security scenarios.


|Competition Type|Vulnerability Type|
|-------|------|

|Intranet penetration|Web class (SQL, XSS, command injection, sensitive file disclosure. git/.idea/.project, etc.)
| Reverse Analysis | Firmware Analysis, Industrial Control Software Reverse | Actual Software, DLL, ELF, MIPS Reverse |
| Industrial Control Protocol | Industrial Control Flow Analysis, Misc Class | Misc Flow Analysis, Industrial Control Flow Characteristics |
| Industrial Control Programming | PLC Configuration, HMI Configuration | Industrial Control Real Configuration Software Use, Ladder Recognition and Analysis |


In view of the types of ICS CTFs that have appeared or have appeared in the past, there are many coincidences with the CTF competition. Therefore, this is not to be repeated. It is mainly discussed in the CTF that is not consistent with the CTF competition.


## Web penetration class (Web)


This section focuses on the characteristics of industrial control Web penetration:


- Highly compatible with business scenarios. For example, in industrial control, the Web terminal mainly displays information such as control parameters and running status in the current usage scenario. If it is hijacked by an intermediary in the internal network, the HMI display device cannot run the device in real time with the PLC. When synchronizing, the system will alarm or make an error.
- General use of common technology to display the Web interface, with the Windows operating system as the main platform, including WinCC, Windows Server, Windows 98/2000/XP and other seemingly ancient systems.
- Web infiltration will retain multiple ports, such as FTP, HTTPS, Telnet, SNMP, NTP and other service ports, you can try other ports while Web penetration can not be penetrated.
- Because industrial control is generally in the internal network environment, intranet hijacking is often more effective. However, if the internal network is configured with static IP or other protection measures, the intranet hijacking method such as ARP spoofing mode cannot take effect.
- Sensitive information leaks and incomplete configuration files are common problems in industrial control web publishing. Not only include engineering information protocols such as .git/.idea/.project, but also path traversal, command injection, weak passwords, etc.


## Reverse Analysis (Reverse)


This section mainly discusses the characteristics of industrial control reverse:


- The industrial control operating system is generally RTOS (Real Time Operate System). For example, real-time operating systems such as vxworks and uc-os need to be familiar with the architecture and instruction set in the reverse direction. If you do not understand, please learn by yourself.
- The common target of industrial control firmware reverse is the common firmware reverse vulnerability such as industrial control engineering encryption algorithm, hard coded key, hard coded backdoor, etc. If a stack overflow vulnerability is discovered, it can often lead to target device downtime (ie DOS consequences).
- The firmware of the industrial control often has encryption and compression. It needs to be decompressed or decrypted in the first step of decompression. This part is based on the specific manufacturer and cannot be generalized.
- Industrial control firmware has no reverse analysis


## Industrial Control Protocol (Protocol)


This section mainly talks about the relevant characteristics of industrial control protocol topics:


- The industrial control protocol is designed for industrial control scenarios, with features such as simplicity, high efficiency, and low latency. Therefore, simple attacks such as replay and command injection can be considered for such attacks.
- The industrial control protocol not only uses the public agreement, but also includes a large number of private agreements. The specific details of this part of the agreement need to reverse or collect data to achieve the restoration of data functions. For example, Modbus, DNP3, Melsec-Q, S7, Ethernet/IP, etc.
- The industrial control protocol may cause problems such as downtime and non-restart of the target PLC, DCS, RTU, etc. The Fuzz-based method can quickly and efficiently find the PLC downtime vulnerability.
- There may be many operations in the industrial control protocol for devices such as PLCs. Users need to distinguish between legal requests and exception requests. This requires experience and needs to study the logic of the current traffic. This scene is very suitable for the conditions of machine learning, which can be considered as a direction of exploration.
- The actual defense scheme for the industrial control scenario is actually the best bypass detection. The traffic is connected to the analysis system through the splitting, and the target system is monitored safely without affecting the normal service usage.




## 工控编程(Program)


Industrial control programming is the core and focus of the operation of industrial control systems. The characteristics of such topics are generally:


- The core of industrial control programming is to understand the logic of industrial control business, and the industrial control programming follows IEC61131-3 (the first standard in the history of industrial control to realize joint programming of PLC, DCS, motion control, SCADA, etc. - IEC61131-3), including five programming language standards. The three types are graphical languages (ladder diagrams, sequential function diagrams, and function block diagrams), and two are textual languages (instruction tables and structured text).
- Industrial control equipment can often be debugged online, so that some input and output ports can be controlled to realize the function of forced start and stop. If these functions can be retransmitted by Remote, the attack hazard is more serious.
- Industrial control equipment is connected in a variety of ways, generally using a serial port, but the current development of the device supports Ethernet, USB interface and other new methods, if the network port does not try serial port, USB.
- The industrial control configuration can be very complicated. It is even possible to connect hundreds or thousands of inputs and outputs. The configuration will be more troublesome due to the addition of new components. At this time, you should look slowly and pick it up a little bit.


The above is some of my experience in participating in the industrial control competition, hoping to give more guidance to the small partners who will participate in the competition.