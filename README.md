# COMP9301 Cyber Security Project Proposal
### z5184991 Lance Young


## Background

Botnets are used today to implement many different attack vectors on the internet - from DDoS attacks to spam distribution. 

Botnets are a large collection of malware-infected machines. These machines, by some means, become infected over the internet and turn into a bot waiting for further instructions from a 'bot master'.

Therefore, a newly infected machine will try to establish a connection with one or more command & control (C&C) servers to download updates, retrieve instructions or send private data from the host.

Traditionally, IP addresses were hardcoded into the malware. However, as IT professionals become more cyber-aware, blocking all internet packets going to or from said suspicious IP addresses would result in the attacker losing connection to their bot. 

A popular solution was to instead use DNS queries to find the C&C's IP address and register a domain name accordingly. However, the same issue noted above still applies - a domain name can similarly be blocked.

So the domain generation algorithm (DGA) was born where attackers would register a huge set of all possible domain names generated from their DGA and an infected host machine would randomly select (or more accurately generate) one of the possible domain names depending on some sort of seed (eg. the current time and/or date).

This meant that it is a lot more difficult for IT professionals to detect malware packets being sent in and to the internet.


## Proposal Description

The proposed project will be to create a software tool capable of analysing real-time network traffic, and identifying particular known families of malware and collecting suspicious traffic for further research.

Dr Hassan Habibi Gharakheili, a lecturer at UNSW's school of Electrical Engineering and Telecommunications, is currently leading a broad project called Nozzle. He has agreed to be my supervisor and provide the required resources and data to accomplish this goal.

Nozzle has access to large academic records with known DNS domain names used by active DGA driven malware (accumulated through RE), and also to the live network traffic on a large enterprise. It should be noted that the Nozzle project has an ethics approval and is sensitive the privacy of users.

With this software tool, IT departments are able use it to identify the scale of infection by known malware families using DGA on their network. In addition, this tool will lead to further research on the data being send from and to malware programs.


## Milestones

1. Accumulate and prepare academic data with DNS domain names in a database for querying.
2. Using a test-sample of network traffic, parse suspicious DNS queries and get DNS response IP address (address of C&C server).
3. Collect all traffic related to identified C&C ip addresses.
4. Generate wave form analysis on packet flow.
5. Cluster results and identify different families of malware.
6. Perform the above analysis on live network-traffic.
7. Categorise found malware into a malware family.
8. Provide a simple visualisation tool to illustrate the prevalence of known malware using DGA on a network system.


## Schedule

Weeks

3. Design software architecture and complete milestones 1.
4. Research pcap parsing techniques and complete milestone 2.
5. Complete milestone 3 and 4.
6. Research clustering methods for data analytics and complete milestone 5.
7. Research real-time analysis techniques.
8. Complete milestone 6.
9. Complete milestone 7 and 8.
10. General improvements and report writing.
11. Submit report.


## Supervisor

Dr Hassan Habibi Gharakheili has agreed to act as my supervisor and agreed to meeting weekly for an hour each week.
