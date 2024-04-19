**Szymon Głuch:**
- NETXP EQL process with double extensions (filename.pdf.exe) - Regex dla format nazwa_pliku.rozszerzenie.rozszerzenie
- NETXP EQL Traffic to EC2/S3 services - Do poprawy, kwestia uzycia funkcji sequnce i wykorzystania dalszej komunikacji do wyciagniecia certyfikatu?
- Potential PowerShell HackTool Script by Function Names - 	Do poprawy pipeline ze względu na typ fieldow (text)
- Python usage on critical machines - Dodac uzycie pythona przez powershella - do poprawy caly pipeline
- NETXP EQL Attack followed by resource exhaustion - Identifies sequence of events. Logged attack attempt by Suricata followed by windows event 2004 - Resource exhaustion on critical machines.
- NETXP Web attack followed by 200 OK response - The rule is designed to identify a sequence of events in which a web attack occurs, followed by a subsequent HTTP response with a status code of 200. The rule is crafted for detecting potential instances of attacks on web systems, where the attacker's actions are succeeded by a successful response from the targeted server.
- NETXP EQL ELAM detected unsigned driver wanting to be loaded upon startup - Identifies unsigned driver during early bootup process. Early Launch AntiMalware service checks each driver upon it's initialization, if someone made a mistake during remapping vulnerable driver and the signature is gone then the event code is generated (or the driver is unsigned by mistake).
- NETXP PowerShell Script Detected Calling a Credential Prompt
- NETXP EQL User logged on multiple stations simultaneously
- NEXTXP Connection to 50 or more countries - kalibracja
- NETXP TI Detected malicious file hash
- NETXP TI Detected malicious process hash
- NETXP EQL Suspicious Buffer overflow attempt on linux machine
- NETXP EQL Kernel Panic detected
- NETXP EQL process with double extensions (filename.pdf.exe)
- NETXP DHCP spoofing attack detected
- NETXP Potential MAC flood detected
- NETXP TI Detected malicious process hash
- NETXP TI DNS resolved to malicious IPDomain
- NETXP TI DNS request forwarded to known malicious address
- NETXP TI Detected malicious file hash
- NETXP TI Detected communication with known malicious IP
- NETXP New application installation outside of business hours
- NETXP EQL Unapproved local DNS request TEST

**Dawid Przyczyna:**
- NETXP User Account Creation Outside Bussines Hours
- NETXP Outbound TOR Traffic
- NETXP Windows Defender Detected Malware
- New Process Found
- Anomalne Procesy 
- Nowe procesy

**Eliza Samsel:**
- NETXP SQL injection from inside
- NETXP XSS from INSIDE
- NETXP Audit Log Was Cleared
- NETXP System shutdown  reboot outside hours 

**Michał Zadruski:**
TODO




Do wykorzystania reguł niezbędny jest podany niżej config z działającą usługą auditd na dowolnej dystrybucji Linuxa (Redhat ma problemy z resetowaniem usługi auditd ze względów bezpieczeństwa).

Żeby zamienić config trzeba:\
-wyłączyć serwis auditd\
-usunąć plik audit.rules w /etc/audit/rules.d\
-pobrać i wrzucić nowy plik audit.rules do folderu rules.d (alternatywnie można wget z tego linku "https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules") \
-zrestartować serwis \
