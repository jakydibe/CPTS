# Introduzione

Solitamente lo scopo di fare privesc su windows e' arrivare a utente **Local Administrator** o **NT AUTHORITY\SYSTEM**.
COME CONNETTERSI AI LAB: **xfreerdp /v:<target ip> /u:htb-student**

## Useful Tools
| Tool                                     | Description                                                                                                                                                                                                       |
|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Seatbelt                                 | C# project for performing a wide variety of local privilege escalation checks                                                                                                                                   |
| winPEAS                                  | WinPEAS is a script that searches for possible paths to escalate privileges on Windows hosts. All of the checks are explained here                                                                              |
| PowerUp                                  | PowerShell script for finding common Windows privilege escalation vectors that rely on misconfigurations. It can also be used to exploit some of the issues found                                               |
| SharpUp                                  | C# version of PowerUp                                                                                                                                                                                           |
| JAWS                                     | PowerShell script for enumerating privilege escalation vectors written in PowerShell 2.0                                                                                                                       |
| SessionGopher                            | PowerShell tool that finds and decrypts saved session information for remote access tools. It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information                                   |
| Watson                                   | .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities                                                                                                       |
| LaZagne                                  | Tool used for retrieving passwords stored on a local machine from web browsers, chat tools, databases, Git, email, memory dumps, PHP, sysadmin tools, wireless network configurations, internal Windows password storage mechanisms, and more |
| Windows Exploit Suggester - Next Generation (WES-NG) | Tool based on the output of Windows' systeminfo utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported |
| Sysinternals Suite                       | Includes tools like AccessChk, PipeList, and PsService for enumeration                                                                                                                                           |

Solitamente e' sempre conveniente scrivere i file in `C:\Windows\Temp` perche' abbiamo permessi di scrittura.


# Situational Awareness

We should always look at routing tables to view information about the local network and networks around it. We can also gather information about the local domain (if the host is part of an Active Directory environment), including the IP addresses of domain controllers. It is also important to use the arp command to view the ARP cache for each interface and view other hosts the host has recently communicated with. This could help us with lateral movement after obtaining credentials. It could be a good indication of which hosts administrators are connecting to via RDP or WinRM from this host.

`C:\htb> ipconfig /all`

`C:\htb> arp -a`

`C:\htb> route print` routing table

`PS C:\htb> Get-MpComputerStatus`

`PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections` list applocker rules
`PS C:\htb> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone`

# Initial Enumeration

## Key points
- **OS Name** and **Version** sono utili per capire cosa dobbiamo cercare e se ci sono exploit pubblici.
- **Running Services**. E' importante vedere quali servizi runnano, soprattutto runnati da local administrator o NT AUTHORITY/SYSTEM.

## System Information
`C:\htb> tasklist /svc`, tasklist ritorna i processi in esecuzione.
E' importante diventare familiari con i processi standard di windows come SMSS.exe, CSRSS.exe, winlogon.exe LSASS.exe e svchost.exe. e' importante perche'
cosi' potremo spottare subito processi non standard e potenzialmente vulnerabili.

## Display ALl Environment Variables
il comando **set** per printarle.
La variabile piu' comune da vedere e' **PATH**, e molto spesso gli amministratori la modificano.

`C:\htb> set`, lista tutte le variabili d' ambiente.

## Detailed Configuration Information
il comando **systeminfo** mostra se la box e' stata patchata di recente. se non lo e' stata potremmo semplicemente runnare un known exploit.
Google the KBs installed under HotFixes to get an idea of when the box has been patched. 
The System Boot Time and OS Version can also be checked to get an idea of the patch level.

`C:\htb> systeminfo`

## Patches and Updates
Se systeminfo non mostra gli hotfixes possiamo vederli con **WMI**

`C:\htb> wmic qfe` mostra le laetst patch

`PS C:\htb> Get-HotFix | ft -AutoSize` anche questo

## Installed Programs
WMI si puo' usare anche per vedere i software installati
`C:\htb> wmic product get name`
`PS C:\htb> Get-WmiObject -Class Win32_Product |  select Name, Version`, con powershell

## Display Running Processes
`PS C:\htb> netstat -ano`

## User & Group information
### Logged-In Users
`C:\htb> query user`, per vedere gli utenti.
### Current User
`C:\htb> echo %USERNAME%`

### Current User Privileges
`C:\htb> whoami /priv`

### Current User Group Information
`C:\htb> whoami /groups`

### Get All Users
`C:\htb> net user`

### Get All Groups
`C:\htb> net localgroup`

### Deatils about a specific group
`C:\htb> net localgroup administrators`

### Password Policy and Other account info
`C:\htb> net accounts`




