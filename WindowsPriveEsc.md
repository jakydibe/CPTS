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


# Communication With Processes
Uno dei posti migliori per privesc e' guardare i processi che runnano nel sistema. Anche se non stanno runnando da amminstratore possono portare a privesc
tipo se si exploita un servizio con SeImpersonateToken.

## Access Tokens
Gli access token sono usati per descrivere il security context (attributi di sicurezza di un process o thread).
Il token include informazioni sull' identita' dell' utente e i privilegi specifici di quel processo o thread.
Quando un utente si autentica la password viene verificata contro un database, e se si autentica gli viene assegnato un access token. Ogni volta che l'utente interagisce con un process una copia di quel token viene presentata ed associata al processo.

## Enumerating Network Services

Il metodo piu' comune per interagire con i processi e' tramite network socket (DNS,HTTP,SMB etc.etc.). **netstat** mostra le connessioni TCP e UDP attive.
Potremmo trovare servizi vulnerabili.

`C:\htb> netstat -ano`.

La cosa principale da guardare sono le entry che ascoltano nei loopback addresses (**127.0.0.1** e **::\1**) che non stanno ascoltando sull' indirizzo IP della rete o sul broadcast(0.0.0.0, ::/0).
Spesso queste cose sono insicure perche' non sono accessibili dalla rete.

**Splunk Universal Forwarder** esempio di privesc.

**Erlang Port (25672)** porta spesso usata come vettore di privesc. 

## Named Pipes
Un altro modo in cui i processi comunicano tra loro sono le **Named Pipes**. Essenzialmente sono file storati in memoria che vengono ripuliti dopo essere stati letti.

Cobalt strike usa Named Piped per ogni comando. spesso pero' si usa la named pipe di un altro processo per mascherarsi.

ci sono due tipi di Pipe: **Named** e **Anonymous piped**.

Named pipes can communicate using half-duplex, or a one-way channel with the client only being able to write data to the server, or duplex, which is a two-way communication channel that allows the client to write data over the pipe, and the server to respond back with data over that pipe.

`C:\htb> pipelist.exe /accepteula` per listare le istance di Named Pipes, Pipelist e' della sysinternal suite

`PS C:\htb>  gci \\.\pipe\` con powershell.

After obtaining a listing of named pipes, we can use Accesschk to enumerate the permissions assigned to a specific named pipe by reviewing the Discretionary Access List (DACL), which shows us who has the permissions to modify, write, read, or execute a resource. Let's take a look at the LSASS process. We can also review the DACLs of all named pipes using the command .\accesschk.exe /accepteula \pipe\.

accesschk.exe /accepteula \pipe\.

`C:\htb> accesschk.exe /accepteula \\.\Pipe\lsass -v`

## Named Pipes Attack Example
Usando **accesschk** possiamo cercare tutte le named piped che ci danno permessi di scrittura

`accesschk.exe -w \pipe\* -v` comando per vedere le pipes con permessi di scrittura
