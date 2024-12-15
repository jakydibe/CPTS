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