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

