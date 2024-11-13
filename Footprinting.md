# Footprinting
## Domain informations
E' importante trovare la presenza in internet di un certo dominio.
Il primo punto di presenza potrebbe essere il **certificato SSL**. usa `crt.sh` per trovarli.

per printare il certificato in JSON
```
j4k1dibe@htb[/htb]$ curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .

[
  {
    "issuer_ca_id": 23451835427,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "matomo.inlanefreight.com",
    "name_value": "matomo.inlanefreight.com",
    "id": 50815783237226155,
    "entry_timestamp": "2021-08-21T06:00:17.173",
    "not_before": "2021-08-21T05:00:16",
    "not_after": "2021-11-19T05:00:15",
    "serial_number": "03abe9017d6de5eda90"
  },
  {
    "issuer_ca_id": 6864563267,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "matomo.inlanefreight.com",
    "name_value": "matomo.inlanefreight.com",
    "id": 5081529377,
    "entry_timestamp": "2021-08-21T06:00:16.932",
    "not_before": "2021-08-21T05:00:16",
    "not_after": "2021-11-19T05:00:15",
    "serial_number": "03abe90104e271c98a90"
  },
  {
    "issuer_ca_id": 113123452,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "smartfactory.inlanefreight.com",
    "name_value": "smartfactory.inlanefreight.com",
    "id": 4941235512141012357,
    "entry_timestamp": "2021-07-27T00:32:48.071",
    "not_before": "2021-07-26T23:32:47",
    "not_after": "2021-10-24T23:32:45",
    "serial_number": "044bac5fcc4d59329ecbbe9043dd9d5d0878"
  },
  { ... SNIP ...
```

### Company hosted servers
`j4k1dibe@htb[/htb]$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done`

**Shodan** si puo' usare per trovare dispositivi connessi a internet come dispositivi IoT. Cerca porte TCP/IP aperte. 
Cosi' potremmo trovare dispositivi come telecamere di sicurezza, server, smart home

```
j4k1dibe@htb[/htb]$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done
j4k1dibe@htb[/htb]$ for i in $(cat ip-addresses.txt);do shodan host $i;done
```
## DNS Records
`j4k1dibe@htb[/htb]$ dig any inlanefreight.com`
ricordiamoci che:
- **A** record sono quelli che rislvono domain name in IP.
- **MX** record sono quelli che mostrano il mail server.
- **NS** record sono quelli di risoluzione inversa. quindi risolvono IP in Domain name.
- **TXT** record contengono varie chiavi per provider di terze parti e roba di sicurezza per il DNS

# Cloud Resources
Oramai molte aziende usano servizi in cloud come Amazon AWS, Microsoft Azure etc.etc.

per trovare questi cloud storage ci sono molti modi:
## Google search per AWS e Azure
Possimao usare i google Dork come **inurl:** e **intext:** con intext: nome_compagnia e inurl:amazonaws.com.
Stessa roba per Azure ma inurl:blob.core.windows.net.
Potremmo trovare alcuni documenti contenuti nel cloud.

## Domain.glass
e' un sito dove gli passiamo un dominio e ci dice parecchia roba.

## GrayHatWarfare
Molto utile. a volte si riescono pure a trovare chiavi pubbliche e private SSH leakate 

## Linkeding job post

# FTP
Di base il client e il server stabiliscono un canale di comunicazione in porta 21 TCP per mandare comandi. invece quando bisogna passarsi data
si passa a porta 20 TCP.

In **Active Mode**, il client avvia la connessione dati inviando un comando PORT al server porta 21. Il problema e' che che se c'e' un firewall che protegge il client il server non puo' rispondere. 
Percio' hanno sviluppato lla **passive mode**, dove il server annuncia una porta dove il client deve stabilire il data channel e percio' il firewall non blocca.

**Anonymous FTP** e' un login di default sui server FTP in cui si logga con anonymous:anonymous.

## TFTP
Trivial File Transfer Protocol e' piu' semplice di FTP ma non c'e' nessuna autenticazione. 
In piu' TFTP usa UDP quindi non e' assicurato.

comandi TFTP:
|Commands|	Description|
|--------|-------------|
|connect|	Sets the remote host, and optionally the port, for file transfers.|
|get|	Transfers a file or set of files from the remote host to the local host.|
|put|	Transfers a file or set of files from the local host onto the remote host.|
|quit|	Exits tftp.|
|status|	Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on.|
|verbose|	Turns verbose mode, which displays additional information during file transfer, on or off.|


## Default configurations
Il server FTP piu' usato Linux-based e' **vsFTPd**. la configurazione di default e' in `/etc/vsftpd.conf`.
`/etc/ftpusers` e' un file usato per negare l' accesso FTP a certi utenti.

|Settings|	Description|
|--------|-------------|
|listen=NO|	Run from inetd or as a standalone daemon?|
|listen_ipv6=YES|	Listen on IPv6 ?|
|anonymous_enable=NO|	Enable Anonymous access?|
|local_enable=YES|	Allow local users to login?|
|dirmessage_enable=YES|	Display active directory messages when users go into certain directories?|
|use_localtime=YES|	Use local time?|
|xferlog_enable=YES|	Activate logging of uploads/downloads?|
|connect_from_port_20=YES|	Connect from port 20?|
|secure_chroot_dir=/var/run/vsftpd/empty|	Name of an empty directory|
|pam_service_name=vsftpd|	This string is the name of the PAM service vsftpd will use.|
|rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem|	The last three options specify the location of the RSA certificate to use for SSL encrypted connections.|
|rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key||
|ssl_enable=NO||


## Settings Pericolose
|Settings|	Description|
|--------|-------------|
|anonymous_enable=YES|	Allowing anonymous login?|
|anon_upload_enable=YES|	Allowing anonymous to upload files?|
|anon_mkdir_write_enable=YES|	Allowing anonymous to create new directories?|
|no_anon_password=YES|	Do not ask anonymous for password?|
|anon_root=/home/username/ftp|	Directory for anonymous.|
|write_enable=YES|	Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE?|

## vsFTPD Detailed Output
usare i comandi `debug`, `trace` e `status` per avere output piu' dettagliati nella sessione FTP.y

|Settings|	Description|
|--------|-------------|
dirmessage_enable=YES|	Show a message when they first enter a new directory?
chown_uploads=YES|	Change ownership of anonymously uploaded files?
chown_username=username|	User who is given ownership of anonymously uploaded files.
local_enable=YES|	Enable local users to login?
chroot_local_user=YES|	Place local users into their home directory?
chroot_list_enable=YES|	Use a list of local users that will be placed in their home directory?
hide_ids=YES|	All user and group information in directory listings will be displayed as "ftp".
ls_recurse_enable=YES|	Allows the use of recurse listings.

## Recursive Listing
con il comando `ls -R` possiamo listare ricorsivamente la directory

## comandi base ftp
`get` per scaricare file in locale.
`put` per uploadare file.

## Scarica tutti i file available
`j4k1dibe@htb[/htb]$ wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136`

## Footprinting di FTP
Possiamo usare anche Nmap NSE con gli script per FTP.
prima aggiorniamo il db di scripts: `sudo nmap --script-updatedb`.
gli script stanno in `/usr/share/nmap/scripts/`
per trovarli usiamo questo comando: `j4k1dibe@htb[/htb]$ find / -type f -name ftp* 2>/dev/null | grep scripts`
per tracciare gli script aggiungiamo la flag `--script-trace` di nmap.

## Service interaction
Possiamo interagire con FTP anche con altri client quali **netcat** e **telnet** e **openssl**.
`nc -nv IP PORT`.
`telnet IP PORT`.
`j4k1dibe@htb[/htb]$ openssl s_client -connect 10.129.14.136:21 -starttls ftp`. questo perche; il certificato SSL ci fa riconoscere l' hostname e email address della compagnia.


# SMB
SMB e' un protocollo TCP client-server che regola l' accesso a file e directory e risorse di rete tipo stampanti, router etc.etc.
Lo scambio di informazioni e dati si puo' fare tramite protocollo SMB che e' anche di default nelle macchine Windows.

Un server SMB puo' dare parti arbitrarie del suo file system locale come **shares** visibili ai client. 
GLi Access right sono definiti da **Access Control Lists (ACL)**.

## Samba
Samba (SMB/CIFS)e' un' implementazione alternativa del Server SMB ed e' sviluppata per sistemi Unix-baseed. 
Samba implementa il **Common Internet File SYstem(CIFS)**, che e' un dialetto di SMB. Questo permette a Samba di comunicare con sistemi windows moderni.

In una rete ogni host partecipa nello stesso **workgroup**. Un **Workgroup** e' un gruppo  che indetnficia una collezione di computer e le loro risorse in una rete SMB. Ci possono essere piu' workhroup sulla rete.
IBM ha fatto un API per connettere computer e si chiama **Network Basic Input/Output System (NetBIOS)**.
La NetBIOS api permette ai pc in LAN di scambairsi dati e altra roba. In NetBIOS ogni PC della rete ha un nome univoco (invece degli IP),
l' assegnazione del nome avviene tramite la **name registration procedure**; ogni host ha il suo hostname nella rete e il **NetBIOS Name Server (NBNS) e'si occupa di gesitre questo**. Adesso c'e' pure il **WIndows Internet Name Server (WINS)**.

## Default Configuration
`/etc/samba/smb.conf` e' dove si trova la conf.
`cat /etc/samba/smb.conf | grep -v "#\|\;" `

|Setting|	Description|
|-------|------------|
[sharename]|	The name of the network share.
workgroup = WORKGROUP/DOMAIN|	Workgroup that will appear when clients query.
path = /path/here/|	The directory to which user is to be given access.
server string = STRING|	The string that will show up when a connection is initiated.
unix password sync = yes|	Synchronize the UNIX password with the SMB password?
usershare allow guests = yes|	Allow non-authenticated users to access defined share?
map to guest = bad user|	What to do when a user login request doesn't match a valid UNIX user?
browseable = yes|	Should this share be shown in the list of available shares?
guest ok = yes|	Allow connecting to the service without using a password?
read only = yes|	Allow users to read files only?
create mask = 0700|	What permissions need to be set for newly created files?

## Dangerous Settings

|Setting|	Description|
|-------|------------|
browseable = yes|	Allow listing available shares in the current share?
read only = no|	Forbid the creation and modification of files?
writable = yes|	Allow users to create and modify files?
guest ok = yes|	Allow connecting to the service without using a password?
enable privileges = yes|	Honor privileges assigned to specific SID?
create mask = 0777|	What permissions must be assigned to the newly created files?
directory mask = 0777|	What permissions must be assigned to the newly created directories?
logon script = script.sh|	What script needs to be executed on the user's login?
magic script = script.sh|	Which script should be executed when the script gets closed?
magic output = script.out|	Where the output of the magic script needs to be stored?

## SMBclient, connettersi alle shares
`j4k1dibe@htb[/htb]$ smbclient -N -L //10.129.14.128` enumerare e shares.
le share print$ e IPC$ sono di default nei basic settings.
`j4k1dibe@htb[/htb]$ smbclient //10.129.14.128/notes` loggare in una share
`!<cmd\>` si usa per eseguire local system commands. tipo `!ls`.
Scaricare e uploadare sempre `get` e `put`.

## Footprinting the service

con nmap possiamo fare la scan alle porte **139 e 445**.

### RPCclient
e' un tool per eseguire funzioni MS-RPC. (chiama una funzione su un server remoto).
`j4k1dibe@htb[/htb]$ rpcclient -U "" 10.129.14.128`. Questo per connettersi. dopo possiamo fare le richieste
il comando rpcclient ci da molte richieste che possiamo fare al sever SMB

eccone alcune:
|Query|	Description|
|-------|------------|
srvinfo|	Server information.
enumdomains|	Enumerate all domains that are deployed in the network.
querydominfo|	Provides domain, server, and user information of deployed domains.
netshareenumall|	Enumerates all available shares.
netsharegetinfo <share>|	Provides information about a specific share.
enumdomusers|	Enumerates all domain users.
queryuser <RID>|	Provides information about a specific user.
querygroup <group_RID>| Provide info about a specifi group

## Bruteforcing User RIDs con RPCclient
`j4k1dibe@htb[/htb]$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`
in alternativa si puo' usare un  python script d **Impacket** chiamato **samrdump.py**: `j4k1dibe@htb[/htb]$ samrdump.py 10.129.14.128`.

## Altri tools
Queste enumerazioni si possono fare anche con altri tools
### SMBmap
`j4k1dibe@htb[/htb]$ smbmap -H 10.129.14.128`

### CrackMapExec
`j4k1dibe@htb[/htb]$ crackmapexec smb 10.129.14.128 --shares -u '' -p ''`
### Enum4linux
`j4k1dibe@htb[/htb]$ ./enum4linux-ng.py 10.129.14.128 -A`


# NFS
Network File System e' un network filesystem che ha lo stesso scopo di SMB, ovvero accedere a file su una rete come se fossero locali.
Pero' usa un protocollo completamente diverso. si usa tra sistemi Linux e Unix, quindi non puo' comunicare direttamente con SMB servers.
dopo NFSv4 l'utente si deve autenticare
