# Footprinting
RIGUARDARE BENE SEZIONE DNS. TROPPO NOIOSA NON CI HO CAPITO MOLTO.
Rileggere SMTP

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
dopo NFSv4 l'utente si deve autenticare e si usa solo la porta 2049.

NFS e' basato su Open Network Computing Remote Procedure Call (ONC-RPC/SUN-RPC) protocol. che gira su porta TCP e UDP 111, e usa la External Data Representation (XDR) per scambio di dati.
Di base NFS non ha meccaniscmi di autenticazione o autorizzazione, l' autenticazione e; spostata al protoccolo RPC.
L' autenticazione piu' comunie e' tramite UNIX UID/GID e group memberships. tuttavia il client e il server potrebbero non avere lo stesos mapping di UID/GID.

## Default configuration
`/etc/exports` contiene una tabella del filesystem fisico in un server NFS e che e' accessibile ai client.
|Option|	Description|
|-------|------------|
rw|	Read and write permissions.
ro|	Read only permissions.
sync|	Synchronous data transfer. (A bit slower)
async|	Asynchronous data transfer. (A bit faster)
secure|	Ports above 1024 will not be used.
insecure|	Ports above 1024 will be used.
no_subtree_check|	This option disables the checking of subdirectory trees.
root_squash|	Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents root from accessing files on an NFS mount.

il  comando `exportfs` fa vedere le directory exportate.

## Dangerous Settings
|Option|	Description|
|-------|------------|
rw|	Read and write permissions.
insecure|	Ports above 1024 will be used.
nohide|	If another file system was mounted below an exported directory, this directory is exported by its own exports entry.
no_root_squash|	All files created by root are kept with the UID/GID 0.

Insecure e' pericolosa perche' le porte sotto 1024 richiedono permessi da root, quindi se invece possiamo usare porte piu' di 1024 gli user possono usare sockets.

## Footprinting the service

con nmap facciamo scan a porte **111,2049** con `-sV` e `-sC`.
lo script nmap `rpcinfo` prende una ista di RPC services con nomi e descrizioni.

`j4k1dibe@htb[/htb]$ sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049` runno script di nmap per enumerare NFS.
`j4k1dibe@htb[/htb]$ showmount -e 10.129.14.128` per mostrare le exports.

una volta scoperto un servizio NFS possiamo montarlo in locale.
```
j4k1dibe@htb[/htb]$ mkdir target-NFS
j4k1dibe@htb[/htb]$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
j4k1dibe@htb[/htb]$ cd target-NFS
j4k1dibe@htb[/htb]$ tree .
```
dopo li possiamo vedere come fie locali quindi `ls -l` e `ls -n` per vedere UID e GUIDs

**Si puo' usare NFS per fare escalation** ad esempio quando abbiamo accesso SSH ad una macchina e vogliamo leggere file da un' altra cartella che uno specifico utente puo' leggere. avremo bisogno di uploadare una shell nella NFS share che ha il SUID di quell' utente e runnare la shell tramite utente SSH.

`sudo umoung ./target-NFS` per eliminare la share

# DNS
Domain Name System, e' il sistema di risoluzione di nomi in indirizzi IP.
Tipi di Server DNS:

|Server Type|	Description|
|-------|------------|
DNS Root Server|	The root servers of the DNS are responsible for the top-level domains (TLD). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The Internet Corporation for Assigned Names and Numbers (ICANN) coordinates the work of the root name servers. There are 13 such root servers around the globe.
Authoritative Nameserver|	Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point.
Non-authoritative Nameserver|	Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying.
Caching DNS Server|	Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage.
Forwarding Server|	Forwarding servers perform only one function: they forward DNS queries to another DNS server.
Resolver|	Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.

DNS e' principalmente non criptato, quindi dispositivi in WLAN possono spiare le DNS queries.
Quindi si sono inventati DNS over TLS(DoT) e DNS over HTTPS(DoH) e DNSCrypt.

I serve DNS ovviamente storano anche altri dati oltre alla risoluzione di indirizzi.


|DNS Record|	Description|
|-------|------------|
A|	Returns an IPv4 address of the requested domain as a result.
AAAA|	Returns an IPv6 address of the requested domain.
MX|	Returns the responsible mail servers as a result.
NS|	Returns the DNS servers (nameservers) of the domain.
TXT|	This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam.
CNAME|	This record serves as an alias for another domain name. If you want the domain www.hackthebox.eu to point to the same IP as hackthebox.eu, you would create an A record for hackthebox.eu and a CNAME record for www.hackthebox.eu.
PTR|	The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.
SOA|	Provides information about the corresponding DNS zone and email address of the administrative contact.

## Default Configuration
I server DNS funzionano con 3 tipi di file di configurazione diversi:
- Local DNS configuration files
- Zone files
- Reverse name resolution files
Il DNS principalmente usato in Linux e' **Bind9**. il suo file di configurazione si chiama **named.conf**.
i file di configurazione locale:
- named.conf.local
- named.conf.options
- namd.conf.log

```
root@bind9:~# cat /etc/bind/named.conf.local

//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";
zone "domain.com" {
    type master;
    file "/etc/bind/db.domain.com";
    allow-update { key rndc-key; };
};
```
qui definiamo le diverse zone. le zone sono divise in singoli file.
Un file di zona **zone file** e' un file di testo che descrive una zona DNS. il formato file **BIND** e' il preferito dall' industria.
Un file di zona descrive completamente una zona. DEVE esserci precisamente un record **SOA** e almeno un record **NS**.
un errore di sintasis rende tutto il file non utilizzabile.

Affinche l' indirizzo IP sia risolto in un **Fully Qualified Domain Name (FQDN)**. il server DNS deve avere un **reverse lookup file**.
In questo file il nome del computer (FQDN) e' assegnato all' ultimo ottetto dell' indirizzo IP, che corrisponde al rispettivo host usando il record PTR.

## Dangerous Settings
Ci potrebbero essere alcuni vettori di attacco tipo CVE su BIND9.

|Option|	Description|
|-------|------------|
allow-query|	Defines which hosts are allowed to send requests to the DNS server.
allow-recursion|	Defines which hosts are allowed to send recursive requests to the DNS server.
allow-transfer|	Defines which hosts are allowed to receive zone transfers from the DNS server.
zone-statistics|	Collects statistical data of zones.

## Footprinting the Service
Il server DNS puo' essere richiesto come gli altri domain name, usando il record **NS**.
`j4k1dibe@htb[/htb]$ dig ns inlanefreight.htb @10.129.14.128` prendiamo il record NS.

`j4k1dibe@htb[/htb]$ dig CH TXT version.bind 10.129.120.85` prendere la versione del server DNS. potrebbe non esistere questo record.
`j4k1dibe@htb[/htb]$ dig any inlanefreight.htb @10.129.14.128` per stampare tutti i record disponibili.

Uno **Zone Transfer** e' il trasferimento di zone ad un altro server DNS, tipicamente avviene sopra porta TCP 53.
Questa procedure e' abbreviata **Asynchronous Full Transfer Zone(AXFR)**. 
Se si hanno piu' server DNS  lo zone file di uno andrebbe tenuto identico in altri server per ridondanza e resistenza ai fallimenti.
La sincronizzazione (per tenere questi file aggiornati in entrambi i server) e' fatta dalla Zone transfer usando una chiave segreta**rdnc-key**.
I dati originali di una zona sono sul server DNS che e' il **primary** domain name server per quella zona.
Per incrementare affidabilita'/load distirbution si installano i server **secondary** name server per una zona.
TLD(Top level domains) avranno pure i Second Level Domain.
`j4k1dibe@htb[/htb]$ dig axfr inlanefreight.htb @10.129.14.128` AXFR Zone transfer
`j4k1dibe@htb[/htb]$ dig axfr internal.inlanefreight.htb @10.129.14.128` AXFR Zone Transfer - Internal, si puo' queriare se c'e' **allow-transfer**.

## Subdomain Brute Forcing
Si puo' fare con alcuni tool tipo gobuster o ffuf ma anche in bash
`for sub in $(cat /home/kali/roba/kali-wordlists/amass/subdomains-top1mil-110000.txt);do dig $sub.inlanefreight.htb @10.129.171.45
 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done`.

con **DNSenum**
`j4k1dibe@htb[/htb]$ dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb`.

 # SMTP
Simple Mail Transfer Protocol e' un protocollo per mandare email in una rete IP.
Si puo' usare tra un email client e un outgoing mail server o tra server SMTP.
Si usa combinato con IMAP o POP3 che possono fetchare e mandare email.
Di default accetta connessioni su porta **25** ma server nuovi usano anche porta TCP **587** per ricevere mail da utenti/server autenticati usando il comando **STARTTLS** per switchare connessione plaintext in criptata.

SMTP lavora non criptato e manda tutto in plaintext. per prevenire si usa insieme a SSL/TLS, in questi casi si usano porte diverse.

Una funzione importante dei server SMTP e' prevenire SPAM usando autenticazione.
Lo fa con estensione  **ESMTP** del protocollo con SMTP-Auth. dopo mandare le mail il **Mail User Agent (MUA)** client SMTP converte in un header e body e manda al server SMTP.
Il server avra' un **Mail Transfer Agent(MTA)** il software per mandare/ricever email, lui checka per lo spam.
A volte c'e' pure il **Mail Submission Agent(MSA)**, per togliere carico al MTA.
I MTA sono anche detti **Relay** server e si puo' fare un attacco chiamato **Open Relay Attack** a causa di alcune 

Quando arriva al server SMTP di destinazione viene riformata l'email originale e il **Mail Delivery Agent(MDA)** lo trasferisce al mailbox.
**POP3/IMAP ---> MailBox**

Problemi:
- SMTP non ritorna conferma di ricezione della mail.
- Quando si fa una connessione gli utenti non sono autenticati
- 
identification protocol DomainKeys (DKIM), the Sender Policy Framework (SPF).

**ESMTP** e' l' estensione di SMTP con TLS 

## Default configuration
si trova in `/etc/postfix/main.cf`

|Command|	Description|
|------|-----------|
AUTH PLAIN|	AUTH is a service extension used to authenticate the client.
HELO|	The client logs in with its computer name and thus starts the session.
MAIL FROM|	The client names the email sender.
RCPT TO|	The client names the email recipient.
DATA|	The client initiates the transmission of the email.
RSET|	The client aborts the initiated transmission but keeps the connection between client and server.
VRFY|	The client checks if a mailbox is available for message transfer.
EXPN|	The client also checks if a mailbox is available for messaging with this command.
NOOP|	The client requests a response from the server to prevent disconnection due to time-out.
QUIT|	The client terminates the session.

Per interagire con il server SMTP possiamo usare il tool **telnet**  a porta 25 e mandando il comando **HELO** o **EHLO**.

comando **VRFY <user>** si puo' usare per enumerate utenti esistenti nel sistema.
Non funziona sempre, dipende dalla configurazione. se il server SMTP ritorna **codice 252** conferma la NON esistenza dell' utente.

## Send an Email
- Prima mando **HELO/EHLO <mailserver>**
- ```
MAIL FROM: <cry0l1t3@inlanefreight.htb>

250 2.1.0 Ok


RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure

250 2.1.5 Ok


DATA

354 End data with <CR><LF>.<CR><LF>

From: <cry0l1t3@inlanefreight.htb>
To: <mrb3n@inlanefreight.htb>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work. 
Did you make any changes there?
.

250 2.0.0 Ok: queued as 6E1CF1681AB


QUIT

221 2.0.0 Bye
Connection closed by foreign host.```

## Dangerous settings
Per prevenire che la mail sia presa dai filtri antispam il sender puo' usare un relay server che e' trustato dal recipiente.

### Open Relay Configuration
`mynetworks = 0.0.0.0/0`, conq questo setting il server SMTP puo' mandare email false e inizializzare comunicazione tra piu' parti. inoltre puo' spoofare le mail e leggerle.

## Footprinting the service
con nmap `smtp-commands` possiamo listare i comandi che possiamo eseguire sul server SMTP.
con nmap `smtp-open-relay` script possiamo verificare serve con un open relay.
con nmap 'smtp-enum-users' si possono enumerare gli utenti.


# IMAP/POP3
## IMAP (Internet Message Access Protocol): 
è un protocollo usato per accedere ai messaggi di posta elettronica direttamente sul server, senza scaricarli localmente. Questo significa che i messaggi rimangono sul server e sono sincronizzati tra tutti i dispositivi. Con IMAP:

- Puoi visualizzare e gestire la posta da diversi dispositivi.
- I messaggi rimangono sul server a meno che non vengano cancellati manualmente.
- Le cartelle e la struttura della casella postale sono sincronizzate tra i dispositivi.
## POP3 (Post Office Protocol 3):
è un protocollo che scarica i messaggi dal server sul dispositivo locale e, per impostazione predefinita, li rimuove dal server. Questo significa che:

- La posta non è sincronizzata tra dispositivi diversi.
- Dopo il download, i messaggi restano solo sul dispositivo da cui è stato effettuato il download (salvo configurazioni diverse).
- POP3 è utile se si desidera gestire la posta offline o se si ha poco spazio sul server.
**SMTP (Simple Mail Transfer Protocol)** invece è il protocollo utilizzato per inviare messaggi di posta elettronica. Mentre IMAP e POP3 sono protocolli usati per ricevere la posta, SMTP è usato esclusivamente per l'invio. Con SMTP:

Il client invia i messaggi al server di posta in uscita (SMTP) per la consegna.
Il server SMTP del provider si occupa di consegnare il messaggio alla casella di posta del destinatario.


## Comandi IMAP
|Command|	Description|
|-------|------------|
1 LOGIN username password|	User's login.
1 LIST "" *|	Lists all directories.
1 CREATE "INBOX"|	Creates a mailbox with a specified name.
1 DELETE "INBOX"|	Deletes a mailbox.
1 RENAME "ToRead" "Important"|	Renames a mailbox.
1 LSUB "" *|	Returns a subset of names from the set of names that the User has declared as being active or subscribed.
1 SELECT INBOX|	Selects a mailbox so that messages in the mailbox can be accessed.
1 UNSELECT INBOX|	Exits the selected mailbox.
1 FETCH -ID- all|	Retrieves data associated with a message in the mailbox.
1 SEARCH all| Per vedere tutti gli ID dei messagig nella mailbox
1 FETCH -ID- BODY[TEXT]| per leggere il contenuto della mail
1 CLOSE|	Removes all messages with the Deleted flag set.
1 LOGOUT|	Closes the connection with the IMAP serv

## Comandi POP3
|Command|	Description|
|-------|------------|
USER username|	Identifies the user.
PASS password|	Authentication of the user using its password.
STAT|	Requests the number of saved emails from the server.
LIST|	Requests from the server the number and size of all emails.
RETR id|	Requests the server to deliver the requested email by ID.
DELE id|	Requests the server to delete the requested email by ID.
CAPA|	Requests the server to display the server capabilities.
RSET|	Requests the server to reset the transmitted information.
QUIT|	Closes the connection with the POP3 server.

## Dangerous settings
Di solito le aziende si affidano a servizi mail di 3e parti. tuttavia potrebbe capitare che alcune di loro hanno piccoli server mail

|Setting|	Description|
|-------|------------|
auth_debug|	Enables all authentication debug logging.
auth_debug_passwords|	This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.
auth_verbose|	Logs unsuccessful authentication attempts and their reasons.
auth_verbose_passwords|	Passwords used for authentication are logged and can also be truncated.
auth_anonymous_username|	This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism.

## Footprinting the Service
con nmap: `j4k1dibe@htb[/htb]$ sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC`.
di default:
- POP3 porta **100 e 995**, 995 SSL/TLS.
- IMAP porte **143 e 993**, 993 SSL/TLS.

con **cURL**: `j4k1dibe@htb[/htb]$ curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd -v`.

**OpenSSL per TLS POP3**: `j4k1dibe@htb[/htb]$ openssl s_client -connect 10.129.14.128:pop3s`.
**OpenSSL per TLS IMAP**: `j4k1dibe@htb[/htb]$ openssl s_client -connect 10.129.14.128:imaps`

# SNMP (Simple Network Management Protocol)
E' stato creato per gestire dispositivi di rete. E' usato per gestire configurazioni e cambiare settings a remoto.
Gestisce roba tipo router, switch, server, dispositivi IoT etc.etc..

La versione attuale e' **SNMPv3**.
Oltre allo scambio di informazioni SNMP trasmette comandi di controlllo ai suoi agenti sulle macchine tramite la porta **UDP 161**.
Principalmnte sono i client che tramite gli agenti comunicano con il server SNMP; Pero' SNMP ha pure abilitato l' uso delle **traps** che tramite porta **UDP 162**, il Server SNMP manda pacchetti al client senza che siano stati richiesti, solitamente vengono mandati quando uno specifico eventu in server-side accade.

## MIB
Per funzionare SNMP ha bisogno di un sistema di addressing tra client e server.
il MIB (Management Information Base) e' stato creato come formato per storare device informations. un MIB e' un text file dove Tutti i SNMP oggetti di un device sono listati in uno albero gerarchico standardizzato.
Contiene almeno un **Object Identifier (OID)** dove in aggiunt al necessario indirizzo e  nome, da anche informazioni sul tipo, diritti di accesso e descrizione del rispettivo oggetto.

I file MIB sono scritti nela **Abstract Syntax Notation One (ASN.1)** basato su formato testo ASCII. il MIB non contiene dati ma spiega DOVE trovar ele informazioni.

## OID
Un OID rappresenta un nodo in un namespace gerarchico. una sequenza di numeri che identifica univocamente un nodo.
Utile per determinare la posizione di un Nodo in un albero. Piu' lunga la catena, piu' specifiche le info.
Molti nodi OID contengon solo reference a quelli sotto di loro.
OID e' fatto da interi concatenati da notazione dot.

## SNMPv1
- Ancora molto usata in piccole reti.
- Non ha meccanismi di autenticazione built-in
- Non supporta encryption

## SNMPv2
Esiste ancora oggi in versione **v2c**. 'c' sta per community based.
Ancora no built in encryption

## SNMPv3 
E' stat aggiunta autenticazione e encrytpion con pre-shared key.

## Community Strings
Le community strings possono essere viste come password per determinare se le informazioni richieste possono essere viste o no.

## Default configuration
il file di conf sta in `/etc/snmp/snmpd.conf`.

## Dangerous Settings
|Settings|Description|
|--------|-----------|
rwuser noauth|	Provides access to the full OID tree without authentication.
rwcommunity -community string- -IPv4 address-|	Provides access to the full OID tree regardless of where the requests were sent from.
rwcommunity6 -community string- -IPv6 address-|	Same access as with rwcommunity with the difference of using IPv6.

## Footprinting The Service
tool:
- **snmpwalk**, per prendere gli OIDs e le loro info.
- **onesixtyone**, per brute-forzare i nomi delle community strings dato che possono essere specificati dagli admin
- **braa**, quando sappiamo la coomunity string possiamo bruteforzare i singoli OIDs e enumerare le info.


`j4k1dibe@htb[/htb]$ snmpwalk -v2c -c public 10.129.14.128`.

`snmp-check 10.129.129.84 -c public`. con snmp-check, uguale

`j4k1dibe@htb[/htb]$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128`.

`j4k1dibe@htb[/htb]$ braa <community string>@<IP>:.1.3.6.*`.

`j4k1dibe@htb[/htb]$ braa public@10.129.14.128:.1.3.6.*`

si puo' usare tool come **crunch** per creare custom wordlist**s

# MySQL
MySQL e' un DBMS opensource che supporta database relazionali con linugaggio SQL.

funziona con il proncipio di client-server. I database sono spesso salvati in un solo file **.sql**. ES: wordpress.sql.

**MySQL CLients** possono retrievare ed editare i dati usando query al database. Lo possono fare via rete interna o internet pubblico.

Un esempio e' WordPRess che tora tutto nel suo database, accessibile solo al localhost.

**MySQL Database** e' ideato per applicazioni come siti web dinamici dove l' efficienza e' importante.
Spesso MySQL e' combinato con Linux, PHP e server web APache. (**LAMP** Linux, Apache, MySQL,PHP) o con Nginx LEMP


## MySQL Commands
Spesso quando il database ritorna errori puo' dare informazioni molto importanti per verificare anche se c'e' una SQL Injection.

**MariaDB** e' una fort del MySQL originale, il creatore originale ha lasciato MySQL quando e' stato acquisito da Oracle.

## Default Configuration
il file di configurazione sta in : `/etc/mysqp/mysql.conf.d/mysqld.conf`.

## Dangerous Settings
|Settings|	Description|
|--------|-------------|
user|	Sets which user the MySQL service will run as.
password|	Sets the password for the MySQL user.
admin_address|	The IP address on which to listen for TCP/IP connections on the administrative network interface.
debug|	This variable indicates the current debugging settings
sql_warnings|	This variable controls whether single-row INSERT statements produce an information string if warnings occur.
secure_file_priv|	This variable is used to limit the effect of data import and export operations.

Attenzione che **user, password e admin_address sono entry messe in Plaintext**.

## Footprinting the service
Per molte ragioni il servizio puo' essere accessibile dall' esterno. Il server MySQL gira su porta **TCP 3306**.

con nmap: `sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*`. Potrebbe tornare alcuni falsi positivi comunque.

`j4k1dibe@htb[/htb]$ mysql -u root -h 10.129.14.132`. iteragire con Mysql

`j4k1dibe@htb[/htb]$ mysql --skip-ssl -u root -pP4SSw0rd -h 10.129.14.128`.

In MySQL i database piu' importanti sono **system schema (sys)** e **information schema (information_schemaa)**. system contiene tabelle e info necessarie per la gestione.
```
mysql> use sys;
mysql> show tables; 
```

## Comandi utili

|Command|	Description|
|-------|------------|
mysql --skip-ssl -u -user- -p-password- -h =IP address- |	Connect to the MySQL server. There should not be a space between the '-p' flag, and the password.
show databases;|	Show all databases.
use -database-;|	Select one of the existing databases.
show tables;|	Show all available tables in the selected database.
show columns from -table-;|	Show all columns in the selected database.
select * from \<table\>;|	Show everything in the desired table.
select * from \<table\> where <column> = "<string>"; | Search for needed string in the desired table.


# MSSQL
Microsoft SQL e' un DMBS per SQL fatto da microsoft.
MSSQL e' closed source. e' popolare tra sysadmin che fanno applicazioni in .NET.

## MSSQL Clients
SQL Server Management Studio (SSMS) e' una feature che si puo' installare insieme a MSSQL, serve a gestire il DB.

Ci sono vari client per MSSQL come : mssqli-cli, SQL Server Powershell, HeidiSQL, SQLPro, Impacket's mssqlclient.py(https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py).

## MSSQL databses
di default ci sono questi databasse:

|Default System Database	|Description|
|-------------------------|-----------|
master|	Tracks all system information for an SQL server instance
model|	Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database| created after changes to the model database
msdb|	The SQL Server Agent uses this database to schedule jobs & alerts
tempdb|	Stores temporary objects
resource|	Read-only database containing system objects included with SQL server

Il servizio SQL gira come utente **NT SERVICE\MSSQLSERVER**, e ci si puo' provare a connettere e di default non c'e' encryption.
L' autenticazione messa a **Windows Authentication** significa che il sistema windows processera' la richiesta di login usando il local SAM databae o il domain controller.

## Dangerous Settings

- MSSQL clients not using encryption to connect to the MSSQL server
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
- The use of named pipes
- Weak & default sa credentials. Admins may forget to disable this account

## Footprinting the service

Di default gire su porta **TCP 1443**.
con nmap: 

`sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248`.

con metasploit: 
`msf6 auxiliary(scanner/mssql/mssql_ping)`

connettersi con mssqlclient.py
`j4k1dibe@htb[/htb]$ python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth`



