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
dirmessage_enable=YES	Show a message when they first enter a new directory?
chown_uploads=YES	Change ownership of anonymously uploaded files?
chown_username=username	User who is given ownership of anonymously uploaded files.
local_enable=YES	Enable local users to login?
chroot_local_user=YES	Place local users into their home directory?
chroot_list_enable=YES	Use a list of local users that will be placed in their home directory?
hide_ids=YES	All user and group information in directory listings will be displayed as "ftp".
ls_recurse_enable=YES	Allows the use of recurse listings.

## Recursive Listing
con il comando `ls -R` possiamo listare ricorsivamente la directory
