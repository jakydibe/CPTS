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




