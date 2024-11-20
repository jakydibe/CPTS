# WHOIS

WHOIS e' un protocollo di query and response usato per accedere a database che storano informazioni su risorse internet registrate.

WHOIS puo' dare dettagli su blocchi di indirizzi IP e Autonomous Systems. una sorta di gigante Pagine Gialle.

Each WHOIS record typically contains the following information:
- Domain Name: The domain name itself (e.g., example.com)
- Registrar: The company where the domain was registered (e.g., GoDaddy, Namecheap)
- Registrant Contact: The person or organization that registered the domain.
- Registration Dates
- Takedown History
- Administrative Contact: The person responsible for managing the domain.
- Technical Contact: The person handling technical issues related to the domain.
- Creation and Expiration Dates: When the domain was registered and when it's set to expire.
- Name Servers: Servers that translate the domain name into an IP address.

Usare whois e' facile: `whois domain.com`.


# DNS
Domain Name System.

Funzionamento di una query per un sito web:
  1) Prima il tuo pc controlla se ha in memoria/cache per vedere se gia' sa' l' IP. Se non ce l;ha contatta un **DNS Resolver**, tipicamente gestito dal tuo ISP.
  2) Il DNS Resolver controlla la sua memoria/cache per vedere se ce l'ha, e se non lo trova inizia a chiamare ricorsivamente in gerarchia di DNS. inizia facendo una query ad un **root name server**
  3) Il root name server non sa a chi corrisponde ma sa quale server DNS lo sa. Perche' si rivolge ai **Top Level Domain(TLD)** DNS servers, responsabili per i domini (es. .com, .it, .org etc.etc.).
  4) Il DNS TLD sa chi e' autoritativo di quel dominio e punta li'
  5) Il server Autoritativo rimanda al resolver del nostro ISP che lo ritornera' a noi.


 ## Il file Hosts

 Sia in windows (`C:\Windows\System32\drivers\etc\hosts`) che in Linux (`/etc/hosts`) c'e' un file che ci mappa hostname a indirizzi IP.

 ## Concetti importanti 
 Una **Zona** e' una sorta di container per domini che ne contiene varie informazioni come il Name server NS, il Mail server MX, l' IP A per vari host all' interno di un dominio come ad esempio example.com (ns1.example.com, ns1.example.com etc.etc.).
 
|DNS Concept|	Description|	Example|
|-----------|------------|---------|
Domain Name|	A human-readable label for a website or other internet resource.|	www.example.com
IP Address|	A unique numerical identifier assigned to each device connected to the internet.	|192.0.2.1
DNS Resolver|	A server that translates domain names into IP addresses.|	Your ISP's DNS server or public resolvers like Google DNS (8.8.8.8)
Root Name Server|	The top-level servers in the DNS hierarchy.|	There are 13 root servers worldwide, named A-M: a.root-servers.net
TLD Name Server|	Servers responsible for specific top-level domains (e.g., .com, .org).|	Verisign for .com, PIR for .org
Authoritative Name Server|	The server that holds the actual IP address for a domain.|	Often managed by hosting providers or domain registrars.
DNS Record| Types	Different types of information stored in DNS.|	A, AAAA, CNAME, MX, NS, TXT, etc.


| Record Type | Full Name                 | Description                                                                 | Zone File Example                                                              |
|-------------|---------------------------|-----------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| A           | Address Record           | Maps a hostname to its IPv4 address.                                       | `www.example.com. IN A 192.0.2.1`                                             |
| AAAA        | IPv6 Address Record      | Maps a hostname to its IPv6 address.                                       | `www.example.com. IN AAAA 2001:db8:85a3::8a2e:370:7334`                       |
| CNAME       | Canonical Name Record    | Creates an alias for a hostname, pointing it to another hostname.          | `blog.example.com. IN CNAME webserver.example.net.`                           |
| MX          | Mail Exchange Record     | Specifies the mail server(s) responsible for handling email for the domain.| `example.com. IN MX 10 mail.example.com.`                                     |
| NS          | Name Server Record       | Delegates a DNS zone to a specific authoritative name server.              | `example.com. IN NS ns1.example.com.`                                         |
| TXT         | Text Record              | Stores arbitrary text information, often used for domain verification or security policies. | `example.com. IN TXT "v=spf1 mx -all"` (SPF record)               |
| SOA         | Start of Authority Record| Specifies administrative information about a DNS zone, including the primary name server, responsible person's email, and other parameters. | `example.com. IN SOA ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400` |
| SRV         | Service Record           | Defines the hostname and port number for specific services.                | `_sip._udp.example.com. IN SRV 10 5 5060 sipserver.example.com.`              |
| PTR         | Pointer Record           | Used for reverse DNS lookups, mapping an IP address to a hostname.         | `1.2.0.192.in-addr.arpa. IN PTR www.example.com.`                              |



## Why DNS Matters for Web Recon
DNS is not merely a technical protocol for translating domain names; it's a critical component of a target's infrastructure that can be leveraged to uncover vulnerabilities and gain access during a penetration test:

Uncovering Assets: DNS records can reveal a wealth of information, including subdomains, mail servers, and name server records. For instance, a CNAME record pointing to an outdated server (dev.example.com CNAME oldserver.example.net) could lead to a vulnerable system.
Mapping the Network Infrastructure: You can create a comprehensive map of the target's network infrastructure by analysing DNS data. For example, identifying the name servers (NS records) for a domain can reveal the hosting provider used, while an A record for loadbalancer.example.com can pinpoint a load balancer. This helps you understand how different systems are connected, identify traffic flow, and pinpoint potential choke points or weaknesses that could be exploited during a penetration test.
Monitoring for Changes: Continuously monitoring DNS records can reveal changes in the target's infrastructure over time. For example, the sudden appearance of a new subdomain (vpn.example.com) might indicate a new entry point into the network, while a TXT record containing a value like _1password=... strongly suggests the organization is using 1Password, which could be leveraged for social engineering attacks or targeted phishing campaigns.


# Digging DNS

## Comandi per queryare DNS
| Tool                     | Key Features                                                                 | Use Cases                                                                                                   |
|---------------------------|-----------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| `dig`                    | Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output. | Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records. |
| `nslookup`               | Simpler DNS lookup tool, primarily for A, AAAA, and MX records.             | Basic DNS queries, quick checks of domain resolution and mail server records.                              |
| `host`                   | Streamlined DNS lookup tool with concise output.                           | Quick checks of A, AAAA, and MX records.                                                                   |
| `dnsenum`                | Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed). | Discovering subdomains and gathering DNS information efficiently.                                          |
| `fierce`                 | DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection. | User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets.              |
| `dnsrecon`               | Combines multiple DNS reconnaissance techniques and supports various output formats. | Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis.     |
| `theHarvester`           | OSINT tool that gathers information from various sources, including DNS records (email addresses). | Collecting email addresses, employee information, and other data associated with a domain from multiple sources. |
| Online DNS Lookup Services | User-friendly interfaces for performing DNS lookups.                       | Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic information. |

| Command                        | Description                                                                                                                      |
|--------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `dig domain.com`               | Performs a default A record lookup for the domain.                                                                               |
| `dig domain.com A`             | Retrieves the IPv4 address (A record) associated with the domain.                                                               |
| `dig domain.com AAAA`          | Retrieves the IPv6 address (AAAA record) associated with the domain.                                                            |
| `dig domain.com MX`            | Finds the mail servers (MX records) responsible for the domain.                                                                 |
| `dig domain.com NS`            | Identifies the authoritative name servers for the domain.                                                                       |
| `dig domain.com TXT`           | Retrieves any TXT records associated with the domain.                                                                           |
| `dig domain.com CNAME`         | Retrieves the canonical name (CNAME) record for the domain.                                                                     |
| `dig domain.com SOA`           | Retrieves the start of authority (SOA) record for the domain.                                                                   |
| `dig @1.1.1.1 domain.com`      | Specifies a specific name server to query; in this case, `1.1.1.1`.                                                             |
| `dig +trace domain.com`        | Shows the full path of DNS resolution.                                                                                          |
| `dig -x 192.168.1.1`           | Performs a reverse lookup on the IP address `192.168.1.1` to find the associated host name. You may need to specify a name server. |
| `dig +short domain.com`        | Provides a short, concise answer to the query.                                                                                  |
| `dig +noall +answer domain.com`| Displays only the answer section of the query output.                                                                            |
| `dig domain.com ANY`           | Retrieves all available DNS records for the domain. (*Note:* Many DNS servers ignore ANY queries to reduce load, as per RFC 8482). |


Per avere un output piccolo: `dig +short hackthebox.com`


# Subdomains

Spesso e' molto utile enumerare i sottodomini per varie ragioni quali:
- Development and Staging Environments. spesso per testare nuove feature le aziende usano sottodomini prima di lanciarlo nella main app.
- Hidden Login Portals
- Legacy application. Applicazioni vecchie che si sono scordati li'
- Sensitive information

## Subdomain Enumeration
### Active Subdomain Enumeration
1) Se riusciamo e' fare un **DNS zone Transfer** che ci rivela una lista completa di subdomain(raramente si puo' fare).
2) **brute-force** enumeration con tool come dnsenum,ffuf e gobuster.

### Passive Subdomain Enumeration
Ci si affida a fontin esterne di info. ad esempio **Certificate Transparecy (CT) Logs**, repository pubbliche di certificati SSL/TLS.

Search engine come Google, usando ad esempio Google dork come **site:)  per mostrare solo sottodomini relativi al target domain.

# Subdomain Bruteforcing

Il processo si puo' dividere in 4 step:
1) **Wordlist Selection**:
     - **General Purpose**, una lista che contiene molti subdomain name, utile quando non conosci le naming convention del target
     - **Targeted**, quando conosci le naming convention, piu' efficiente
     - **Custom**, basata su specifiche keyword, patther etc/ etc
2) **Iteration and Querying**, bruteforcing
3) **DNS Lokkup**, Si fa una Query DNS per ogni potenziale sottominio per vedere se risolve. solitamente guardiamo i record A e AAAA.
4) **Filtering and Validation**

| Tool         | Description                                                                                                           |
|--------------|-----------------------------------------------------------------------------------------------------------------------|
| `dnsenum`    | Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.       |
| `fierce`     | User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface.       |
| `dnsrecon`   | Versatile tool that combines multiple DNS reconnaissance techniques and offers customizable output formats.            |
| `amass`      | Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources. |
| `assetfinder`| Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans.      |
| `puredns`    | Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.                  |


## DNSEnum
tool utile e scritto in perl.
puo' fare:
- DNS Record Enumeration
- Zone Transfer Attempts
- Subdomain Brute-forcing
- Google Scraping
- WHOIS Lookups

`dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r`, subdomain brutefore con dnsenum.
la flag **-r** significa recursively, quindi se trova un sottodominio brute-forza pre quello.

# DNS Zone transfer
Questo meccanismo e' sviluppato per replicare DNS record tra server Name servers. Se configurato male (raro) puo' essere molto utile.
Nei primi anni di internet era comune permettere una Zone Transfer a tutti i client. 

Uno zone transfer e' effettivamente una copia di tutti i record DNS di una zona da un server ad un altro.
E' fondamentale questo processo per mantenere ridondanza tra server, ma se configurato male possiamo scaricare l' intero file di Zona vedendo tutti i sottodomini e gli IP associati e altri dati.

La richiesta si fa:
1) Server secondario fa una richiesta AXFR (richiesta di Zone Transfer)
2) Il primary server risponde con il SOA record (Start Of Authority) e i Vari DNS Record
3) Poi il primary server risponde con un Zone Transfer Complete
4) Infine il secondary server risponde con un ACK.

## Zone Transfer Vulnerability e Remediation
L' awereness di questa vulnerabilita' e' cresciuta e per mitigare il problema i server DNS moderni sono tipicamente configurati per permettere zone transfers solo a server secondari trustati.

Comunque rimane una cosa da provare fare lo zone transfer perche' legacy systems e configurazioni sbagliate possono consentircelo.

## Exploiting Zone Transfers
`j4k1dibe@htb[/htb]$ dig axfr @nsztm1.digi.ninja zonetransfer.me` Qua chiediamo uno Zone transfer al server DNS responsabile per il dominio **zonetransfer.me**.



# Virtual Hosts
Web server come Apache, Nginx, o IIS sono fatti per hostare piu' server web o applicazioni su uno stesso server. QUesto e' possibile grazie al **Virtual hoskint**. che permette di differenziare tra domini, sottodomini e website separati.

## Come funzionano 
Il core del virtual hosting e' l' abilita' dei server web di distinguere tra piu' website che condividono lo steso indirizzo IP. Si fa usando l' header **HTTP Host**, un campo dell' header.

La differenza chiav tra Vhosts e sottodomini e' la relazione con il DNS e la conf. del server web.

- Subdomains: These are extensions of a main domain name (e.g., blog.example.com is a subdomain of example.com). Subdomains typically have their own DNS records, pointing to either the same IP address as the main domain or a different one. They can be used to organise different sections or services of a website.
- Virtual Hosts (VHosts): Virtual hosts are configurations within a web server that allow multiple websites or applications to be hosted on a single server. They can be associated with top-level domains (e.g., example.com) or subdomains (e.g., dev.example.com). Each virtual host can have its own separate configuration, enabling precise control over how requests are handled.

se un virtual host non ha un record DNS possiamom comunque accederci modificando il file hosts.

Spesso i sitiweb hanno subdomains che non sono pubblici e non appaiono in DNR Records. sono accessibili sono internamente.

**Vhost fuzzing** e' la tecnica per scoprire subdomain e Vhosts pubblici e non pubblici testando vari hostname contro indirizzo ip conosciuto.

```
# Example of name-based virtual host configuration in Apache
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```

## Tipi di virtual hosting

1) Name-Based Virtual Hosting. questo metodo dipende solo sull' header HTTP Host. e' il piu' comune e flessibile e non richiede piu' indirizzi IP. Puo' avere alcune limitazioni con protocolli come SSL/TLS.
2) IP-Based Virtual Hosting. Questo tipo assegna un IP unico ad ogni sito web hostato sul server. Il server determina quale sito web rispondere in base a quale IP e' stato richiesto. Non dipende dall' header HTTP Host. Contro: richiede molti Indirizzi IP.
3) Port-Based Virtual Hosting. Siti web diversi sono associati a porte diverse sullo stesso IP. Utile ma non e' molto user friendly perche' richiede agli utenti di specificare la porta nell' URL.

## Virtual Host Discovery Tools

| Tool          | Description                                                                                     | Features                                                     |
|---------------|-------------------------------------------------------------------------------------------------|--------------------------------------------------------------|
| `gobuster`    | A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery. | Fast, supports multiple HTTP methods, can use custom wordlists. |
| `Feroxbuster` | Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility.  | Supports recursion, wildcard discovery, and various filters.  |
| `ffuf`        | Another fast web fuzzer that can be used for virtual host discovery by fuzzing the Host header.  | Customizable wordlist input and filtering options.            |


### Gobuster
**RICORDA DI EDITARE /etc/hosts PRIMA DI RUNNARE GOBUSTER CON UN DOMINIO**.

`j4k1dibe@htb[/htb]$ gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain` --append-domain significa di appendere il dominio base ad ogni parola nella wordlist.

`j4k1dibe@htb[/htb]$ gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain` esmepio pratico.

flag **-k** per ignorare errori di certificati SSL/TLS. flag **-o** per salvare output in un file.


# Certificate Transparency Logs
Al centro di SSL/TLS ci sono i certificati digitali, piccoli file che verificano l' identita' dei website per assicurare connessioni sicure.

Gli attaccanti possono abusare di rogue o misused certificati per impersonarsi siti web legittimi e intercettare dati sensibili.

I **Certicate Transparecy(CT) logs** sono log pubblici che accertano l' emissione del certificato. quando una CA(Certificate Authority) emette un ceritifcato nuovo deve submittare alcuni CT logs.

La transparency serve per:
- Rilevare subito dei certificati maligni (Rogue cert).
- Accountability for Certificate Authorities. Se una CA emette un certificato che viola le regole o standard, sara' visibile nei log.
- RInforzare la Web PKI.

## CT Logs and Web Recon
I CT logs offrono un vantaggio unico nell' enumerazione dei sottodomini rispetto ad altri metodi come brute-forcing etc.etc.
CT logs danno un record di certificati emessi per un dominio e sottodomini. Questo significa che non sei limitato dalla wordlist.
Inoltre i CT logs possono rivelare sottodomini con certificati scaduti, che magari hostano software legacy

## Searching CT Logs

| Tool     | Key Features                                                                                 | Use Cases                                         | Pros                                  | Cons                                       |
|----------|---------------------------------------------------------------------------------------------|-------------------------------------------------|---------------------------------------|--------------------------------------------|
| `crt.sh` | User-friendly web interface, simple search by domain, displays certificate details, SAN entries. | Quick and easy searches, identifying subdomains, checking certificate issuance history. | Free, easy to use, no registration required. | Limited filtering and analysis options.    |
| `Censys` | Powerful search engine for internet-connected devices, advanced filtering by domain, IP, certificate attributes. | Advanced device and certificate reconnaissance. | Advanced filtering, rich data sources.  | Requires an account for extended features. |

`j4k1dibe@htb[/htb]$ curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u`, per listare tutti i sottodomini di facebook.com che contengono 'dev'.


 # Fingerprinting

 Il fingerprinting consiste nell' estrarre dettagli tecnici sulle tecnologie usate in un sito web.

 Tecniche:
 - Banner Grabbing. analizzare i banner per vedere software usati , versioni e altri dettagli.
 - Analisi degli header HTTP. Il server header a volte rivela alcune info sul software del web server e **X-Powered-By** header puo' rivelare alcune info sulle tecnologie usate.
 - Probing for Specific Responses. Mandare richieste craftate in un modo specifico per vedere che risposte da' e capire ce tecnologie vengono usate e le versioni.
 - Analisi del contenuto della pagina web.


| Tool         | Description                                                                  | Features                                                                                       |
|--------------|------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| `Wappalyzer` | Browser extension and online service for website technology profiling.      | Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more. |
| `BuiltWith`  | Web technology profiler that provides detailed reports on a website's technology stack. | Offers both free and paid plans with varying levels of detail.                                |
| `WhatWeb`    | Command-line tool for website fingerprinting.                               | Uses a vast database of signatures to identify various web technologies.                      |
| `Nmap`       | Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting. | Can be used with scripts (NSE) to perform more specialised fingerprinting.                   |
| `Netcraft`   | Offers a range of web security services, including website fingerprinting and security reporting. | Provides detailed reports on a website's technology, hosting provider, and security posture. |
| `wafw00f`    | Command-line tool specifically designed for identifying Web Application Firewalls (WAFs). | Helps determine if a WAF is present and, if so, its type and configuration.                   |


## Banner Grapping
`j4k1dibe@htb[/htb]$ curl -I inlanefreight.com`, con curl, la flag **-I o --head** serve a prendere solo gli heade HTTP.

## Wafw00f
**Web Application Firewalls** (WAFs) sono soluzioni di sicurezza per proteggere app web. Prima di fare fingerprinting e' importante capire se il sito usa un WAF.

**wafw00f** e' un tool che permette di capire se un app usa un WAF.
`j4k1dibe@htb[/htb]$ pip3 install git+https://github.com/EnableSecurity/wafw00f`, per installare 

`j4k1dibe@htb[/htb]$ wafw00f inlanefreight.com`, per usare.

## Nikto
Nikto e' un web server scanner open source.
`j4k1dibe@htb[/htb]$ nikto -h inlanefreight.com -Tuning b`, dove **-h** specifica l' Host, **-Tuning b** specifica di runnare solo i Software Identification modules.

# Crawling
Il crawling chiamato anche spidering e' il processo automatico di explorare il World Wide Web.

Un crawler segue link da una pagina ad un altra, raccoglie informazioni. 
UN crawler Inizia da un Seed URL, fetcha la pagina, estrae tutti i link, li aggiunge ad una coda e e li esplora facendo questo processo ricorsivamente.
Facendo cosi' puo' mappare una vasta porzione di una pagina web.

Di solito estraggono Link (esterni e interni), Commenti, Metadati e File sensibili.

# Robots.txt

| Directive     | Description                                                                                                  | Example                                                    |
|---------------|--------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| `Disallow`    | Specifies paths or patterns that the bot should not crawl.                                                   | `Disallow: /admin/` (disallow access to the admin directory) |
| `Allow`       | Explicitly permits the bot to crawl specific paths or patterns, even if they fall under a broader Disallow rule. | `Allow: /public/` (allow access to the public directory)   |
| `Crawl-delay` | Sets a delay (in seconds) between successive requests from the bot to avoid overloading the server.          | `Crawl-delay: 10` (10-second delay between requests)       |
| `Sitemap`     | Provides the URL to an XML sitemap for more efficient crawling.                                              | `Sitemap: https://www.example.com/sitemap.xml`             |


# Well-known URIs
lo standard **.well-known**, e; uno standard di directory in un website root domain.
Tipicamente si accede tramite il path /.well-known/  e include metadati e file di configurazione.

.well-known semplifica la discovery e accesso per vari stakeholder.

la Internet Assigned Numbers Authority(YANA) mantiene un registro di .well-known URIs.

Eccone alcuni:
| URI Suffix                        | Description                                                                                     | Status       | Reference                                                                                             |
|-----------------------------------|-------------------------------------------------------------------------------------------------|--------------|-------------------------------------------------------------------------------------------------------|
| `security.txt`                    | Contains contact information for security researchers to report vulnerabilities.              | Permanent    | [RFC 9116](https://datatracker.ietf.org/doc/rfc9116/)                                                |
| `/.well-known/change-password`    | Provides a standard URL for directing users to a password change page.                        | Provisional  | [W3C Change Password URL](https://w3c.github.io/webappsec-change-password-url/#the-change-password-well-known-uri) |
| `openid-configuration`            | Defines configuration details for OpenID Connect, an identity layer on top of the OAuth 2.0 protocol. | Permanent    | [OpenID Connect Discovery](http://openid.net/specs/openid-connect-discovery-1_0.html)                |
| `assetlinks.json`                 | Used for verifying ownership of digital assets (e.g., apps) associated with a domain.          | Permanent    | [Google Digital Asset Links](https://github.com/google/digitalassetlinks/blob/master/well-known/specification.md) |
| `mta-sts.txt`                     | Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security. | Permanent    | [MTA-STS Specification](https://tools.ietf.org/html/rfc8461)                                         |
 
Nel contesto di web-recon l' URI **openid-configuration** puo' essere molto utile.
roba noiosissima. riguardatela qui: https://academy.hackthebox.com/module/144/section/3078


# Creepy Crawlies
## Popular Web Crawlers
- Burp Suite SPider
- OWASP ZAP
- Scrapy (python framework)
- Apache Nutch

## ReconSPider
```
j4k1dibe@htb[/htb]$ wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
j4k1dibe@htb[/htb]$ unzip ReconSpider.zip 
```

`j4k1dibe@htb[/htb]$ python3 ReconSpider.py http://inlanefreight.com`

# Search Engine Discovery
usa questo **https://www.exploit-db.com/google-hacking-database**


Search Operators.
| Operator       | Operator Description                                         | Example                                                   | Example Description                                                                                  |
|----------------|-------------------------------------------------------------|-----------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| `site:`        | Limits results to a specific website or domain.             | `site:example.com`                                        | Find all publicly accessible pages on example.com.                                                  |
| `inurl:`       | Finds pages with a specific term in the URL.                | `inurl:login`                                             | Search for login pages on any website.                                                              |
| `filetype:`    | Searches for files of a particular type.                    | `filetype:pdf`                                            | Find downloadable PDF documents.                                                                    |
| `intitle:`     | Finds pages with a specific term in the title.              | `intitle:"confidential report"`                           | Look for documents titled "confidential report" or similar variations.                              |
| `intext:` or `inbody:` | Searches for a term within the body text of pages.         | `intext:"password reset"`                                  | Identify webpages containing the term “password reset”.                                             |
| `cache:`       | Displays the cached version of a webpage (if available).    | `cache:example.com`                                       | View the cached version of example.com to see its previous content.                                 |
| `link:`        | Finds pages that link to a specific webpage.                | `link:example.com`                                        | Identify websites linking to example.com.                                                           |
| `related:`     | Finds websites related to a specific webpage.               | `related:example.com`                                     | Discover websites similar to example.com.                                                           |
| `info:`        | Provides a summary of information about a webpage.          | `info:example.com`                                        | Get basic details about example.com, such as its title and description.                             |
| `define:`      | Provides definitions of a word or phrase.                   | `define:phishing`                                         | Get a definition of "phishing" from various sources.                                                |
| `numrange:`    | Searches for numbers within a specific range.               | `site:example.com numrange:1000-2000`                     | Find pages on example.com containing numbers between 1000 and 2000.                                 |
| `allintext:`   | Finds pages containing all specified words in the body text.| `allintext:admin password reset`                          | Search for pages containing both "admin" and "password reset" in the body text.                     |
| `allinurl:`    | Finds pages containing all specified words in the URL.      | `allinurl:admin panel`                                    | Look for pages with "admin" and "panel" in the URL.                                                 |
| `allintitle:`  | Finds pages containing all specified words in the title.    | `allintitle:confidential report 2023`                     | Search for pages with "confidential," "report," and "2023" in the title.                            |
| `AND`          | Narrows results by requiring all terms to be present.       | `site:example.com AND (inurl:admin OR inurl:login)`       | Find admin or login pages specifically on example.com.                                              |
| `OR`           | Broadens results by including pages with any of the terms.  | `"linux" OR "ubuntu" OR "debian"`                         | Search for webpages mentioning Linux, Ubuntu, or Debian.                                            |
| `NOT`          | Excludes results containing the specified term.             | `site:bank.com NOT inurl:login`                           | Find pages on bank.com excluding login pages.                                                       |
| `*` (wildcard) | Represents any character or word.                           | `site:socialnetwork.com filetype:pdf user* manual`        | Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com.              |
| `..` (range)   | Finds results within a specified numerical range.           | `site:ecommerce.com "price" 100..500`                     | Look for products priced between 100 and 500 on an e-commerce website.                              |
| `" "`          | Searches for exact phrases.                                 | `"information security policy"`                           | Find documents mentioning the exact phrase "information security policy".                           |
| `-` (minus)    | Excludes terms from the search results.                     | `site:news.com -inurl:sports`                             | Search for news articles on news.com excluding sports-related content.                              |


# Web Archives

La famosa WayBack Machine.
La wayback machine funziona usando crawler che cattura snapshots di siti web a intervalli regolari e si salva tutto: HTML,CSS,JavaScript file etc.etc..

