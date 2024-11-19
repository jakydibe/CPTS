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

