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