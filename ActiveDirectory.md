# Active Directory attacks

Spesso ci sono misconfiguration. Utilizzeremo molti tool e molti attacchi.

Lo scopo principale di attaccare un ambiente AD e' scalare privilegi e muoversi lateralmente o verticalmente attraverso la rete.

Dovremo diventare abituati ad enumerare sia da Windows che da Linux e usando un toolset limitato o windows built-in tools per **Living off the land**.

Nel corso molte volte i tool saranno in "C:\Tools"


# Initial Enumeration

# External Recon and Enumeration

Si puo' sempre trarre beneficio da fare una reconnaissance esterna del target.


dovremo cercare 
|Data Point|	Description|
|--|--|
IP Space	|Valid ASN for our target, netblocks in use for the organization's public-facing infrastructure, cloud presence and the hosting providers, DNS record entries, etc.|
Domain Information|	Based on IP data, DNS, and site registrations. Who administers the domain? Are there any subdomains tied to our target? Are there any publicly accessible domain services present? (Mailservers, DNS, Websites, VPN portals, etc.) Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.)
Schema Format	|Can we discover the organization's email accounts, AD usernames, and even password policies? Anything that will give us information we can use to build a valid username list to test external-facing services for password spraying, credential stuffing, brute forcing, etc.
Data Disclosures|	For data disclosures we will be looking for publicly accessible files ( .pdf, .ppt, .docx, .xlsx, etc. ) for any information that helps shed light on the target. For example, any published files that contain intranet site listings, user metadata, shares, or other critical software or hardware in the environment (credentials pushed to a public GitHub repo, the internal AD username format in the metadata of a PDF, for example.)
Breach Data	Any| publicly released usernames, passwords, or other critical information that can help an attacker gain a foothold.
