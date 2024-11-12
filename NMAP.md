# NMAP

offre diversi tipi di scan e tecniche quali 
- Host discovery
- Port scanning
- Service enumration e detection
- OS detection
- Script vari


### TCP-SYN Scan
Di default fa la TCP-SYN scan che corrisponde alla flag `-sS`.
e' molto veloce e consiste nel mandare un pacchetto con la flag SYN SENZA completare il 3-way handshake.

- se il target ci manda indietro una __SYN-ACK__  allora la porta e' **open**
- se risponde con **RST** la porta e' **closed**
- se non riceviamo niente vedremo **filtered** e probabilmente il firewall ha droppato il pacchetto


# Host Discovery
Si puo' specificare un range di host da controllare se sono online.
```sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5``` 

dove :
- 10.129.2.0/24 e' il range della rete
- la flab `-sn` consente di disabilitare il port scanning

Si puo' anche fare una scan di una lista di indirizzi ip fornendo la flag `-iL` e il file con gli indirizzi IP.
Oppure semplicemente dare piu' IP nel comando tipo cosi: ```sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20```

se disabilitiamo il port scan con `-sn` NMAP fa una ping scan con le **ICMP Echo Requests** (flag `-PE`), e dopo una richiesta del genere solitamente ci aspettiamo indietro una **ICMP reply** se l' host e' alive.  comunque Nmap prima che puo' mandare una ICMP echo request DEVE mandare prima un **ARP ping** a cui risponde una **ARP reply**.
Per poter visualizzare queste cose e vedere effettivamente tutto cio' che fa il pacchetto possiamo usare la flag `--packet-trace`.

Una volta scoperto possiamo disabiitare le ARP Requests che ormai non ci servono piu' con `--disable-arp-ping`.


# Host and Port Scanning

Le porte possono avere 6 stati:
- **open**. Si puo' stabilire una connessione su quella porta.
- **closed** la porta e' chiusa, significa che ci ritorna un **RST**
- **filtered**, non abbiamo ricevuto nessun pacchetto risposta o ritorna un errore. probabilmente e' stato droppato dal firewall.
- **unfiltered**, puo' succedere solo durante la scan **TCP-ACK** e significa che la porta e' accessibile ma non si puo' determinare se e' aperta o chiusa.
- **open|filtered** se non riceviamo una risposta da quella porta. probabilmente droppato
- **closed|filtered** c'e' solo quando facciamo una **IP ID idle** scan. indicia che era impossibile determinare se la porta e' chiusa o filtrata.


  Di default Nmap fa la scan delle top 1000 porte (le 1000 piu' utilizzate) con la scan `-sS`. la **SYN** scan con `-sS` solitamente e' default quando runniamo nmap come root perche' c'e' bisogno di permessi di root per creare pacchetti TCP raw. Altrimenti se non runniamo come root la default e' la **TCP scan** con la fla `-sT`,

flag che scrive il perche' una certa porta e' in uno stato: `--reason`
specificare piu' porte: `-p 22,25,80,139,445`.
specificare un range di porte `-p 22-445`.
specificare il numero di top ports: `--top-ports=10`
top 100 porte `-F`

per disabilitare le ICMP echo requests: `-Pn`
per disabilitare la DNS resolution: `-n`
per disabilitare ARP ping scan `--disable-arp-ping`

## Connect scan
la **TCP Connect Scan** che si fa con flag `-sT` usa il 3-way TCP handshake per determinare se una porta specifica di un target e' aperta o chiusa.
Manda un pacchetto SYN e aspetta, se la porta risponde con SYN-ACK e' aperta, se con RST e' chiusa.
Il vantaggio della TCP COnnect Scan e' che e' molto accurata in quanto fa un completo 3-way handshake, riuscendo a trovare lo stato esatto di una porta. tuttavia non e' per niente stealthy e crea molti log facili bersaglio per IDS/IPS moderni. Inoltre e' piu' socira perche' la probabilita' che causa errori ai servizi con cui interagisce e' minore.

E' utile anche nei casi in cui l'host ha un personal firewall che droppa pacchetti incoming ma permette gli outgoing.
esempio di una connect scan: `j4k1dibe@htb[/htb]$ sudo nmap 10.129.2.28 -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT `

## Porte filtrate
Una porta puo' risultare filtrata per piu' ragioni. Nella maggior parte dei casi e' colpa del firewall. I pacchetti possono essere **dropped** oppure **rejected**. quando un pacchetto viene droppato nmap non riceve risposte dal nostro target e di default il **retry rate** e' settato a 10 `--max-retries`.

## Porte UDP
A volte alcuni sysadmin potrebbero simenticarsi di filtrare le prote UDP oltre alle TCP. Dato che UDP e' un protocollo stateless non riceviamo nessun Acknowledgment. percio'  il timeout e' piu' lunnga e la **UDP Scan** (che si fa con la flag `-sU`) e' molto piu' lenta della TCP scan.

## Version Scan
la flag `-sV` cerca di trovare quale servizio e quale versione del servizio giro su una determinata porta.


# Salvare l' output
- `-oN` per salvare l' output normale con l' estensione .nmap
- `-oG` con l' estensione .gnmap
- `-oX` per salvare con estensione .xml
- `-oA` per salvare in tutti i modi di prima

convertire .xml in html `j4k1dibe@htb[/htb]$ xsltproc target.xml -o target.html`.

# Service Enumeration
e' 
