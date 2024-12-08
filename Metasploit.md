# Metasploit Project

Il Metasploit project e' suddiviso in Metasploit Pro, mirato alle aziende e al Metasploit Framework che e' open source e gratis.


## To list the modules
`j4k1dibe@htb[/htb]$ ls /usr/share/metasploit-framework/modules`

## To list plugins
`j4k1dibe@htb[/htb]$ ls /usr/share/metasploit-framework/plugins/`

## Scripts
`j4k1dibe@htb[/htb]$ ls /usr/share/metasploit-framework/scripts/`

## Tools
`j4k1dibe@htb[/htb]$ ls /usr/share/metasploit-framework/tools/`


# MSFConsole

### Launch without banner
`msfconsole -q`

### Installare se non c'e'
`j4k1dibe@htb[/htb]$ sudo apt update && sudo apt install metasploit-framework`


# Modules

la categoria **exploit** consiste in PoCs per exploitare in modo automatico certe vulnerabilita'.

## Type

il tag Type specifica il tipo di moduli presenti

| Type         | Description                                                                                     |
|--------------|-------------------------------------------------------------------------------------------------|
| **Auxiliary**| Scanning, fuzzing, sniffing, and admin capabilities. Offers extra assistance and functionality. |
| **Encoders** | Ensure that payloads are intact when they reach their destination.                              |
| **Exploits** | Modules that exploit a vulnerability to deliver the payload.                                    |
| **NOPs**     | (No Operation code) Keep the payload sizes consistent across exploit attempts.                  |
| **Payloads** | Code that runs remotely and calls back to the attacker's machine to establish a connection (or shell). |
| **Plugins**  | Additional scripts that can be integrated into an assessment using msfconsole and coexist.      |
| **Post**     | Modules used for post-exploitation, including gathering information and pivoting deeper.        |



## MSF Specific search
`msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft`


## Info

comando `info` dopo aver selezionato un modulo fa vedere molte info sul modulo.

## Permanent target Specification

`setg RHOSTS 10.10.10.40`. **setg** sta oer set globally e setta il parametro globalmente (comodo se voglio switchare moduli)



# Targets

i **Target** sono token identificatori univoci di sistemi operativi. Quindi specificare un target significa specificare la versione precisa di un OS.

`msf6 > show targets` fa vedere i target disponibili

con `info` si vedono anche gli available targets.



a volte per identificare correttamente un target dovremmo:

1) ottenere un binario del target
2) usare **msfpescan** per trovare un valido return address.


# Payloads

## Singles
contengono l' esploit e lo shellcode intero per la task selezionata.


## Stagers

## STages


## List payloads
`show payloads`


## Searching for a specific payload
`msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter show payloads`





# Encoders

Gli encoder sono utili per farli runnare in diverse architetture come x64,x86,sparc,ppc,mips.

Si usano anche per bypassare AVs


# Databases

Database in msfconsole si usano per tenere traccia dei risultati. In macchina piu' complesse la quantita' di informazioni e' overwhelming.

Msfconsole ha un built-int PostgreSQL database.

## Setting up database

### PostgreSQL status
`j4k1dibe@htb[/htb]$ sudo service postgresql status`

### Start PostgreSQL
`j4k1dibe@htb[/htb]$ sudo systemctl start postgresql`


### MSF initiate a database
`j4k1dibe@htb[/htb]$ sudo msfdb init`

`j4k1dibe@htb[/htb]$ sudo msfdb status` visualizza status


### MSF Connect to database
`j4k1dibe@htb[/htb]$ sudo msfdb run`


### Reinitiate the database

```
j4k1dibe@htb[/htb]$ msfdb reinit
j4k1dibe@htb[/htb]$ cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
j4k1dibe@htb[/htb]$ sudo service postgresql restart
j4k1dibe@htb[/htb]$ msfconsole -q

msf6 > db_status

[*] Connected to msf. Connection type: PostgreSQL.
```

### Database commands

```
msf6 > help database

Database Backend Commands
=========================

    Command           Description
    -------           -----------
    db_connect        Connect to an existing database
    db_disconnect     Disconnect from the current database instance
    db_export         Export a file containing the contents of the database
    db_import         Import a scan result file (filetype will be auto-detected)
    db_nmap           Executes nmap and records the output automatically
    db_rebuild_cache  Rebuilds the database-stored module cache
    db_status         Show the current database status
    hosts             List all hosts in the database
    loot              List all loot in the database
    notes             List all notes in the database
    services          List all services in the database
    vulns             List all vulnerabilities in the database
    workspace         Switch between database workspaces
```

## Workspaces

Possiamo mettere i vari risultati delle nostre analisi in diversi workspace


Si possono pure importare file con `db_import`.


## Using Nmap inside MSFCOnsole
`msf6 > db_nmap -sV -sS 10.10.10.8`


# Plugins

i Plugins sono software gia' rilasciati da terze parti e apprivate dai crreatori di Metasploit per integrarle nel framework.

`j4k1dibe@htb[/htb]$ ls /usr/share/metasploit-framework/plugins` listare i okugin


### Nessus
`msf6 > load nessus` c'e' pure Nessus come plugin.


### Install new plugins
```
j4k1dibe@htb[/htb]$ git clone https://github.com/darkoperator/Metasploit-Plugins
j4k1dibe@htb[/htb]$ ls Metasploit-Plugins

```

`j4k1dibe@htb[/htb]$ sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb` copio il plugin dentro la cartella


`msf6 > load pentest` dentro msfconsole lo carico

- nMap (pre-installed)
- NexPose (pre-installed)
- Nessus (pre-installed)
- Mimikatz (pre-installed V.1)
- Stdapi (pre-installed)
- Railgun
- Priv
- Incognito (pre-installed)
- Darkoperator's



# Sessions

`bg` in meterpreter per metterla in background

`sessions` per visualizzare le sessioni attive

`sessions -i <id_sessione`, per rimettere in foreground una sessione

## Jobs
`jobs -h` per vedere le opzioni 


`exploit -j`, runna un exploit come un job in background.

`jobs -l` lista i jobs



# Meterpreter

## Dump hashes
`hashdump`
`lsa_dump_sam`

`lsa_dump_secrets`



# Writing and importing modules

Per cercare le PoC non c'e' solo la funzione search di Metasploit ma c'e' anche **searchsploit**.

`j4k1dibe@htb[/htb]$ searchsploit -t Nagios3 --exclude=".py"` se voglio vedere solo i moduli di Metasploit (tendenzialmente  file .rb) 

## Loading additional modules at runtime

```
j4k1dibe@htb[/htb]$ cp ~/Downloads/9861.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb
j4k1dibe@htb[/htb]$ msfconsole -m /usr/share/metasploit-framework/modules/
```

## Loading from a path
`msf6> loadpath /usr/share/metasploit-framework/modules/`

`msf6 > reload_all`


## Writing our module


# Firewall and IPS/IDS Evasion

## Endpoint protection

tutte quelle protezioni per proteggere un singolo host.

## Test with VirusTotal
`j4k1dibe@htb[/htb]$ msf-virustotal -k <API key> -f test.js `
