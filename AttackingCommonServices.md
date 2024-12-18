# Interacting with Common Services

## File Sharing services

## Various ways to interact with SMB

### Win + R \\IP\sharename
Un modo semplice e' premere \\IP\nomeshare e ci aprira' la finestra nella share

### dir \\IP\sharename
da CMD shell possiamo lanciare `C:\htb> dir \\192.168.220.129\Finance\` per listare i contenuti della share

### WIndows CMD net
`C:\htb> net use n: \\192.168.220.129\Finance` per usare la share 

`C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123` se chiede l' autenticazione

`C:\htb> dir n: /a-d /s /b | find /c ":\"` Per contare quanti file nella share

`C:\htb>dir n:\*cred* /s /b` per vedere se ci sono file che contengono 'cred' nel nome del file

### Con findstr
`c:\htb>findstr /s /i cred n:\*.*` cerca file che contengono 'cred' dentro di loro


### Con Powershell

`PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\` lista i contenuti della share

`PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"` invece che net use

### Se richiede credenziali
```
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
----           ---------     --------- --------      ----                                                              ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```
### vedere quanti file ci sono nella share montata N
```
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count

29302
```

### Vedere file con 'cred' nel nome
`PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File`

### File che contengono cred dentro
`PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List`

## Montare share su Linux
```
j4k1dibe@htb[/htb]$ sudo mkdir /mnt/Finance
j4k1dibe@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

`sudo apt install cifs-utils` per installare le dipendenze per collegarsi alla share smb

`j4k1dibe@htb[/htb]$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile` alternativa

### Linux find
`j4k1dibe@htb[/htb]$ find /mnt/Finance/ -name *cred*` find files that contains 'cred' in the name

`j4k1dibe@htb[/htb]$ grep -rn /mnt/Finance/ -ie cred` files that contains 'cred' inside

## Other Services

Spesso dovremo interagire con diversi servizi. 

`j4k1dibe@htb[/htb]$ sudo apt-get install evolution`  per installare evolution, un mail client su linux

## Databases

Abbiamo vari modi per comunicare con i database. 

1) Usare command line utilities come **mysql** o **sqsh** shells
2) Usare le GUI per questi prodotti
3) usare linguaggi di programmazione

### MSSQL

Per interagire con MSSQL usiamo **sqsh** oppure **sqlcmd**

`j4k1dibe@htb[/htb]$ sqsh -S 10.129.20.13 -U username -P Password123` da linux

`C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123` da windows

### MySQL
`j4k1dibe@htb[/htb]$ mysql -u username -pPassword123 -h 10.129.20.13` da linux

`C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13` da windows

### GUI

per usare le GUI dobbiamo installare 

`j4k1dibe@htb[/htb]$ sudo dpkg -i dbeaver-<version>.deb`


# Attacking FTP

## Enumeration
`j4k1dibe@htb[/htb]$ sudo nmap -sC -sV -p 21 192.168.2.142 `

## Misconfigurations

1) Controlliamo se possiamo fare anonymous login


## Brute force con Medusa

`j4k1dibe@htb[/htb]$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp `

## FTP Bounce attack

Un attacco FTP Bounce permette ad un attaccante di utilizzare un server FTP esposto all' esterno per interagire con la rete interna.

`nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2` 

Con questo comando possiamo fare una nmap scan di una macchina in rete interna.



