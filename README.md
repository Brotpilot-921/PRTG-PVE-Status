# PRTG-PVE-Status.PS1

<!-- ABOUT THE PROJECT -->
### About The Project
Project Owner: Jannos-443

PRTG powershell script to monitor Proxmox VE (PVE)

Free and open source: [MIT License](https://github.com/Jannos-443/PRTG-PVE-Status/blob/main/LICENSE)

**Features**
* Monitor Node status
* Monitor Subscription status
* Monitor Storage
* Monitor VM status
* Monitor Container status
* Monitor snapshot age
* Excludes/Includes
  * ExcludeVMName
  * ExcludeVMTag
  * ExcludeLXCName
  * ExcludeLXCTag
  * ExcludeNode
  * ExcludeSnapDescription
  * ExcludeSnapName 
  * IncludeVMName
  * IncludeVMTag
  * IncludeLXCName
  * IncludeLXCTag
  * IncludeNode
  * IncludeSnapDescription
  * IncludeSnapName

**Working On**

*  Cluster Sensor
*  Ceph Integration
*  Network usage (per node) 

## Changelog

V0.01 - initial release  
V0.02 - Added feature to monitore storage + subscription status

<!-- GETTING STARTED -->
## Getting Started

1. Create PVE API Token
    - Full API Permissions 
       - Permissions -> API Tokens -> Add
          - User: YourUser
          - Token ID: YourTokenName
          - Privilege Seperation: Disable

    - ReadOnly API Permission (Privilege Seperation)
       - Permissions -> API Tokens -> Add
          - User: YourUser
          - Token ID: YourTokenName
          - Privilege Seperation: Enable
       - Permissions -> Add -> API Token Permission
          - Path: /
          - API Token: YourTokenName
          - Role: PVEAuditor

       ![example1](media/token.png)

       ![example1](media/token_acl.png)

2. Make sure the "Corsinvest.ProxmoxVE.Api" module exists on the Probe under the Powershell Module Path
   - `C:\Program Files\PowerShell\Modules\Corsinvest.ProxmoxVE.Api`
       - https://github.com/Corsinvest/cv4pve-api-powershell
       -  open pwsh.exe (powershell 7) and `Install-Module -Name Corsinvest.ProxmoxVE.Api -Scope AllUsers`

3. Make sure Powershell 7 is installed and available
    - `C:\Program Files\PowerShell\7\pwsh.exe`
        - https://aka.ms/powershell-release?tag=lts
        - `winget install --id Microsoft.PowerShell`
    
4. Place `PRTG-PVE-Status.ps1` under `C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML`

5. Create new sensor

   | Settings | Value |
   | --- | --- |
   | EXE/Script Advanced | PRTG-PVE-Status.ps1 |
   | Parameters | -Server 'yourPVE' -User 'yourUser' -Password 'yourPassword' |
   | Scanning Interval | 30 minutes |


6. Change parameter if needed 
   - Include/Exclude
   - Change Limits

## Usage

Connect to Server using Username/Password (using placeholder)
```powershell
-Server '%host' -User '%linuxuser' -Password '%linuxpassword' -SkipCertCheck
```

Connect to Server using Username/Password
```powershell
-Server '192.168.1.100' -User 'PVEUser' -Password 'PVEPassword' -SkipCertCheck
```

Connect to Server using API Token, ignore SelfSigned certificate and custom port (using placeholder)
```powershell
-Server '%host' -PORT "8888" -APITOKEN '%scriptplaceholder1' -SkipCertCheck
```

Connect to Server using API Token, ignore SelfSigned certificate and custom port
```powershell
-Server '192.168.1.100' -PORT "8888" -APITOKEN 'root@pam!prtg=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -SkipCertCheck
```

Show all Channel
```powershell
-Server '192.168.1.100' -PORT "8888" -APITOKEN 'root@pam!prtg=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -SkipCertCheck
```
![example1](media/ok.png)

Show Snapshots
```powershell
... -channel_snapshot
```
![example1](media/snapshot.png)

Show Node state 
```powershell
... -channel_nodes
```
![example1](media/node.png)

Show VM state 
```powershell
... -channel_vm
```
![example1](media/vm.png)

Show LXC state 
```powershell
... -channel_vm
```
![example1](media/lxc.png)

## Includes/Excludes

You can use the variables to exclude/include
The variables take a regular expression as input to provide maximum flexibility.

For more information about regular expressions in PowerShell, visit [Microsoft Docs](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions).

".+" is one or more charakters
".*" is zero or more charakters
