<#
    .SYNOPSIS
    PRTG powershell script to monitor Proxmox VE (PVE)

    .DESCRIPTION
    PRTG powershell script to monitor Proxmox VE (PVE)

    .NOTES
    Version 0.01

    Changelog:
    0.01 - initial release

    Powershell 7 required - https://aka.ms/powershell-release?tag=lts
    Proxmox VE Powershell Module required - https://github.com/Corsinvest/cv4pve-api-powershell
    Proxmox VE API: https://pve.proxmox.com/pve-docs/api-viewer/#/nodes

    Author:  Jannos-443
    https://github.com/Jannos-443/PRTG-PrintJobs
#>
param(
    [string] $Server = "",
    [string] $Port = "8006",
    [string] $Username = "",
    [string] $Password = '',
    [string] $APITOKEN = '',
    [switch] $SkipCertCheck,
    [switch] $channel_nodes,
    [switch] $channel_nodes_detail,
    [switch] $channel_snapshot,
    [switch] $channel_vm,
    [switch] $channel_lxc,
    [string] $ExcludeLXCName ='',
    [string] $ExcludeLXCTag ='',
    [string] $ExcludeVMName = '',
    [string] $ExcludeVMTag = '',
    [string] $ExcludeNode = '',
    [string] $ExcludeSnapDescription = '',
    [string] $ExcludeSnapName = '',
    [string] $IncludeLXCName ='',
    [string] $IncludeLXCTag ='',
    [string] $IncludeVMName = '',
    [string] $IncludeVMTag = '',
    [string] $IncludeNode = '',
    [string] $IncludeSnapDescription = '',
    [string] $IncludeSnapName = '' 
)

#Catch all unhandled Errors
trap {
    $Output = "line:$($_.InvocationInfo.ScriptLineNumber.ToString()) char:$($_.InvocationInfo.OffsetInLine.ToString()) --- message: $($_.Exception.Message.ToString()) --- line: $($_.InvocationInfo.Line.ToString()) "
    $Output = $Output.Replace("<", "")
    $Output = $Output.Replace(">", "")
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>$Output</text>"
    Write-Output "</prtg>"
    Exit
}

# Error if there's anything going on
$ErrorActionPreference = "Stop"

# XML output variable
$xmlOutput = '<prtg>'

# XML output text
$OutputText = ""

# Checkif POWERSHELL 7 is installed
if (-not (Test-Path "C:\Program Files\PowerShell\7\pwsh.exe")) {
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>please verify powershell 7 is installed under `"C:\Program Files\PowerShell\7\pwsh.exe`"</text>"
    Write-Output "</prtg>"
    Exit
}

# POWERSHELL 7 Workaround because PRTG can just run PWSH 5
if ($PSVersionTable.PSVersion.Major -eq 5) {
    if ($myInvocation.Line) {
        [string]$output = &'C:\Program Files\PowerShell\7\pwsh.exe' -NonInteractive -NoProfile -CommandWithArgs "$($myInvocation.Line)"
    }
    else {
        [string]$output = &'C:\Program Files\PowerShell\7\pwsh.exe' -NonInteractive -NoProfile -file "$($myInvocation.InvocationName)" $args
    }

    Write-Output $output
    exit
}

# Import Corsinvest.ProxmoxVE.Api PowerCLI module
try {
    Import-Module "Corsinvest.ProxmoxVE.Api" -ErrorAction Stop
}
catch {
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>Error Loading Corsinvest.ProxmoxVE.Api Powershell Module ($($_.Exception.Message))</text>"
    Write-Output "</prtg>"
    Exit
}

# Check Credentials
$login_type = $null
if (($APITOKEN -ne "") -and ($null -ne $APITOKEN)) {
    $login_type = "TOKEN"
}
elseif (($Username -ne "") -and ($Password -ne "")) {
    $login_type = "USER"
}
else {
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>APITOKEN or Username/Password missing</text>"
    Write-Output "</prtg>"
    Exit
}

# Check Server
if (($Server -eq "") -or ($null -eq $Server)) {
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>Server not specified</text>"
    Write-Output "</prtg>"
    Exit
}

# Check Server Port
if (($Port -eq "") -or ($null -eq $Port)) {
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>Server Port not specified</text>"
    Write-Output "</prtg>"
    Exit
}

# Check Channel Selection
if ((-not $channel_nodes) -and (-not $channel_nodes_detail) -and (-not $channel_snapshot) -and (-not $channel_vm) -and (-not $channel_lxc)) {
    $channel_nodes = $true
    $channel_snapshot = $true
    $channel_vm = $true
    $channel_lxc = $true
    #Write-Output "<prtg>"
    #Write-Output "<error>1</error>"
    #Write-Output "<text>please configure at least one -channel parameter</text>"
    #Write-Output "</prtg>"
    #Exit
}


# Connect to Server
try {
    #USERNAME AND PASSWORD
    if ($login_type -eq "USER") {
        $SecPasswd = ConvertTo-SecureString $Password -AsPlainText -Force
        $pve_creds = New-Object System.Management.Automation.PSCredential ($Username, $SecPasswd)
        
        if ($SkipCertCheck) {
            $ticket = Connect-PveCluster -Credentials $pve_creds -HostsAndPorts "$($Server):$($Port)" -SkipCertificateCheck
        }
        else {
            $ticket = Connect-PveCluster -Credentials $pve_creds -HostsAndPorts "$($Server):$($Port)"
        }
    }
    #APITOKEN
    elseif ($login_type -eq "TOKEN") {
        if ($SkipCertCheck) {
            $ticket = Connect-PveCluster -ApiToken $APITOKEN -HostsAndPorts "$($Server):$($Port)" -SkipCertificateCheck
        }
        else {
            $ticket = Connect-PveCluster -ApiToken $APITOKEN -HostsAndPorts "$($Server):$($Port)"
        }
    }
    #missing login_type
    else {
        throw "missing login_type!!??"
    }
}
 
catch {
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>Could not connect to PVE server $Server. Error: $($_.Exception.Message)</text>"
    Write-Output "</prtg>"
    Exit
}

# Check if ticket is there
if (($null -eq $ticket) -or ($ticket -eq "")) {
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>Could not connect to PVE server $Server. No Response - please verify attributes</text>"
    Write-Output "</prtg>"
    Exit
}
elseif ($login_type -eq "USER") {
    if (($null -eq $ticket.token) -or ($ticket.token -eq "")) {
        Write-Output "<prtg>"
        Write-Output "<error>1</error>"
        Write-Output "<text>Could not connect to PVE server $Server. Ticket response error - please verify credentials</text>"
        Write-Output "</prtg>"
        Exit
    }
}
elseif ($login_type -eq "TOKEN") {
    if (($null -eq $ticket.ApiToken) -or ($ticket.ApiToken -eq "")) {
        Write-Output "<prtg>"
        Write-Output "<error>1</error>"
        Write-Output "<text>Could not connect to PVE server $Server. APIToken response error - please verify credentials</text>"
        Write-Output "</prtg>"
        Exit
    }
}

$version = Get-PveVersion -PveTicket $ticket
if(-not $version.IsSuccessStatusCode){
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>Error getting API Response - Code=$($version.StatusCode) Reason=$($version.ReasonPhrase)</text>"
    Write-Output "</prtg>"
    Exit
}

# NODES 
if ($channel_nodes) {
    $Nodes = (Get-PveNodes -PveTicket $ticket).ToData()
    $Nodes = $Nodes | Where-Object { $_.type -eq "node" }
    $NodesOnline = $Nodes | Where-Object { $_.status -eq "online" }
    $NodesOffline = $Nodes | Where-Object { $_.status -eq "offline" }
    $NodesUnkown = $Nodes | Where-Object { ($_.status -ne "online") -and ($_.status -ne "offline") } 
    $xmlOutput += "<result>
<channel>Nodes Online</channel>
<value>$($NodesOnline.Count)</value>
<unit>Count</unit>
</result>
<result>
<channel>Nodes Offline</channel>
<value>$($NodesOffline.Count)</value>
<unit>Count</unit>
<limitmode>1</limitmode>
<LimitMaxError>0</LimitMaxError>
</result>
<result>
<channel>Nodes Unkown</channel>
<value>$($NodesUnkown.Count)</value>
<unit>Count</unit>
<limitmode>1</limitmode>
<LimitMaxError>0</LimitMaxError>
</result>"
}

# SNAPSHOT
if ($channel_snapshot) {
    $all_vms = Get-PveVm -PveTicket $ticket
    $SnapshotCount = 0
    $age = 0
    $age_name = ""

    # Region: VM Filter (Include/Exclude)
    # hardcoded list that applies to all hosts
    $ExcludeVMNameScript = '^(TestIgnore123)$' 
    $IncludeVMNameScript = ''

    #VM Name
    if ($ExcludeVMName -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -notmatch $ExcludeVMName }  
    }

    if ($ExcludeVMNameScript -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -notmatch $ExcludeVMNameScript }  
    }

    if ($IncludeVMName -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -match $IncludeVMName }  
    }

    if ($IncludeVMNameScript -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -match $IncludeVMNameScript }  
    }

    #VM Tag
    if ($ExcludeVMTag -ne "") {
        $all_vms = $all_vms | Where-Object { (-not $_.tags) -or ($_.tags.split(";") -notmatch $ExcludeVMTag) } 
    }

    if ($IncludeVMTag -ne "") {
        $all_vms = $all_vms | Where-Object { ($_.tags) -and ($_.tags.split(";") -match $IncludeVMTag) }
    }

    #VM Node
    if ($ExcludeNode -ne "") {
        $all_vms = $all_vms | Where-Object { $_.node -notmatch $ExcludeNode }  
    }

    if ($IncludeNode -ne "") {
        $all_vms = $all_vms | Where-Object { $_.node -match $IncludeNode }  
    }
    #End Region VM Filter

    foreach ($vm in $all_vms) {
        $snapshots = Get-PveVmSnapshot -VmIdOrName $vm.vmid -PveTicket $ticket
        $snapshots = $snapshots.Response.data
        $snapshots = $snapshots | Where-Object { $_.name -ne "current" }

        # Snapshot filter (include/exclude)
        # Snapshot Name
        if ($ExcludeSnapName -ne "") {
            $snapshots = $snapshots | Where-Object { $_.Name -notmatch $ExcludeSnapName }  
        }

        if ($IncludeSnapName -ne "") {
            $snapshots = $snapshots | Where-Object { $_.Name -match $IncludeSnapName }  
        }

        # Snapshot Description
        if ($ExcludeSnapDescription -ne "") {
            $snapshots = $snapshots | Where-Object { $_.Description -notmatch $ExcludeSnapDescription }  
        }

        if ($IncludeSnapDescription -ne "") {
            $snapshots = $snapshots | Where-Object { $_.Description -match $IncludeSnapDescription }  
        }        
            
        foreach ($snapshot in $snapshots) {
            $SnapshotCount ++ 
            $temp_age = (Get-Date) - (Get-Date -UnixTimeSeconds $snapshot.snaptime)
            $temp_age = [math]::Round($temp_age.TotalSeconds)
            if ($temp_age -gt $age) {
                $age = $temp_age
                $age_name = "VM=$($vm.name) Snapshot=$($snapshot.name) Created=$((Get-Date -UnixTimeSeconds $snapshot.snaptime).ToString("dd.MM.yyyy-hh:mm"))"
            }
        }
    }
    $OutputText += "$($age_name)"

    $xmlOutput += "
<result>
<channel>total Snapshots</channel>
<value>$SnapshotCount</value>
<unit>Count</unit>
</result>
<result>
<channel>oldest Snapshot</channel>
<value>$([decimal]$age)</value>
<unit>TimeSeconds</unit>
<limitmode>1</limitmode>
<LimitMaxWarning>432000</LimitMaxWarning>
<LimitMaxError>604800</LimitMaxError>
</result>"
}

# LXC
if ($channel_lxc) {
    $all_vms = $null
    $all_vms = Get-PveVm -PveTicket $ticket
    $all_vms = $all_vms | Where-Object {$_.type -eq "lxc"}

    #Node
    if ($ExcludeNode -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -notmatch $ExcludeNode }  
    }
    
    if ($IncludeNode -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -match $IncludeNode }  
    }

    #Name
    if ($ExcludeLXCName -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -notmatch $ExcludeLXCName }  
    }
    
    if ($IncludeLXCName -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -match $IncludeLXCName }  
    }
    
    #Tags
    if ($ExcludeLXCTag -ne "") {
        $all_vms = $all_vms | Where-Object { (-not $_.tags) -or ($_.tags.split(";") -notmatch $ExcludeLXCTag) } 
    }
    
    if ($IncludeLXCTag -ne "") {
        $all_vms = $all_vms | Where-Object { ($_.tags) -and ($_.tags.split(";") -match $IncludeLXCTag) }
    }
    #End Filter

    $total_vms = $null
    $online_vms = $null
    $offline_vms = $null

    $total_lxc = ($all_vms | Measure-Object).count
    $online_lxc = ($all_vms | Where-Object { $_.status -eq "running" } | Measure-Object).count
    $offline_lxc = ($all_vms | Where-Object { $_.status -eq "stopped" } | Measure-Object).count

    $xmlOutput += "
<result>
<channel>LXCs Total</channel>
<value>$total_lxc</value>
<unit>Count</unit>
</result>
<result>
<channel>LXCs Online</channel>
<value>$online_lxc</value>
<unit>Count</unit>
</result>
<result>
<channel>LXCs Offline</channel>
<value>$offline_lxc</value>
<unit>Count</unit>
</result>"
}

# VM STATE
if ($channel_vm) {
    $all_vms = $null
    $all_vms = Get-PveVm -PveTicket $ticket
    $all_vms = $all_vms | Where-Object {$_.type -eq "qemu"}

    #Node
    if ($ExcludeNode -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -notmatch $ExcludeNode }  
    }
    
    if ($IncludeNode -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -match $IncludeNode }  
    }

    #Name
    if ($ExcludeVMName -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -notmatch $ExcludeVMName }  
    }
    
    if ($IncludeVMName -ne "") {
        $all_vms = $all_vms | Where-Object { $_.Name -match $IncludeVMName }  
    }
    
    #Tags
    if ($ExcludeVMTag -ne "") {
        $all_vms = $all_vms | Where-Object { (-not $_.tags) -or ($_.tags.split(";") -notmatch $ExcludeVMTag) } 
    }
    
    if ($IncludeVMTag -ne "") {
        $all_vms = $all_vms | Where-Object { ($_.tags) -and ($_.tags.split(";") -match $IncludeVMTag) }
    }
    #End Filter

    $total_vms = $null
    $online_vms = $null
    $offline_vms = $null
    $total_vms = ($all_vms | Measure-Object).count
    $online_vms = ($all_vms | Where-Object { $_.status -eq "running" } | Measure-Object).count
    $offline_vms = ($all_vms | Where-Object { $_.status -eq "stopped" } | Measure-Object).count

    $xmlOutput += "
<result>
<channel>VMs Total</channel>
<value>$total_vms</value>
<unit>Count</unit>
</result>
<result>
<channel>VMs Online</channel>
<value>$online_vms</value>
<unit>Count</unit>
</result>
<result>
<channel>VMs Offline</channel>
<value>$offline_vms</value>
<unit>Count</unit>
</result>"
}

#text exists = problems found
if ($OutputText -ne "") {
    $xmlOutput += "<text>$OutputText</text>"
}

else {
    $xmlOutput += "<text>Version=$($version.ToData().version)</text>"
}

$xmlOutput += "</prtg>"

Write-Output $xmlOutput


<#
root@pam!prtg=a6cdfa39-2d5b-4077-946c-e52aabbc2565

VALUE: root@pam!test=cbd47bed-534e-4c8e-a793-5c943691f587
SECRET: cbd47bed-534e-4c8e-a793-5c943691f587
USER@REALM!TOKENID=UUID

Connect-PveCluster -HostsAndPorts 192.168.190.191:8006,192.168.190.192 -SkipCertificateCheck -ApiToken root@pam!qqqqqq=8a8c1cd4-d373-43f1-b366-05ce4cb8061f
$ticket = Connect-PveCluster -ApiToken a6cdfa39-2d5b-4077-946c-e52aabbc2565 -SkipCertificateCheck -HostsAndPorts 192.168.178.240:8006

#>
