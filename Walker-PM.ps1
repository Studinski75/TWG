<#PSScriptInfo
.VERSION 1.0.2024.1211
.COPYRIGHT 2020-2024
.DESCRIPTION Walker Preventive Maintenance script
.AUTHOR tcolumb@thewalkergroup.com
.COMPANYNAME The Walker Group, Inc.
.TAGS PM, Preventive Maintenance, Inventory, Domain Checks, Server Details
.GUID 235d800e-5262-4044-899b-1ec3cd350cd3
.LICENSEURI
.PROJECTURI
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.PRIVATEDATA

───────────────────────────────────────────────────────────
#region 🔰🔰 IDEAS 🔰🔰 


################### 2024-12-11 MJS: 3rd Party Browser matching not working for FireFox


### 2024-09-16 AJG: List of users "Hidden from GAL" but if also disabled issue warning, check for Exchange Schema
$Schema = Get-ADObject -SearchBase (Get-ADRootDSE).schemanamingcontext -filter 'name -like "ms-Exch-Schema-Version-Pt"' -Property *
# https://eightwone.com/references/schema-versions/
if ( $Null -eq $Schema ) { ShowWarning "AD Schema has not been extended for Exchange" }
else { $Schema.RangeUpper
       $DisabledUsers = Get-ADUser -Filter {(mail -like "*") -and (enabled -eq $false)} -Properties * | Select-Object * -ExcludeProperty *cert* | Sort-Object Name
       $HideGAL = $DisabledUsers | Where-Object { "msExchHideFromAddressLists" -in $_.PropertyNames } 
       $HideGAL | Format-Table Name, Mail, Enabled, Modified, Description, msexchhide*, *
     }    ### Null Schema

### 2024-06-12 AJG: Detect orphaned DHCP servers

### Send email via 365
https://www.gitbit.org/course/ms-500/blog/how-to-send-emails-through-microsoft-365-from-powershell-injifle8u
https://office365itpros.com/2024/06/17/teams-post-to-channel-workflow/


### Check SPF record for more than 10 includes, also provide suggested flattening
$SPFIncludes = (Resolve-DnsName $EmailDomain -Type TXT -Verbose -Server $DNSGood[0] ).Strings -match "^v=spf" -split " " -imatch "^include:" | ForEach-Object { ($_ -split ":")[-1] }
$SPFIncludes | Format-Table
$SPFIncludes | ForEach-Object { (Resolve-DnsName $_ -Type TXT -Server $DNSGood[0]).Strings | Where-Object { $_ -match "^v=spf1" }  }

### Check "FMS Users" group in AD - Warn on disabled accounts, last logon over 3 months
### and maybe active users not in the FMS group?

### WinGet updates available
get-wingetPackage | where { $_.IsUpdateAvailable } | Sort-Object Name

### Verify latest Windows major updates
$InstalledUpdates = Invoke-Command -Session $ServersOnlineSessions `

                                   -ScriptBlock { Try { Get-WUHistory -Last 10 | Where-Object {     $_.title -match "[0-9]{4}.*?Cumulative\b"  `
                                                                                                -or $_.title -match "[0-9]{4}.*?Servicing Stack\b" `
                                                                                                -or $_.title -match "[0-9]{4}.*?NET Framework\b"     } 
                                                      } Catch { }
                                                } 

$InstalledUpdates | Sort-Object PSComputerName, KB | Format-Table pscomputername, date, result, kb*, title

### Check for SharePoint Servers
$SPServer = $ServersInventory | ? { $_.name -like "Microsoft SharePoint Server*" -and $_.ProviderName -eq "Programs" } | sort pscomputername -Unique | select -ExpandProperty PSComputername
etsn $SPServer -EnableNetworkAccess -Authentication Credssp -Credential (Get-Credential)
add-pssnapin Microsoft.SharePoint.PowerShell
get-spfarm | fl * ; get-spsite

### # 2024-04-05 TEC: Use new INI file to perform various checks/test that cannot be programitcally identified otherwise (ie not in AD or local WMI objects)
### # Check SPF/DKIM/DMARC for "OtherDomains"
### # Include additional public DNS record checks: MX,NS,SOA for "OtherDomains"
### $TestOD = $ini.OtherDomains.Values | ForEach-Object { Resolve-DNS }
### # Test http response to local/public sites/services
### $TestHTTP = $ini.HTTPTests.Values | ForEach-Object { iwr "$_" -UseBasicParsing -UseDefaultCredentials }

### 2024-01-11 TEC: Alert on GPO's without any links
### [2023-02-02 AJG] # settings in gpos, security permission etc?
# https://adamtheautomator.com/powershell-export-gpo/
# $GPOXML = ( $GPO | ForEach-Object { [xml]( Get-GPOReport $_.DisplayName -ReportType Xml ) } )
# $GPOXML | Select-Object @{n="Name"; e={$_.GPO.Name}} , @{n='OULinks'; e={$_.GPO.LinksTo.SOMPath -Join ", "}} 
# $GPOXML[0].GPO.SecurityDescriptor.Permissions.TrusteePermissions.trustee.name."#text"

### AngryIP scan
Start-Process "ipscan.exe" -ArgumentList "-f:range 10.10.20.0 10.10.20.255 -o TRDW-IPScan-10-10-20-0-C.csv -s -q" -WorkingDirectory 'C:\Program Files\Angry IP Scanner\' -WindowStyle Hidden

### Check for SMB over QUIC
# https://4sysops.com/archives/windows-server-2025-will-support-smb-over-quic-in-all-editions/
# using Get-SmbServerConfiguration


<# ─────────────────────────── #
### Get primary web site SSL cert details
# Import the necessary .NET class
Add-Type -TypeDefinition @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    { public static void Ignore()
      { ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true; }
    }
"@

[ServerCertificateValidationCallback]::Ignore()            # Call the Ignore method
$req = [Net.WebRequest]::Create("https://$www")            # Create a WebRequest to the site

try { $response = $req.GetResponse() }                     # Get the response from the server
finally { if ($response -ne $null) { $response.Close() } } # Ensure the response stream is closed 

$cert = $req.ServicePoint.Certificate                      # Get the SSL certificate from the request

$req.Address.AbsoluteURI
$Cert | Format-List Subject, Issuer, @{n='DateIssued'; e={$_.GetEffectiveDateString()} }, @{n='ExpirationDate'; e={$_.GetExpirationDateString()} }



<# Sophos status #
# https://community.sophos.com/sophos-central/f/discussions/131875/endpoint-agent-wmi-powershell
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\Health\Status

0 = Service OK
1 = Service is Stopped

For entry "health"
1 = Green
2 = Medium/yellow
3 = Red

<# ─────────────────────────── #
## Windows Defender is installed
# $ServersOnlineSessions | ForEach-Object { Invoke-Command -computer $_.computername -ScriptBlock `

$ADComputers[1..4] | Where-Object { $_.Enabled } | ForEach-Object { #Try { 
Invoke-Command -Computer $_.DNSHostName -ScriptBlock `
{ $D = Try { Get-WindowsFeature Windows-Defender* -ErrorAction SilentlyContinue } Catch { [PSCustomObject]@{ InstallState = "Get-WindowsFeature not supported" } }
  $S = Try { Get-Package "Sophos*Agent*" -ErrorAction SilentlyContinue }          Catch { [PSCustomObject]@{ InstallState = "Get-Package not supported"        } }
  if ( $Null -eq $S ) { $S = [PSCustomObject]@{ InstallState = "Not Installed" }  }
  
  [PSCustomObject]@{ PSComputerName       = "$ENV:ComputerName"
                     Defender             = $D
                     DefenderInstallState = $D.InstallState
                     Sophos               = $S 
                     SophosInstallState   = $S.InstallState }

} -ErrorAction SilentlyContinue -AsJob -JobName "Defender-$($_.DNSHostName)" | Out-null }
# Catch { $Null }   }

$WinDefend = Receive-Job "Defender-*" -Wait -AutoRemoveJob | Where-Object { $_.State -ne "Failed" } | Select-Object * -ExcludeProperty RunspaceID, PSSourceJobInstanceID
Get-Job "Defender-*" | Remove-Job -Force

$WinDefendInstalled = $WinDefend | Where-Object { $_.DefenderInstallState -eq "Installed" } | Sort-Object pscomputername -Unique 
if ( $WinDefendInstalled.Count -eq 0 ) { Write-Output "Windows Defender not installed" }
Else { $WinDefendAndSophos = $WinDefendInstalled | Where-Object { $_.SophosInstallState -eq "Installed" }
       if ( $WinDefendAndSophos.Count -ge 1 ) { ShowWarning "Windows Defender and Sophos installed" $WinDefendAndSophos.PSComputerName -TrimDomain -ShowCount }
       $WinDefendInstalled | Format-Table -Wrap PSComputerName, SophosInstallState `
                                                              , @{n='SophosName';           e={ $_.Sophos.Name           } } `
                                                              , @{n='SophosVersion';        e={ $_.Sophos.Version        } } `
                                                              , DefenderInstallState `
                                                              , @{n='DefenderDisplayName';  e={ ( $_.Defender.DisplayName | Sort-Object -Unique ) -Join "`n"  } } 
     }



<# ─────────────────────────── #
### Detect WSUS
# UseWUServer: 1=Yes, 0=No, WUServer, WUStatusServer
# AllowMUUpdateService, NoAutoUpdate
# AUOptions:
#   2: Notify before download1.
#   3: Automatically download and notify of installation1.
#   4: Automatic download and scheduled installation. This is only valid if values exist for ScheduledInstallDay and ScheduledInstallTime1.
#   5: Automatic Updates is required, but end users can configure it1.
(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue).UseWUServer


<# ─────────────────────────── #
### Auto logoff disconnected sessions
$ServersUsersDiscSessions | ? { $_.State -eq "Disc" } | ForEach-Object { Invoke-Command -ComputerName $_.PSComputername -ScriptBlock { LOGOFF $using:_.ID } }


<# ─────────────────────────── #
### Create Security Event Log custom view showing account management
https://devblogs.microsoft.com/scripting/use-custom-views-from-windows-event-viewer-in-powershell/
https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management


<# ─────────────────────────── #
######################################
# + Event logs summaries
# + Datto backup status
# + Sophos stuff
# + M365 stuff
# + Printer details ?
    Get-WmiObject Win32_Printer | ft
    Get-WmiObject Win32_TcpIpPrinterPort | FT
    Get-WmiObject Win32_PrinterDriver | FT
# + gcim win32_quickfixengineering | sort installedon -desc | format-table -autosize


<# ────────── User Profiles ───────────── #
Write-Output "$($SeparatorLine)User Profiles: "
$ServerUserProfiles = Get-CimInstance -ClassName Win32_LoggedOnUser -CimSession $ServersCIMSessions | Where-Object { $_.Antecedent.Domain -like $AD.NetBIOSName }
$ServerUserProfiles | Sort-Object PSComputerName, Antecedent -Unique | Format-Table PSComputerName, Antecedent
Write-Output "`nUser Profiles Summary: "
$ServerUserProfiles | Sort-Object Antecedent, PSComputerName | Group-Object Antecedent | Select-Object Count, Name, @{n='Servers'; e={ ($_.Group.PsComputerName.Replace(".$($AD.DNSRoot)","")).Replace("localhost",$LocalHost)  -Join ", "}}


<# ─────────────────────────── #
### Details over time:
# + Retrieve Performance Counters (Get-Counter) for:
#   - CPU Usage
#   - Page File Usage
#   - Physical Memory Total
#   - Physical Memory Avail.
#   - System Cache

<# ─────────────────────────── #
### AntiVirus application:
$av = Get-childItem -path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Security Center\Monitoring\*"
$av.PSChildName

## ══════════════════════════════ Change History ══════════════════════════════ ##
#region 🔰🔰 Change History

2024 September TEC:
+ Added warnings for server 1) NICs slower than 1Gbps; 2) VMWare driver is NOT VMXNET and 3) any NICs whose speed does not match with the majority of others and is not Gbps
+ Moved DHCP and DNS checks below IPConfig to address some errors
+ Started working on changing some jobs/invokes to Get-CIMInstance which often is faster
+ Changed CPU details to Get-CIMInstance

2024 April TEC:
+ Now deletes GPO backups over 1 year old (not the ZIP files, the actual GPO backups) 
+ Changed GPO backup ZIP to include only the past 2 days of GPO backups (instead of all)
+ Added function to read contents of custom .INI file "Walker-PM-<domain>.INI"
+ Added more details to the empty OU's list - created, modified, desc

2024 March TEC:
+ Excluded "GoggleUpdater" from the stopped services list 
+ Added functionality to track "Critical" warnings separately from general warnings - like critical disk space levels
+ Added more disk details: Physical/Virtual Disks, Partitions and Volumes
+ Added more BitLocker details including key protectors and recovery key
+ Added warning about installed 3rd party web browsers
+ Added dates of when AD Schema was updated
+ Critical warning for disk offline or not healthy

>>> Note: For older history of changes see archived, dated copies in OneDrive: \The Walker Group\Engineering - Documents\Scripting\PM Scripts\Walker-PM-yyyy-mm-dd.ps1

#>

<# Comment Based Help
    .NOTES
    The Walker Group - AD Check
    1. Run from a Domain Controller while logged in with Admin rights
    2. Must run Windows PowerShell or Windows PowerShell ISE "As Admin"
    3. start-transcript when used within the ISE will duplicate every line of output if you stop/break/debug during execution.  To avoid, run stop-transcript manually
    .SYNOPSIS
    Collect preventive maintenance data about all domain joined servers.
    .DESCRIPTION
    Walker Preventive Maintenance
    .PARAMETER
    None.
    .EXAMPLE
    .\Walker-PM.ps1
    .INPUTS
    None.
    .OUTPUTS
    1. All screen output data collected in a transcript file
    2. The transcript filename format is: DOMAINNAME-YYYY-MM-DD.TXT
    3. The contents of the transcript file will be automatically copied to the clipboard
    .ROLE
    For Network Administrators
    .FUNCTIONALITY
#>

Param( )

<# ───────── Setup and Global Variables ───────── #>
#region 🔰🔰 Variable Declarations

$global:Status     = @{ "OK" = 100 ; "Low" = 25 ; "Warning" = 10 ; "Critical" = 2 }
$global:Status     = $Status.GetEnumerator() | Sort-Object Value -Descending  ### Disk space status levels based on percent free
$OutWidth          = 210
$cpy               = [char]169      ## Lucida Console ASCII 'Copyright Sign' '©'
$diamond           = [char]9674     ## Lucida Console ASCII 'Lozenge' aka diamond "◊"
$Elipses           = [char]0x2026   ## Lucida Console ASCII 'Elipses' '…'
$RightArrow        = [char]0x2192   ## Lucida Console ASCII 'Right Arrow' '→'
$tab               = [char]9
#$DefinedAs         = [char]0x2254   ## Lucida Console ASCII 'Is Defined As (1)' '≔'
#$Hamburger         = [char]0x2261   ## Lucida Console ASCII 'Is Defined As (2)' '≡'
$SeparatorLine     = "`r`n" + ( '=' * 60 ) + "`r`n"
$OpenGrids         = $False
$global:RunStartDateTime = Get-Date
$2DaysAgo          = ($RunStartDateTime).AddDays(-2)
$ObservationWindow = 30
$30DaysAgo         = ($RunStartDateTime).AddDays(-$ObservationWindow)
$365DaysAgo        = ($RunStartDateTime).AddDays(-365)
$Unknown           = "<Unknown>"
$RunningOnAServer  = (Get-CimInstance Win32_OperatingSystem).caption -like "*Server*"
$RunningAsAdmin    = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
$Localhost         = $env:computername
$Global:WV         = @()
$Global:CV         = @()
$PSPID             = Get-Process -Id $PID 
$IsWindowsTerminal = [bool]($env:WT_Session)
$Global:TextInfo   = (Get-Culture).TextInfo
# [regex]$DNRegex    = '^(?:(?<cn>CN=(?<name>(?:[^,]|\,)*)),)?(?:(?<path>(?:(?:CN|OU)=(?:[^,]|\,)+,?)+),)?(?<domain>(?:DC=(?:[^,]|\,)+,?)+)$'
# Example: $ADFGPP.AppliesTo -match $DNRegex

enum WindowsLicenseStatus { Unlicensed = 0
                            Licensed = 1
                            OOB_Grace_Period = 2
                            Out_Of_Tolerance_Grace_Period = 3
                            Non_Genuine_Grace_Period = 4
                            Notification = 5
                            Extended_Grace = 6 }

<# ═══════ Functions ════════════════════════════════════════════════════════════════════════════════════════════════════════ #>
#region 🔰🔰 Functions

<# ─────────────────────────── #>
function Get-IniFile { <# .DESCRIPTION 
                          Imports a .INI file into a hash-table. #>
                       [CmdletBinding()]
                       Param( [Parameter(Mandatory=$True)][String]$Path )

    $ini = @{} # Create a default section if none exist in the file.
    #$section = "NO_SECTION"
    #$ini[$section] = @{}
    switch -regex -file $Path { "^\[(.+)\]$" { $section = $matches[1].Trim()
                                               $ini[$section] = @{} }
                                "^\s*([^#].+?)\s*=\s*(.*)" { $name, $value = $matches[1..2]
                                                             # Skip comments that start with semicolon:
                                                             if (!($name.StartsWith(";"))) { $ini[$section][$name] = $value.Trim() }
                              }
    }
    $ini }

<# ─────────────────────────── #>
function Convert-MasktoCIDR {
    [CmdletBinding()]
    param ( [Object] $mask )
    ### [2022-12-20 TEC] # Convert CIDR/Prefix to subnet mask
    $result = 0;
    # ensure we have a valid IP address
    [IPAddress] $ip = $mask
    $octets = $ip.IPAddressToString.Split('.')
    foreach($octet in $octets) { while (0 -ne $octet)
      { $octet = ($octet -shl 1) -band [byte]::MaxValue
        $result++ }
    } return $result
}

<# ─────────────────────────── #>
function Convert-CIDRtoMask {
    [CmdletBinding()]
    param ( [Object] $cidr )
    ### [2022-12-20 TEC] # Convert CIDR/Prefix to subnet mask
    Return [ipaddress]([math]::pow(2, 32) -1 -bxor [math]::pow(2, (32 - $cidr))-1)
}

<# ─────────────────────────── #>
function FixLocalhostName {
    <# .DESCRIPTION 
       Repalces 'localhost' with the actual host name.  Use -TrimDomain to remove the FQDN local domain name to show just the host name. #>
    [CmdletBinding()]
    Param( [Object][ref]$Object1 , [Parameter(Mandatory=$false)] [Switch]$TrimDomain = $False )
    if ( $Null -eq $Object1 ) { Return }
    ($Object1) | ForEach-Object { if ( $_.PSComputername -eq 'localhost' ) { $_.PSComputername = $LocalDNSHost } 
                                  if ( $_.Computername   -eq 'localhost' ) { $_.Computername   = $LocalDNSHost } }
    if ( $TrimDomain ) { ($Object1) | ForEach-Object { Try   {       $_.PSComputerName = $_.PSComputerName.Replace(".$($AD.DNSRoot)","") }
                                                       Catch { Try { $_.ComputerName   = $_.ComputerName.Replace(  ".$($AD.DNSRoot)","") }
                                                               Catch {  } 
                                                             } } } 
}

<# ─────────────────────────── #>
function Merge-Objects {
    [CmdletBinding()]
    param ( [Object] $Object1, [Object] $Object2 )
    $Object = [ordered] @{}
    foreach ($Property in $Object1.PSObject.Properties) { $Object += @{$Property.Name = $Property.Value} }
    foreach ($Property in $Object2.PSObject.Properties) { $Object += @{$Property.Name = $Property.Value} }
    return [pscustomobject] $Object
}

<# ─────────────────────────── #>
function ElapsedTime { param ( [Parameter(Mandatory=$false)] [Switch] $Total = $False )
    if ( $Null -eq $RunStartDateTime ) { Exit }
    $TX = (New-TimeSpan -Start $RunStartDateTime -end (Get-Date) )
    if ( $Total ) { Write-Host "Total run time:  $($TX.ToString("hh\:mm\:ss"))" -BackgroundColor White -ForegroundColor DarkBlue }
    Else { Write-Host "$diamond Elapsed run time to this point:  $($TX.ToString()) $diamond" -BackgroundColor White -ForegroundColor DarkBlue }
}  ## func

<# ─────────────────────────── #>
function ShowInfo { param ([String] $Message,
                           [Parameter(Mandatory=$false)] [Switch] $NoTime = $False )
    Write-Host "$diamond $Message" -ForegroundColor Yellow
    if ( -not $NoTime ) { ElapsedTime }
}  ## func Info

<# ─────────────────────────── #>
function ShowWarning { param ([String] $Message,
                              [Parameter(Mandatory = $false)] $Object ,
                              [Parameter(Mandatory = $false)] [Int] $Max = 10 ,
                              [Parameter(Mandatory = $false)] [String] $JoinString = ', ' ,
                              [Parameter(Mandatory = $false)] [Switch] $NoMax = $False ,
                              [Parameter(Mandatory = $false)] [Switch] $ShowCount = $False ,
                              [Parameter(Mandatory = $false)] [Switch] $BlankIfZero = $False ,
                              [Parameter(Mandatory = $false)] [Switch] $Critical = $False ,
                              [Parameter(Mandatory = $false)] [Switch] $TrimDomain )
  $xy = "" ; $C = ""
  if ( $BlankIfZero -and ($Null -eq $Object -or $Object.Count -eq 0 ) ) { Return }
  if ( $Null -ne $Object ) {
   if ( $Null -ne $Object -and $Object.Count -gt 0 -and $TrimDomain ) { $Object = $Object.Replace(".$($AD.DNSRoot)","") }
   if ( $ShowCount ) { $C = "($($Object.Count)) " }
   if ( $Object.Count -le 1 ) { $xy = $Object } Else { if ( $null -ne $Object -and $NoMax -eq $true  ) { $xy = $Object -join $JoinString }
                                                       if ( $Null -ne $Object -and $NoMax -eq $false ) { $xy = $Object[0..($Max - 1)] -join $JoinString 
                                                       if ( $Object.Count - $Max -gt 1 ) { $xy = "$xy ... +$($Object.Count - $Max) more" } }
                                                     }   ## else count  
   if ( $xy -ne "" ) { $xy = ": $xy" }
  }   ## Object not null
  if ( $Critical ) { Write-Warning "! $($C)$($Message)$($xy)" -WarningAction Continue -WarningVariable +Global:CV -ErrorAction SilentlyContinue }
              Else { Write-Warning   "$($C)$($Message)$($xy)" -WarningAction Continue -WarningVariable +Global:WV -ErrorAction SilentlyContinue }
}  ## func Warning

<# ─────────────────────────── #>
function Get-IPConfigAll { ## [CmdletBinding()]
 ## Need to convert to use CIMSesssions to avoid a PSSession deserialiation bug that on occassion produces an unsuppresable error message
      
 $NetProfile = Try { Get-NetConnectionProfile -ErrorAction SilentlyContinue } Catch { $Null }

 if ( $Null -ne $NetProfile ) {
    $NetProfile | ForEach-Object {
      
      $NetIPConfig  = Try { Get-NetIPConfiguration     -Detailed -InterfaceAlias $_.InterfaceAlias -ErrorAction SilentlyContinue } Catch { }
      $NetIPAddress = Try { Get-NetIPAddress           -InterfaceAlias $_.InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue } Catch { }
      $DNSClient    = Try { Get-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue } Catch { }

      @{ ComputerName = "$ENV:COMPUTERNAME"
         ProfileName  = $_.Name
         NetProfile   = $_
         NetIPConfig  = $NetIPConfig
         NetIPAddress = $NetIPAddress
         DNSClient    = $DNSClient
       }  ## @

     }  ## foreach
  }  ## if
  Else {
         $ipc = (IPCONFIG /ALL) -split '`n'
         $ipc = for ($x=0; $x -lt $ipc.Length; $x++ ) { if ( $ipc[ $x ] -ne '' ) { $ipc[ $x ] } }
         $IP = ($ipc -like "*IP*Address*")[-1]
         $GW = ($ipc -like "*Default Gateway*")[-1]
         $SM = ($ipc -like "*Subnet Mask*")[-1]

         @{ ComputerName = "$ENV:COMPUTERNAME"
            ProfileName  = "<Unknown>"
            NetIPConfig  = $ipc
            NetIPAddress = ( $IP.Substring($IP.LastIndexOf(':')+2) ).Replace('(Preferred)', '')
            DefGW        = $GW.Substring($GW.LastIndexOf(':')+2)
            SubnetMask   = $SM.Substring($SM.LastIndexOf(':')+2)
          }  ## @
  }
}  ## Function Get-IPConfigALL


<# ─────────────────────────── #>
function Test-PrivateIP {
    <#
        .SYNOPSIS            Use to determine if a given IP address is within the IPv4 private address space ranges.
        .DESCRIPTION         Returns $true or $false for a given IP address string depending on whether or not is is within the private IP address ranges.
        .PARAMETER IP        The IP address to test.
        .EXAMPLE             Test-PrivateIP -IP 172.16.1.2
        .EXAMPLE             '10.1.2.3' | Test-PrivateIP
    #>
    param( [parameter(Mandatory,ValueFromPipeline)]
           [string]
           $IP
         )

    process {
        if ($IP -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)') { $true }
        else { $false }
    }
}

<# ══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════ #>
#region 🔰🔰 Folder

<# ───────── If the current folder is anything under C:\Windows\ then change to root\Walker\ OR the current user's profile documents directory ───────── #>
if ( (Get-Location).Path -like "$env:SystemRoot*" )
{ $Walker = "$ENV:SystemDrive\Walker\"
  if ( Test-Path -Path $Walker ) { Push-Location -Path $Walker }
  else { Push-Location "$env:USERPROFILE\Documents" } }

$ThisScriptFile = $PSCommandPath
$ThisScriptFileVersion = Test-ScriptFileInfo -Path $ThisScriptFile -ErrorAction SilentlyContinue
$ThisScriptFileVersion | Format-List Description, Version, CompanyName

if ( -Not $RunningAsAdmin ) { ShowWarning "Insufficient permissions! Run this PowerShell script as an administrator." ; Exit }

<# ══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════ #>
#region 🔰🔰 Domain Details

<# ───────── Domain Details ───────── #>
$global:RootDSE  = Get-ADRootDSE -Properties *
if ( $Null -eq $RootDSE ) { ShowWarning "Unable to get AD Root Directory Service" ; Return }
$global:AD       = Get-ADDomain          ## Domain Info - Exit if no domain found/accessible
if ( $Null -eq $AD )      { ShowWarning "Unable to get AD Domain" ; Return }
$global:ADForest = Get-ADForest    ## Forest info
$LocalDNSHost    = "$Localhost.$($ad.DNSRoot)"
$global:IsAADDC  = $AD.ComputersContainer -like "OU=AADDC*"
if ( $IsAADDC ) { ShowInfo "Detected 'Azure AD Domain Services (AADDS)'" -NoTime }

<# ───────── Start background jobs ───────── #>
Write-Information "Starting background jobs ..." -InformationAction Continue

### ADUsers
$JobADUsers     = Start-Job -Name GetADUsers     -ScriptBlock { Get-ADUser     -Filter * -Properties * | Select-Object * -ExcludeProperty *cert* | Sort-Object Name }
$JobADComputers = Start-Job -Name GetADComputers -ScriptBlock { Get-ADComputer -Filter * -Properties * | Select-Object * -ExcludeProperty *cert* | Sort-Object Name }

### DNS Servers
$DNS = Resolve-DnsName $AD.DNSRoot -Type ns | Where-Object { $_.type -eq "A" }

$DNS | ForEach-Object {
 $DNSHost = $_.Name
 if ( "$env:computername.$env:USERDNSDOMAIN" -eq $DNSHost )  { $DNSHost = "localhost" }
 Invoke-Command -ComputerName $DNSHost -ScriptBlock { try { Get-DnsServerForwarder -ErrorAction SilentlyContinue } Catch { } } -ErrorAction SilentlyContinue -AsJob -JobName "DNS-Forward-$($DNSHost)" | Out-Null
}

$DNS | ForEach-Object {
 $DNSHost = $_.Name
 if ( "$env:computername.$env:USERDNSDOMAIN" -eq $DNSHost )  { $DNSHost = "localhost" }
 Invoke-Command -ComputerName $DNSHost -ScriptBlock { try { Get-DnsServerScavenging -ErrorAction SilentlyContinue } Catch { } } -ErrorAction SilentlyContinue -AsJob -JobName "DNS-Scavenge-$($DNSHost)" | Out-Null
}

$DNS | ForEach-Object {
  $DNSHost = $_.Name
  if ( "$env:computername.$env:USERDNSDOMAIN" -eq $DNSHost )  { $DNSHost = "localhost" }
  Invoke-Command -ComputerName $DNSHost -ScriptBlock { try { Get-WinEvent -MaxEvents 2 `
                                                             -FilterHashtable @{ LogName = "DNS Server" 
                                                                                 ID = 2501, 2502 } -ErrorAction SilentlyContinue | Sort-Object timecreated -Descending | Select-Object -First 1 } 
    Catch { } } -ErrorAction SilentlyContinue -AsJob -JobName "DNS-EventLog$($DNSHost)" | Out-Null
 }
 
$DNSZones = $DNS | ForEach-Object {
 $DNSHost = $_.Name
 if ( "$env:computername.$env:USERDNSDOMAIN" -eq $DNSHost )  { $DNSHost = "localhost" }
 Invoke-Command -ComputerName $DNSHost -ScriptBlock { try { Get-DnsServerZone -ErrorAction SilentlyContinue } Catch { } } -ErrorAction SilentlyContinue -AsJob -JobName "DNS-Zones-$($DNSHost)" | Out-Null
}

### ADGroups
$JobADGroups = Start-Job -Name GetADGroups -ScriptBlock {
  Get-ADGroup -Filter { ( Name -ne "Domain Users" -and Name -ne "Domain Computers" ) } -Properties * | `
  Select-Object *, @{ Name = 'Protected'; Expression = { ( $_.ProtectedFromAccidentalDeletion ) } } `
                 , @{ Name = 'Critical' ; Expression = { $_.isCriticalSystemObject } } `
                -ExcludeProperty *cert*
  }

<# ───────── Start this early so we can do a long running background task to ping servers ───────── #>
$ServersInAD = (Get-ADComputer -Filter 'operatingsystem -like "*server*"' -Properties * ) | Select-Object * -ExcludeProperty *Certificate* | Sort-Object DNSHostName

<# ───────── Determine Servers that Online / Responding ───────── #>
Clear-Variable *PING -ErrorAction SilentlyContinue
$ServersWithIP = $ServersInAD | Where-Object { $null -ne $_.IPv4Address -and $_.Enabled -eq $True }
$OriginalProgressPreference = $Global:ProgressPreference
$Global:ProgressPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

<# ───────── Start background PING ───────── #>
### PING all servers
$HasTestNet = Get-Command Test-NetConnection -ErrorAction SilentlyContinue

if ( $null -eq $HasTestNet )
{ $JobPing = Start-Job -Name PING1-AllServers -ScriptBlock {
  $Using:ServersWithIP | ForEach-Object { Test-Connection -ComputerName $_.DNSHostName -Count 2 `
                   -ErrorAction SilentlyContinue -WarningAction SilentlyContinue  }
  }
}
Else { $JobPing = Start-Job -Name PING2-AllServers -ScriptBlock { ($Using:ServersWithIP).DNSHostName `
       | Test-NetConnection -InformationLevel Detailed -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 
         Write-Progress -Completed -Activity "PING job completed" }
}
if ( $null -eq $JobPing ) { Write-Warning "PING background job may have failed" }

<# ───────── Set window width so the TXT file output is not truncated ───────── #>
$pshost = Get-Host
if ( $pshost.name -notlike "*Studio Code*" )
{ $pswindow = $pshost.ui.rawui
  $newsize = $pswindow.buffersize
  $newsize.height = 3000
  $newsize.width = $OutWidth
  $pswindow.buffersize = $newsize
  Write-Information "Screen width set to $OutWidth" -InformationAction Continue }

<# ───────── Check for NTP module, install if not already ───────── #>
$NTP = Get-InstalledModule NTPTime -ErrorAction SilentlyContinue
if ($null -eq $NTP ) { Write-Information "Installing NTPTime module ..."
                       Install-Module NTPTime -Scope AllUsers -Confirm:$False -ErrorAction SilentlyContinue
                       $NTP = Get-InstalledModule NTPTime -ErrorAction SilentlyContinue }
if ($null -eq $NTP ) { $NTP = Get-Command Get-NTPTime }
if ($null -eq $NTP ) { ShowWarning "Failed to install NTPTime module - cannot verify clock" }

<# ───────── Capture all output to a transcript file ───────── #>
$PMOutputSubfolder  = '.\Walker PM\'
$FileNameDomainDate = "$($AD.NetBIOSName)-$($RunStartDateTime.ToString('yyyy-MM-dd'))"
$FileNameRoot       = "$PMOutputSubfolder$FileNameDomainDate"
$TranscriptFile     = "$FileNameRoot.txt"
$INIFilename        = "Walker-PM-$($AD.NetBIOSName).ini"
Start-Transcript -Path $TranscriptFile
# Write-Output $RunStartDateTime

<# ───────── Display current script info including version ───────── #>
Write-Output "`nScript file name: $ThisScriptFile"
Write-Output "Script version:   $($ThisScriptFileVersion.Version)"
Write-Output "`nRan on:           $env:computername.$env:userdnsdomain"
Write-Output "Host:             $($PSPID.Description), $($PSPID.Name), $($Host.Name) ($($Host.Version.ToString()))"
Write-Output "Host EXE:         $((Get-Process -Id $PID).Path)"
if ($IsWindowsTerminal) { Write-Output "Running under Windows Terminal" } 

if ( Test-Path -Path $INIFilename ) { $INI = Get-IniFile $INIFilename } Else { $INI = $Null }
<# ───────── Domain Details ───────── #>
Write-Output "`r`nDomain '$($AD.NetBIOSName)':"
$AD | Format-List DNSRoot, Forest, DomainMode, ChildDomains, PDCEmulator, *Master

Write-Output "`r`nForest '$($ADForest.Name)':"
$ADForest | Format-List ForestMode, *Master, @{n='Domains'; e={$_.Domains -Join ", "}}, @{n='Sites'; e={$_.Sites -Join ", "}}, @{n='UPNSuffixes'; e={$_.UPNSuffixes -Join ", "}}

$schema = Get-ADObject -SearchBase ((Get-ADRootDSE).schemaNamingContext) -SearchScope OneLevel -Filter * `
                       -Property objectClass, name, whenChanged, whenCreated `
                     | Select-Object objectClass, name, whenCreated, whenChanged, @{name="event";expression={($_.whenCreated).Date.ToShortDateString()}} `
                     | Sort-Object whenCreated

Write-Output "`r`nDomain '$($AD.NetBIOSName)' Major AD Schema change dates:"
$schema | Group-Object event | Format-Table Count, Name, Group -AutoSize

<# ───────── Group Policies (GPO) ───────── #>
$GPO = Try { Get-GPO -All -ErrorAction SilentlyContinue | Sort-Object DisplayName } Catch { }
If ( $Null -ne $GPO ) { Write-Output "`r`nList of Group Policy Objects (GPO):"
                        $GPO | Sort-Object GPOStatus, DisplayName | Format-Table -AutoSize DisplayName, GPOStatus, *Time, @{Name='WMI Filter'; Expression={ $_.WMIFilter.Name } }, Description -GroupBy GPOStatus
                        
                        $GPODisabled = $GPO | Where-Object { $_.GPOStatus -eq 'AllSettingsDisabled' }
                        if ( $GPODisabled.Count -gt 0 ) { ShowWarning "GPO's have All Settings disabled" $GPODisabled.DisplayName -ShowCount } 
                        $GPOModifiedRecently = $GPO | Where-Object { $_.modificationtime -gt $30DaysAgo }
                        if ( $Null -ne $GPOModifiedRecently ) { ShowWarning "GPO's have been modified in the past $($ObservationWindow) days"  $GPOModifiedRecently.DisplayName -ShowCount } 

                        $OUGPOList = foreach ( $OU in $OUsWithLinkedGPO )
                                     { # Write-Output "`nOU: $OU.Name"
                                       foreach ( $OUGPO in $OU.LinkedGroupPolicyObjects ) 
                                       { $ix = $GPO.path.IndexOf( $OUGPO ) 
                                         $GPO[$ix] | Select-Object *, @{n='OU'; e={$OU.DistinguishedName} }
                                       }
                                     }
                        Write-Output "`nOUs with Linked Group Policy Objects (GPO):"
                        # $OUGPOList | Format-Table -AutoSize -Wrap OU, DisplayName, GPOStatus, ModificationTime, WMIFilter, Description 
                        $OUGPOList | Group-Object OU | Select-Object Count, Name, @{n='GPO'; e={$_.Group.DisplayName -Join ", " }} | Format-Table -AutoSize -Wrap 

                      }   # GPO not null
Else { ShowWarning "GPO management tools are not installed.  Run 'Add-WindowsFeature -Name GPMC' " }

<# ───────── OU's with GPO's linked ───────── #>
# $OUsWithLinkedGPO = Get-ADOrganizationalUnit -filter * -searchbase "$($AD.DistinguishedName)" -SearchScope Subtree | Where-Object { $_.LinkedGroupPolicyObjects.Count -gt 0 }
$OUsWithLinkedGPO = Get-ADOrganizationalUnit -filter * | Where-Object { $_.LinkedGroupPolicyObjects.Count -gt 0 }

<# ───────── Empty OUs ───────── #>
Write-Output "`r`nList of Empty OU's:"
$EmptyOUs = Get-ADOrganizationalUnit -Filter * -Properties * | Where-Object { -not (Get-ADObject -Filter * -SearchBase $_.DistinguishedName -SearchScope OneLevel) }
if ( $Null -eq $EmptyOUs ) { Write-Output "No empty OU's found" }
Else { $EmptyOUs | Format-Table -AutoSize Name, Modified, Created, DistinguishedName, Linked*, Description 
       ShowWarning "Empty OU's" $EmptyOUs.Name -ShowCount }

<# ───────── GPO Backup ───────── #>
If ( $Null -ne $GPO ) { $GPOBackupFolder   = ".\GPO Backup"
                        $GPOBackupFilePath = Resolve-Path $PMOutputSubfolder 
                        $GPOBackupFile     = "$FileNameDomainDate-GPOBackup.zip"
                        if ( -not ( Test-Path $GPOBackupFolder ) ) { New-Item -Path $GPOBackupFolder -ItemType Directory | Out-Null }
                        $GPOBackupFolder   = Resolve-Path ".\GPO Backup"
                        Start-Job -ScriptBlock { # Get-ChildItem -Path "$Using:GPOBackupFolder" -Recurse -Depth 50 | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                                                 # Get-ChildItem -Path "$Using:GPOBackupFolder" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-($Using:ObservationWindow)) } | Get-ChildItem -Recurse -Depth 50 | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                                                 Get-ChildItem -Path "$Using:GPOBackupFolder" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-2) } | Get-ChildItem -Recurse -Depth 50 | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                                                 $Using:GPO | Backup-GPO -Path $Using:GPOBackupFolder -Comment "Walker-PM Automated GPO Backup - $Using:FileNameDomainDate" | Out-Null
                                                 Compress-Archive -Path $Using:GPOBackupFolder -DestinationPath "$Using:GPOBackupFilePath$Using:GPOBackupFile" -CompressionLevel Optimal -Force | Out-Null
                                               } -Name 'GPOBackup' | Out-Null
                      }   # GPO not null

<# ───────── Domain Controllers ───────── #>
$DomainControllers = Get-ADDomainController -Filter * | Sort-Object Site, Hostname

Write-Output "`r$( ($DomainControllers | Measure-Object).Count ) Domain Controllers listed in AD:"
$DomainControllers = $DomainControllers | Select-Object *, @{ n = 'FDMode' ; e = { (($_.OperatingSystem -replace "\S*\s*$").Replace(' ', '' )).Replace('Server', '') } } `
                                                         , @{ n = 'IPType' ; e = { If (Test-PrivateIP $_.IPv4Address) { 'Private' } Else { 'Public' } } }
$DomainControllers | Format-Table -AutoSize Hostname, IPv4address, IPType, Enabled, isGlobalCatalog, Site, Forest, OperatingSystem, OperatingSystemVersion,*Port

$DCPublic = $DomainControllers | Group-Object IPType | Where-Object { $_.Name -eq 'Public' }
if ( $DCPublic.Count -gt 0 ) { ShowWarning "Domain Controllers have public IP Addresses" $DCPublic.Group.HostName -ShowCount -TrimDomain }

$DomainControllersOnline = $DomainControllers.Hostname | Test-NetConnection -ErrorAction SilentlyContinue | Where-Object { $_.pingsucceeded }
Write-Progress -Completed -Activity "Domain Controllers PING completed"
If ( $DomainControllersOnline.GetType().IsArray ) { $DCtoUse = $DomainControllersOnline[0].ComputerName } else { $DCtoUse = $DomainControllersOnline.ComputerName }
if ( @($DomainControllers).Count -ne @($DomainControllersOnline).Count ) { ShowWarning "$(@($DomainControllers).Count - @($DomainControllersOnline).Count ) Domain Controllers are offline - online DCs are" $DomainControllersOnline -NoMax }

<# ───────── Run a complete DCDiag ───────── #>
ShowInfo "Starting DCDiag job ..."
if ( $DCtoUse -eq $LocalDNSHost ) { Start-Job -ScriptBlock { dcdiag.exe /e /v /i /c /test:DNS } -Name "DCDiag-$($AD.NetBIOSName)"  }
Else { Invoke-Command -ComputerName $DCtoUse -ScriptBlock { dcdiag.exe /e /v /i /c /test:DNS } -AsJob -JobName "DCDiag-$($AD.NetBIOSName)" }

$MinFDMode = ( $DomainControllers | Sort-Object fdmode | Group-Object fdmode -NoElement )[0].Name
$MinFDMode = if ( $MinFDMode -in ('Windows2019', 'Windows2022') ) { 'Windows2016' } Else { $MinFDMode }   ## https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels
$ADFMode = if ( [int]$ADForest.ForestMode -eq 7 ) { 'Windows2016Forest' } Else { $ADForest.ForestMode }
$ADDMode = if ( [int]$AD.DomainMode -eq 7 ) { 'Windows2016Domain' } Else { $AD.DomainMode }
If ( "$($MinFDMode)Forest" -gt $ADFMode ) { ShowWarning "Forest Mode should be raised from '$($ADFMode)' to '$($MinFDMode)'" }
If ( "$($MinFDMode)Domain" -gt $ADDMode ) { ShowWarning "Domain Mode should be raised from '$($ADDMode)' to '$($MinFDMode)'" }
$HeldBackBy =  $DomainControllers | Where-Object { $_.FDMode -lt 'Windows2016' } 
if ( $MinFDMode -ne 'Windows2016' ) { ShowWarning "Forest/Domain Mode ($($ADFMode)/$($ADDMode)) is not the latest and is being held back by" $HeldBackBy.Name -ShowCount }

if ( $OpenGrids ) { $DomainControllers | Out-GridView -Title "$($AD.DNSRoot) Domain Controllers" }

<# ───────── Check for LAPS in AD - https://adsecurity.org/?p=3164 ───────── #>
# Domain Functional Level must be 2016 and this Schema attribute must be present
# https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addomainmode?view=windowsserver2022-ps
if ( $AD.DomainMode -lt 7 ) { ShowInfo "NOTE: Domain '$($AD.Name)' is not LAPS capable because the functional level is $($AD.DomainMode)" -NoTime }
## Server 2016 = 10.0 build 14393; 2019 = build 
##elseif ( ($DomainControllers.OperatingSystemVersion -split "\(" -split "\)")[-2] -gt 14393 ) { }
Else { $LAPSSchema = try { get-adobject -ErrorAction SilentlyContinue -Filter { Cannonicalname -eq "CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,$($AD.DistinguishedName)" } } Catch { } 
       if ( $ADForest.ForestMode -eq 7 -and $Null -eq $LAPSSchema ) { ShowInfo "NOTE: Domain is LAPS capable, but is not configured" -NoTime }
       if ( $ADForest.ForestMode -eq 7 -and $Null -ne $LAPSSchema ) { ShowInfo "NOTE: Domain is LAPS capable and is configured" -NoTime }
}   # if domain mode

<# ───────── IDEA from 2022-02-02 - Matthew J. Studinski - Checking to see is AD replication was upgraded
https://techcommunity.microsoft.com/t5/storage-at-microsoft/streamlined-migration-of-frs-to-dfsr-sysvol/ba-p/425405 #>
Write-Output "$($SeparatorLine)AD Replication Status:"
if ( $AD.PDCEmulator -eq "$env:computername.$env:USERDNSDOMAIN" )
{ $PDC = "localhost" } else { $PDC = $AD.PDCEmulator }

Invoke-Command -ComputerName $PDC -ScriptBlock { DFSRMIG /getmigrationstate } -ErrorAction SilentlyContinue | Tee-Object -Variable DFSRStatus
$DFSRStatus = $DFSRStatus.Where({ $_ -ne '' })
if ( $DFSRStatus[-1] -notlike '*Succeeded*' ) { ShowWarning "Check DFSR Migration" $DFSRStatus[-1] -ShowCount }

<# ───────── If there is more than 1 DC, check AD replication status ───────── #>
if ( @($DomainControllersOnline).count -gt 1 ) {
 
  $ADRepl = ForEach ( $DC in $DomainControllersOnline ) { Try { Get-ADReplicationPartnerMetadata -Target $($DC.ComputerName) } Catch { $Null } } 

  $ADRepl = $ADRepl | Select-Object Server, LastReplicationAttempt, LastReplicationSuccess `
                                 , @{n='LastResult'; e={$_.LastReplicationResult}}, @{n='ConsecFail'; e={$_.ConsecutiveReplicationFailures}} `
                                 , Partition, PartnerType, ScheduledSync `
                                 , @{n='PartnerHost'; e={ ((($_.Partner -split ',')[1]) -split '=')[1] }} `
                                 , * -ErrorAction SilentlyContinue

  $ADRepl | Format-Table -AutoSize PartnerHost, LastReplicationAttempt, LastReplicationSuccess, LastResult, ConsecFail `
                               , ScheduledSync, PartnerType, TwoWaySync, Writable, LastChangeUSN, Partition -GroupBy Server

  $adrep = $ADRepl | Group-Object lastresult | Where-Object { $_.Name -ne 0 }
  if ( ( $adrep | Measure-Object ).Count -ge 1 ) { ShowWarning "Possible AD Replication problems" $adrep.Group.PartnerHost -ShowCount }
}   ### More than one DC
Else { ShowWarning "There is only 1 Domain Controller online" $DomainControllersOnline.ComputerName }


<# ───────── AD Sites and Subnets ───────── #>
Write-Output "$($SeparatorLine)$($AD.DNSRoot) AD Sites and Subnets:"

$ADSites = Get-ADReplicationSite -Filter * -ErrorAction SilentlyContinue -Properties *
$ADSites | Format-Table -AutoSize @{n='Site'; e={ $_.Name } }, DistinguishedName, Modified, Created, Description

If ( $Null -ne $ADSites )
{  $SiteSubnets = $ADSites | ForEach-Object { $Site = $_
   $s = Get-ADObject -Identity $Site.DistinguishedName -Properties *
   $Subnets = $s.siteObjectBL | ForEach-Object { Get-ADObject -Identity $_ -Properties * }
   $subnets | Select-Object @{n='Site'; e={ $Site.Name } }, ObjectClass, Name, DistinguishedName, @{n='Protected'; e={$_.ProtectedFromAccidentalDeletion} } , * -ErrorAction SilentlyContinue
  }  ## each site
  $SiteSubnets | Format-Table Site, ObjectClass, Name, Created, Modified, Protected, Location, Description
}  ## not null


<# ───────── Password Policy ───────── #>
Write-Output "$($SeparatorLine)$($AD.DNSRoot) Password Policies:"

$ADPswdPolicy = @()
$ADDefaultPP = Get-ADDefaultDomainPasswordPolicy
$ADDefaultPP = $ADDefaultPP | Select-Object @{Name='Name'; Expression={"<default>"}} `
                                          , @{Name='Complex'; Expression={$_.ComplexityEnabled}} `
                                          , @{Name='Lockout'; Expression={$_.LockoutThreshold}} `
                                          , @{Name='LockoutWindow'; Expression={$_.LockoutObservationWindow}} `
                                          , LockoutDuration, M*Password* `
                                          , @{Name='PasswordHistory'; Expression={$_.PasswordHistoryCount}} `
                                          , @{n='AppliesTo'; e={"<default>"} } `
                                          , @{n='Precedence'; e={ 999 } }

$ADFGPP = Get-ADFineGrainedPasswordPolicy -Filter { Name -like '*' } -Properties * -ErrorAction SilentlyContinue
if ( $ADFGPP.Count -ge 1 ) {
  Write-Output "$($AD.DNSRoot) Fine Grained Password Policy ($($ADFGPP.Count)):`n"
  $ADFGPP = $ADFGPP |  Select-Object @{Name='Name'; Expression={$_.Name}} `
                                   , @{Name='Complex'; Expression={$_.ComplexityEnabled}} `
                                   , @{Name='Lockout'; Expression={$_.LockoutThreshold}} `
                                   , @{Name='LockoutWindow'; Expression={$_.LockoutObservationWindow}} `
                                   , LockoutDuration, M*Password* `
                                   , @{Name='PasswordHistory'; Expression={$_.PasswordHistoryCount}} `
                                   , AppliesTo, Description, Precedence
$ADPswdPolicy += $ADFGPP
}
else { Write-Output 'There are no Fine Grained Password Policies.' }

$ADPswdPolicy += $ADDefaultPP
$ADPswdPolicy | Sort-Object Precedence, Name `
              | Format-Table -AutoSize -Wrap Precedence, Name, Complex, Lockout* `
                                           , ???PasswordAge, MinPasswordLength, PasswordHistory `
                                           , @{n='AppliesTo'; e={ ($_.AppliesTo -replace '^CN=|,.*$' | Sort-Object ) -join "`n" }}

## Check for weak default password policy settings
if ( $ADDefaultPP.MinPasswordLength -lt 12 ) { ShowWarning "Min password length is $($ADDefaultPP.MinPasswordLength) but should be 12 or higher" }
if ( -not $ADDefaultPP.Complex )             { ShowWarning "Password complexity should be enabled" }
if ( $ADDefaultPP.PasswordHistory -lt 6 )    { ShowWarning "Password history is $($ADDefaultPP.PasswordHistory) but should be higher" }
if ( $ADDefaultPP.Lockout -lt 1 -or $ADDefaultPP.Lockout -gt 10 )    { ShowWarning "Password lockout is $($ADDefaultPP.Lockout) but should be between 1 and 10" }
if ( $ADDefaultPP.MaxPasswordAge.Days -gt 366 )   { ShowWarning "Max password age is $($ADDefaultPP.MaxPasswordAge.Days) but should be 1 year or less" }

<# ───────── Accurate ADGroup Details ───────── #>
### The ADGroupMembers job is the one that will likely run for the longest amount of time
### But can't run until the ADGroups job is completed which is probably completed at this point because we started it much earlier
ShowInfo "Waiting for background job '$($JobADGroups.Name)' to complete ..."
Wait-Job -Job $JobADGroups -Timeout 10 | Out-Null
$ADGroups = Receive-Job -Job $JobADGroups -Wait -AutoRemoveJob | Sort-Object Name

### This job will need more time the larger the number of AD Groups there are ###
$JobADGroupMembers = Start-Job -Name GetADGroupMembers -ScriptBlock {
  $Using:ADGroups | ForEach-Object {
  $tg = $_
  try { Get-ADGroupMember -Identity $tg.DistinguishedName | Sort-Object Name | Select-Object @{n='GroupName'; E={$tg.DistinguishedName}}, * -ErrorAction SilentlyContinue } Catch { }
  }
}

<# ───────── Figure out if Azure AD Connect is in use ───────── #>
#region 🔰🔰 Azure

## https://learn.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-version-history

$AzureADConnectHost = Get-ADUser -LDAPFilter "(|(description=*Service account for the Synchronization Service*)(description=*configured to synchronize to tenant*)(samAccountName=MSOL_*)(samAccountName=AAD_*))" `
           -Properties * `
                    | Select-Object @{ n = 'ADSyncHost' ; e = { $ix = ($_.Description).indexof('on computer ')
                                                                if ( $ix -eq -1 ) { $Unknown }
                                                                Else { (($_.Description).Substring( $ix+12 ) -split ' ')[0].replace("'","").replace(".","")  } } } `
                                  , @{ n = 'ADSyncID'   ; e = { $ix = ($_.Description).indexof(' identifier ')
                                                                if ( $ix -eq -1 ) { $Unknown }
                                                                Else { (($_.Description).Substring( $ix+12 ) -split ' ')[0].replace("'","") } } } `
                                    , * -ErrorAction SilentlyContinue

if ( $Null -eq $AzureADConnectHost ) { if ( -not $IsAADDC ) { ShowWarning "Azure AD Connect local host not found (assuming cloud only or not using Microsoft 365)" } }
Else { Write-Output "$($SeparatorLine)Local server(s) with Azure AD Connect: "
       $AzureADConnectHost | Format-Table -Wrap adsync*, samaccountname, Enabled, LastLogonDate, Created, Modified, PasswordLastSet, DistinguishedName }

if ( $AzureADConnectHost.Count -gt 1 )
 { ShowWarning "There are $($AzureADConnectHost.Count) Azure AD Sync accounts and there should only be one" ($AzureADConnectHost.ForEach( { "$($_.samaccountname) on $($_.ADSyncHost)" } ) ) -ShowCount }

<# ───────── Azure AD Sync event log analysis ───────── #>
if ( $Null -ne $AzureADConnectHost ) {

 $AzureADConnectHost | ForEach-Object {

  $hpt = Test-Connection -ComputerName $_.ADSyncHost -Count 3 -TimeToLive 4 -ErrorAction SilentlyContinue
  if ( $hpt.count -eq 0 ) { ShowWarning "Unable to connect to Azure AD Sync host \\$($_.ADSyncHost) for Account '$($_.samAccountName)" }
  Else {

   $AzureADSyncHost = $_.ADSyncHost
   $AzureADSyncConnector = Invoke-Command -ComputerName ($AzureADSyncHost.Replace($Localhost, "localhost") ) -ScriptBlock { Try { Get-ADSyncConnector } Catch { $Null } }
   FixLocalhostName $AzureADSyncConnector -TrimDomain
   $AzureADSyncConnector | Format-Table PSComputerName, Name, CreationTime, LastModificationTime, ConnectivityParameters, ListName

   $AzureADSyncEvents = Get-EventLog -ComputerName $_.ADSyncHost -LogName Application -Source "Directory Synchronization" -After $2DaysAgo
   Write-Output "Most recent AAD Sync cycle: "
   $g0 = $AzureADSyncEvents | Where-Object { $_.Message -like "*Started a new sync cycle run*" -or $_.Message -like "*Completed configured scheduler operations*" } | Select-Object -First 4
   $g0 | Format-Table InstanceID, MachineName, EntryType, @{n='Time'; e={($_.TimeGenerated).ToString('yyyy-MM-dd hh:mm:ss tt')}}, Message
   if ( $g0[0].TimeGenerated.ToShortDateString() -ne $RunStartDateTime.ToShortDateString() ) {
     ShowWarning "Last Azure AD Sync on $($g0[0].MachineName) was not today: $($g0[0].Message.Substring(0,70))... " 
    }  ## TimeGenerate is NOT today

   $g1 = $AzureADSyncEvents | Where-Object { $_.EntryType -in "Error", "Warning", "FailureAudit"  }
   if ( $g1.count -eq 0 ) {  Write-Output "AAD Sync OK since $($2DaysAgo.ToShortDateString()) " } Else {
    Write-Output "Most recent AAD Sync errors: "
    $g1 | Sort-Object InstanceID, Time | Group-Object InstanceID | Select-Object Count, @{n = 'EventID'      ; e = { $_.Name } } `
                            , @{n = 'Time'         ; e = { $e1 = $_.Group.TimeGenerated      ; $e2 = if ($e1.count -gt 1) { $e1[0] } Else { $e1 } ; $e2.ToString('yyyy-MM-dd hh:mm:ss tt')  } } `
                            , @{n = 'ComputerName' ; e = { $e1 = $_.Group.MachineName ; if ($e1.count -gt 1) { $e1[0] } Else { $e1 }      } } `
                            , @{n = 'EntryType'    ; e = { $e1 = $_.Group.EntryType   ; if ($e1.count -gt 1) { $e1[0] } Else { $e1 }      } } `
                            , @{n = 'Message'      ; e = { $e1 = $_.Group.Message     ; if ($e1.count -gt 1) { $e1[0] } Else { $e1 }      } }   |  Format-Table

     if ( $g1[0].TimeGenerated.ToShortDateString() -eq $RunStartDateTime.ToShortDateString() ) {
      ShowWarning "Azure AD Sync on $($g1[0].MachineName) has errors from today: $($g1[0].Message.Substring(0,70))... " 

    }  ## TimeGenerate is today
   }  ## $g1.count

   Write-Output "`nInventory of 'Azure' apps installed on \\$($_.ADSyncHost):"
   $ADSHost = if ( $_.ADSyncHost -eq $Localhost ) { 'localhost' } Else { $_.ADSyncHost }
   $AzureApps = Invoke-Command -ComputerName $ADSHost -ScriptBlock { Get-Package | Where-Object { $_.name -like "*Azure*" } | Sort-Object Name, Version }
   FixLocalhostName $AzureApps -TrimDomain
   $AzureApps | Format-Table -AutoSize

  }  ## $hpt
 }  ## foreach
}  ## $Null -ne $AzureADConnectHost

<# ───────── AD Groups with accurate member details ───────── #>
#region 🔰🔰 AD Groups & Users

### This section requires that both the ADGroups and ADGroupMembers jobs have completed
ShowInfo "Waiting for background job '$($JobADGroupMembers.Name)' to complete ..."
Wait-Job -Job $JobADGroupMembers | Out-Null
$ADGroupMembers = Receive-Job -Job $JobADGroupMembers -Wait -AutoRemoveJob

## Start a 3rd job to combine the group list with the members from the accurate list
$JobADGroupPlusMembers = Start-Job -Name GetADGroupsPlus -ScriptBlock {
      $Using:ADGroups | Select-Object @{ Name = 'GroupMembers' ; Expression = { $g = $_ ; $Using:ADGroupMembers | Where-Object { $_.GroupName -eq $g.DistinguishedName } } } `
                                    , * -ErrorAction SilentlyContinue `
                      | Select-Object Name, Modified, uSNChanged, Created, isCriticalSystemObject, isDeleted, GroupCategory, GroupScope `
                                    , @{ Name = 'MemberCount'  ; Expression = { ($_.GroupMembers | Measure-Object).Count } } `
                                    , @{ Name = 'MemberNames'  ; Expression = { $_.GroupMembers.Name -join ", " } } `
                                    , @{ Name = 'AuditDate'    ; Expression = { $RunStartDateTime.ToShortDateString() } } `
                                    , * -ErrorAction SilentlyContinue
}

<# ───────── AD Users ───────── #>
ShowInfo "Waiting for background job '$($JobADUsers.Name)' to complete ..."
$ADUsers = Receive-Job -Job $JobADUsers -Wait -AutoRemoveJob
$now = Get-Date

$ADUsers | ForEach-Object `
{
  $x = if ( $Null -eq $_.LastLogonDate ) { -1 } Else { New-TimeSpan -Start $_.LastLogonDate -End $now -ErrorAction SilentlyContinue } ;
  Add-Member -InputObject $_ -MemberType NoteProperty -Name 'DaysSinceLastLogon' -Value $x.TotalDays -Force
  Add-Member -InputObject $_ -MemberType NoteProperty -Name 'DaysSinceCreated'   -Value ([math]::Round((New-TimeSpan -Start $_.WhenCreated -End $now -ErrorAction SilentlyContinue).TotalDays, 0)) -Force
  Add-Member -InputObject $_ -MemberType NoteProperty -Name 'DaysSinceModified'  -Value ([math]::Round((New-TimeSpan -Start $_.WhenChanged -End $now -ErrorAction SilentlyContinue).TotalDays, 0)) -Force
  Add-Member -InputObject $_ -MemberType NoteProperty -Name 'OU'                 -Value ($_.DistinguishedName -split ",")[-3].Substring(3) -Force


  $b = Switch ( $_.DaysSinceLastLogon )
  { {$_ -le -1 -or $null -eq $_ }
                  { '  0 - (Never)'  ; Break }
    {$_ -le 14 }  { '  1 - 14 days'  ; Break }
    {$_ -le 30 }  { ' 15 - 30 days'  ; Break  }
    {$_ -le 90 }  { ' 31 - 90 days'  ; Break  }
    {$_ -le 365 } { ' 91 - 365 days' ; Break  }
    Default       { '366 - ~ days (1 year+)' }
  }
  Add-Member -InputObject $_ -MemberType NoteProperty -Name 'Bucket' -Value $b -Force

  $e = Switch ( $_ )
  { { $_.LockedOut -eq $True }        { 'Account Locked Out'     ; Break }
    { $Null -ne $_.AccountExpirationDate `
      -and (New-TimeSpan -Start $_.AccountExpirationDate -End $now).TotalDays -gt 0  } { 'Account Expired'        ; Break }
    { $_.PasswordExpired -eq $True }  { 'Password Expired'       ; Break }
    { $_.Enabled -eq $False }         { 'Account Disabled'       ; Break }
    { $_.Enabled -eq $True }          { 'Account Active/Enabled' ; Break }
    Default { $Unknown }
  }
  Add-Member -InputObject $_ -MemberType NoteProperty -Name 'AccountStatus' -Value $e -Force
}

$ADUsers = $ADUsers | Select-Object -ErrorAction SilentlyContinue                                     `
Name, DisplayName, SamAccountName, OU, Modified, DaysSinceModified ,                                  `
AccountStatus, Enabled, isCriticalSystemObject, isDeleted, AccountExpirationDate,                     `
LastLogonDate, DaysSinceLastLogon, LastBadPasswordAttempt, BadLogonCount, LockedOut,                  `
PasswordExpired, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, CannotChangePassword,    `
Bucket, LogonCount,                                                                                   `
whenChanged, uSNChanged, whenCreated, DaysSinceCreated, uSNCreated,                                   `
MemberOf, PrimaryGroup, primaryGroupID,                                                               `
AllowReversiblePasswordEncryption, AuthenticationPolicy, AuthenticationPolicySilo, CN, Description,   `
DistinguishedName, LastKnownParent, Location, ManagedBy,                                              `
ProtectedFromAccidentalDeletion, PSComputerName,                                                      `
ServiceAccount, servicePrincipalName, ServicePrincipalNames,                                          `
SID, SIDHistory, TrustedForDelegation, TrustedToAuthForDelegation, userAccountControl, *

if ( $OpenGrids ) { $ADUsers | Sort-Object Name | Out-GridView -Title "$($AD.DNSRoot) - AD Users" }
## $user | ft name, lastlogondate, bucket, dayssincelastlogon
Write-Output "`n$($SeparatorLine)User Count by Last Logon Time Frames: "
# $ADUsers | Group-Object Bucket -NoElement | Sort-Object Name | Select-Object Count, @{n='Time Frame'; e={$_.Name}}
$ADUsers | Group-Object Bucket | Sort-Object Name | Select-Object Count, @{n='Time Frame'; e={$_.Name}}, @{n='Users'; e={$_.Group.SAMAccountName -Join ', '}} | Format-Table -AutoSize -Wrap

Write-Output "`nUser Count by Account Status:"
Write-Output "`n"
## $ADUsers | Group-Object AccountStatus -NoElement | Sort-Object Name
$ADUsers | Group-Object AccountStatus | Sort-Object Name | Select-Object Count, Name, @{n='User Accounts'; e={$_.Group.SamAccountName -join ", "}} | Format-Table -AutoSize -Wrap

<# Add bullet point highlights for AD User Account properties: #>
Write-Output "`nAD User Account Proerties of note:"
$ADU1 = @()
# * 0 System Critical Object accounts
$ADU1 += $ADUsers | Where-Object { $_.IsCriticalSystemObject }  | Select-Object @{n='Tag'; e={'Critical System Object'}}, samaccountname
# * 0 Password Not Required
$ADU1 += $ADUsers | Where-Object { $_.PasswordNotRequired }     | Select-Object @{n='Tag'; e={'Password Not Required'}}, samaccountname
# * 0 Disabled
$ADU1 += $ADUsers | Where-Object { $_.Enabled -eq $False }      | Select-Object @{n='Tag'; e={'Disabled'}}, samaccountname
# LockedOut
$ADU1 += $ADUsers | Where-Object { $_.LockedOut }               | Select-Object @{n='Tag'; e={'Locked Out'}}, samaccountname
# * 0 New accounts in the past 30 ($ObservationWindow) days
$ADU1 += $ADUsers | Where-Object { (New-TimeSpan -Start $_.WhenCreated -End $Now).Days -le $ObservationWindow }     | Select-Object @{n='Tag'; e={"New in the past $ObservationWindow days"}}, samaccountname
# * 0 Modified in the past 30 days
$ADU1 += $ADUsers | Where-Object { (New-TimeSpan -Start $_.WhenChanged -End $Now).Days -le $ObservationWindow }     | Select-Object @{n='Tag'; e={"Modified in the past $ObservationWindow days"}}, samaccountname
# * 0 Bad Password attempts in the past 30 days
$ADU1 += $ADUsers | Where-Object { $Null -ne $_.LastBadPasswordAttempt -and (New-TimeSpan -Start $_.LastBadPasswordAttempt -End $Now).Days -le $ObservationWindow }     | Select-Object @{n='Tag'; e={"Bad Password Attempt in the past $ObservationWindow days"}}, samaccountname
# * 0 Password last changed more than 1 year ago
$ADU1 += $ADUsers | Where-Object { $Null -ne $_.PasswordLastSet -and (New-TimeSpan -Start $_.PasswordLastSet -End $Now).Days -gt 365 }     | Select-Object @{n='Tag'; e={"Password last changed over 1 year ago"}}, samaccountname
# Change Password at next logon 
$ADU1 += $ADUsers | Where-Object { $Null -eq $_.PasswordLastSet }     | Select-Object @{n='Tag'; e={"User must change password at next logon"}}, samaccountname
# * 0 Password Never Expires
$ADU1 += $ADUsers | Where-Object { $_.PasswordNeverExpires }    | Select-Object @{n='Tag'; e={'Password Never Expires'}}, samaccountname
# * 0 Cannot change their own password
$ADU1 += $ADUsers | Where-Object { $_.CannotChangePassword }    | Select-Object @{n='Tag'; e={'Cannot Change Password'}}, samaccountname
# * 0 Allow Reversible Encryption
$ADU1 += $ADUsers | Where-Object { $_.AllowReversiblePasswordEncryption }    | Select-Object @{n='Tag'; e={'Allow Reversible Password Encryption'}}, samaccountname
# * 0 Fine Grained Password Policy assigned
# ???
# * 0 Primary Group is NOT 'Domain Users'
$ADU1 += $ADUsers | Where-Object { $_.PrimaryGroupID -ne 513 }    | Select-Object @{n='Tag'; e={'Primary Group is NOT Domain Users'}}, samaccountname
# * 0 Protected from Accidental Deletion
$ADU1 += $ADUsers | Where-Object { $_.ProtectedFromAccidentalDeletion }    | Select-Object @{n='Tag'; e={'Protected From Accidental Deletion'}}, samaccountname
# * 0 Have SID History (SID change)
$ADU1 += $ADUsers | Where-Object { '' -ne $_.SIDHistory }    | Select-Object @{n='Tag'; e={'SID has changed'}}, samaccountname
# * 0 Trusted for Delegation
$ADU1 += $ADUsers | Where-Object { $_.TrustedforDelegation }    | Select-Object @{n='Tag'; e={'Trusted for Delegation'}}, samaccountname
# * 0 Does not require pre-auth
$ADU1 += $ADUsers | Where-Object { $_.DoesNotRequirePreAuth }    | Select-Object @{n='Tag'; e={'Does Not Require Pre-Auth'}}, samaccountname
# * 0 Without an email address
$ADU1 += $ADUsers | Where-Object { '' -eq $_.EmailAddress }    | Select-Object @{n='Tag'; e={'Does Not have an email address'}}, samaccountname
# * 0 Without a UPN
$ADU1 += $ADUsers | Where-Object { '' -eq $_.UserPrincipalName }    | Select-Object @{n='Tag'; e={'Does Not have a UPN'}}, samaccountname
# * 0 With an assigned SPN
$ADU1 += $ADUsers | Where-Object { $_.ServicePrincipalNames.Count -gt 0 }    | Select-Object @{n='Tag'; e={'Has an SPN assigned'}}, samaccountname
# * 0 Renamed Well Known Accounts
# ???

$ADU2 = $ADU1 | Group-Object Tag
$ADU2 | Select-Object Count, Name, @{n='User Accounts'; e={$_.Group.SamAccountName -join ", "}} | Format-Table -AutoSize -Wrap

Write-Output "`nTotal user count: $($ADUsers.Count)"

## User Account Warnings
$ADUWarn = $adu2 | Where-Object { $_.name -in "Locked Out", "Password not required", "Password never expires", "Password last changed over 1 year ago", "User must change password at next logon" }
$ADUWarn | ForEach-Object { ShowWarning "User accounts '$($_.Name)'" $_.Group.SAMAccountName -ShowCount -Max 8 }

$F2 = ".\$FileNameRoot-ADUsers.csv"
$ADUsers | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $F2 -Encoding utf8
Write-Output "AD Users details saved to: $((Resolve-Path $F2).Path)`n"

Write-Output "`n$($SeparatorLine)New Users in the past $ObservationWindow days:`n"
$NewUsers = $ADUsers | Where-Object { (New-TimeSpan -Start $_.WhenCreated -End $Now).Days -le $ObservationWindow } | Sort-Object Created -Descending
$NewUsers | Format-Table name, created, SAMAccountName, Mail, UserPrincipalName, Description
If ( $NewUsers.Count -gt 0 ) { $NU = ( $NewUsers | foreach-object { if ($_.Mail) { "$($_.Name) ($($_.Mail))" } Else { "$($_.Name)" } } )
                               ShowWarning "New user accounts created in the past $ObservationWindow days" $NU -ShowCount -Max 7
                               }
ElapsedTime

<# ───────── Accurate AD Groups ───────── #>
ShowInfo "Waiting for background job '$($JobADGroupPlusMembers.Name)' to complete ..."
Wait-Job -Job $JobADGroupPlusMembers -Timeout 60 | Out-Null
$ADGroups = Receive-Job -Job $JobADGroupPlusMembers -Wait -AutoRemoveJob | Sort-Object Name
$F3b = ".\$FileNameRoot-ADGroups.csv"
$ADGroups | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $F3b -Encoding utf8

## Warn if there are any groups without any members
$ADGroupsEmpty = $ADGroups | Where-Object { $_.MemberCount -eq 0 -and -not $_.Critical }
$ADGE = $ADGroupsEmpty | Measure-Object
if ( $ADGE.Count -gt 0 ) { ShowWarning "AD Groups with no members" $ADGroupsEmpty.Name -ShowCount -Max 6 }

Write-Output "$($SeparatorLine)$($AD.DNSRoot) - System Critical Groups: "
$ADCritGroups = $ADGroups | Where-Object { $_.iscriticalsystemobject -and $_.name -notin "Domain Users", "Domain Computers" } | Sort-Object Modified
$ADCritGroups | Where-Object { $_.membercount -gt 0  } | Format-Table -AutoSize Name, MemberCount, Modified, uSNChanged, MemberNames -Wrap
$F3 = ".\$FileNameRoot-ADCriticalGroups.csv"
$ADCritGroups | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $F3 -Encoding utf8
$F4a = ($F3.Replace("csv", "clixml"))
$ADCritGroups | Export-Clixml -Path $F4a
Write-Output "AD Critical Groups details saved to: $((Resolve-Path $F3).Path)`n"

if ( $OpenGrids ) { $ADGroups | Sort-Object Modified -Descending | Out-GridView -Title "$($AD.DNSRoot) - AD Groups and Members" }

<# ───────── Compare to previous AD Critical Groups ───────── #>
$F4b = "$PMOutputSubfolder$($AD.NetBIOSName)*ADCriticalGroups.clixml"
$Files = Get-Item -Path $F4b -Exclude ($F4a | Split-Path -Leaf ) | Sort-Object LastWriteTime
$ADGChanged = @()
If ( $Null -ne $Files )
{ $ADGSorted = Import-Clixml -Path $Files[-1].FullName | Sort-Object Name   ## Most recent of all previous .clixml files
  if ( $ADGSorted.count -gt 0 ) {
   $ADG2 = $ADCritGroups | Sort-Object ObjectGUID                        ## The current ADGroups, but sorted by GUID so the indexof() works
   $ADGChanges = 0

   $i = 0
   foreach ( $g in $ADG2 )
   { $ix = $ADGSorted.ObjectGUID.Indexof( $g.ObjectGUID )                ## Use GUID instead of name because the group name could change too
     if ( $g.uSNChanged -ne $ADGSorted[ $ix ].uSNChanged )
     { Write-Output "`n------> AD Group '$($g.name)' changed: "
       ## Write-Output "ADG2 = $i ; ADGSorted = [$ix]" 
       $g, $ADGSorted[ $ix ] | Format-Table -AutoSize -Wrap Name, MemberCount, Modified, uSNChanged, MemberNames

       $g1 = ( $g.membernames -split ', ' | Sort-Object )
       $g2 = ( $adgsorted[ $ix ].membernames -split ', ' | Sort-Object )
       $c3 = Compare-Object $g1 $g2    # -IncludeEqual
       
       $removed = $c3 | Where-Object { $_.Sideindicator -eq '=>' } 
       if ( $null -ne $removed ) { ShowWarning "Users removed from AD group '$($adgsorted[ $ix ].name)'" $removed.inputobject -ShowCount }

       $added   = $c3 | Where-Object { $_.Sideindicator -eq '<=' } 
       if ( $null -ne $added ) { ShowWarning "Users added to AD group '$($g.name)'" $added.inputobject -ShowCount }

       $ADGChanges++
       $ADGChanged += $g
       
     } # if USNchanged
   $i++
   } # foreach

   if ( $ADGChanges -eq 0 ) { Write-Output "No AD Group changes detected since $($files[-1].LastWriteTime.ToShortDateString())" }
   Else { ShowWarning "AD Group changes detected" $ADGChanged.Name -ShowCount }
  }  ## $ADGSorted.count
 } # if $files

<# ───────── AD Computers ───────── #>
ShowInfo "`nWaiting for background job '$($JobADComputers.Name)' to complete ..."
$ADComputers = Receive-Job -Job $JobADComputers -Wait -AutoRemoveJob
$now = Get-Date

$ADComputers | ForEach-Object `
{
  $x = if ( $Null -eq $_.LastLogonDate ) { -1 } Else { New-TimeSpan -Start $_.LastLogonDate -End $now -ErrorAction SilentlyContinue } ;
  Add-Member -InputObject $_ -MemberType NoteProperty -Name 'DaysSinceLastLogon' -Value $x.TotalDays -Force

  $b = Switch ( $_.DaysSinceLastLogon )
  { {$_ -le -1 -or $null -eq $_ }
                  { '  0 - (Never)'  ; Break }
    {$_ -le 14 }  { '  1 - 14 days'  ; Break }
    {$_ -le 30 }  { ' 15 - 30 days'  ; Break }
    {$_ -le 90 }  { ' 31 - 90 days'  ; Break }
    {$_ -le 365 } { ' 91 - 365 days' ; Break }
    Default       { '366 - ~ days (1 year+)' }
  }
  Add-Member -InputObject $_ -MemberType NoteProperty -Name 'Bucket' -Value $b -Force

  $e = Switch ( $_ )
  { { $_.LockedOut -eq $True }        { 'Account Locked Out'     ; Break }
    { $Null -ne $_.AccountExpirationDate `
      -and (New-TimeSpan -Start $_.AccountExpirationDate -End $now).TotalDays -gt 0  } { 'Account Expired'        ; Break }
    { $_.PasswordExpired -eq $True }  { 'Password Expired'       ; Break }
    { $_.Enabled -eq $False }         { 'Account Disabled'       ; Break }
    { $_.Enabled -eq $True }          { 'Account Active/Enabled' ; Break }
    Default { $Unknown }
  }
  Add-Member -InputObject $_ -MemberType NoteProperty -Name 'AccountStatus' -Value $e -Force
}

$ADComputers = $ADComputers | Select-Object -ErrorAction SilentlyContinue `
Name, DNSHostName, IPv4Address, SamAccountName, Modified,                                             `
AccountStatus, Enabled, isCriticalSystemObject, isDeleted, AccountExpirationDate,                     `
LastLogonDate, DaysSinceLastLogon, LastBadPasswordAttempt, BadLogonCount, LockedOut,                  `
PasswordExpired, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, CannotChangePassword,    `
Bucket, LogonCount,                                                                                   `
OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack, OperatingSystemHotfix,           `
whenChanged, uSNChanged, whenCreated, uSNCreated,                                                     `
AllowReversiblePasswordEncryption, AuthenticationPolicy, AuthenticationPolicySilo, CN, Description,   `
DisplayName, DistinguishedName, IPv6Address,                                                          `
LastKnownParent, Location, ManagedBy, MemberOf, PrimaryGroup, primaryGroupID,                         `
ProtectedFromAccidentalDeletion, PSComputerName,                                                      `
ServiceAccount, servicePrincipalName, ServicePrincipalNames,                                          `
SID, SIDHistory, TrustedForDelegation, TrustedToAuthForDelegation, userAccountControl, *

Write-Output "`n$($SeparatorLine)Computer Count by Last Logon Time Frames: "
# $ADComputers | Group-Object Bucket -NoElement | Sort-Object Name
$ADComputers | Group-Object Bucket | Sort-Object Name | Select-Object Count, @{n='Time Frame'; e={$_.Name}}, @{n='Computers'; e={$_.Group.SAMAccountName -Join ', '}} | Format-Table -AutoSize -Wrap

Write-Output "`nComputer Count by Account Status:"
Write-Output " "
## $ADComputers | Group-Object AccountStatus -NoElement | Sort-Object Name
$ADComputers | Group-Object AccountStatus | Sort-Object Name | Select-Object Count, Name, @{n='Computers'; e={$_.Group.Name -join ", "}} | Format-Table -AutoSize -Wrap

<# ───────── Count by OS Version ───────── #>
Write-Output "`nOS Summary of AD Computers:"
$ADComputers | Sort-Object OperatingSystem | Group-Object OperatingSystem | Format-Table -AutoSize -Wrap Count, Name, @{n='Computer Name'; e={$_.Group.Name -join ", "}}

<# Add bullet point highlights for AD Computer Account properties: #>
Write-Output "`nAD Computer Account Proerties of note:"
$ADC1 = @()
# * 0 System Critical Object accounts
$ADC1 += $ADComputers | Where-Object { $_.IsCriticalSystemObject }  | Select-Object @{n='Tag'; e={'Critical System Object'}}, Name
# * 0 Password Not Required
$ADC1 += $ADComputers | Where-Object { $_.PasswordNotRequired }     | Select-Object @{n='Tag'; e={'Password Not Required'}}, Name
# * 0 Disabled
$ADC1 += $ADComputers | Where-Object { $_.Enabled -eq $False }      | Select-Object @{n='Tag'; e={'Disabled'}}, Name
# LockedOut
$ADC1 += $ADComputers | Where-Object { $_.LockedOut }               | Select-Object @{n='Tag'; e={'Locked Out'}}, Name
# * 0 New accounts in the past 30 ($ObservationWindow) days
$ADC1 += $ADComputers | Where-Object { (New-TimeSpan -Start $_.WhenCreated -End $Now).Days -le $ObservationWindow }     | Select-Object @{n='Tag'; e={"New in the past $ObservationWindow days"}}, Name
# * 0 Modified in the past 30 days
$ADC1 += $ADComputers | Where-Object { (New-TimeSpan -Start $_.WhenChanged -End $Now).Days -le $ObservationWindow }     | Select-Object @{n='Tag'; e={"Modified in the past $ObservationWindow days"}}, Name
# * 0 Bad Password attempts in the past 30 days
$ADC1 += $ADComputers | Where-Object { $Null -ne $_.LastBadPasswordAttempt -and (New-TimeSpan -Start $_.LastBadPasswordAttempt -End $Now).Days -le $ObservationWindow }     | Select-Object @{n='Tag'; e={"Bad Password Attempt in the past $ObservationWindow days"}}, Name
# * 0 Password last changed more than 1 year ago
$ADC1 += $ADComputers | Where-Object { $Null -ne $_.PasswordLastSet -and (New-TimeSpan -Start $_.PasswordLastSet -End $Now).Days -gt 365 }     | Select-Object @{n='Tag'; e={"Password last changed over 1 year ago"}}, Name
# * 0 Password Never Expires
$ADC1 += $ADComputers | Where-Object { $_.PasswordNeverExpires }    | Select-Object @{n='Tag'; e={'Password Never Expires'}}, Name
# * 0 Cannot change their own password
$ADC1 += $ADComputers | Where-Object { $_.CannotChangePassword }    | Select-Object @{n='Tag'; e={'Cannot Change Password'}}, Name
# * 0 Allow Reversible Encryption
$ADC1 += $ADComputers | Where-Object { $_.AllowReversiblePasswordEncryption }    | Select-Object @{n='Tag'; e={'Allow Reversible Password Encryption'}}, Name
# * 0 Protected from Accidental Deletion
$ADC1 += $ADComputers | Where-Object { $_.ProtectedFromAccidentalDeletion }    | Select-Object @{n='Tag'; e={'Protected From Accidental Deletion'}}, Name
# * 0 Have SID History (SID change)
$ADC1 += $ADComputers | Where-Object { '' -ne $_.SIDHistory }    | Select-Object @{n='Tag'; e={'SID has changed'}}, Name
# * 0 Trusted for Delegation
$ADC1 += $ADComputers | Where-Object { $_.TrustedforDelegation }    | Select-Object @{n='Tag'; e={'Trusted for Delegation'}}, Name
# * 0 Does not require pre-auth
$ADC1 += $ADComputers | Where-Object { $_.DoesNotRequirePreAuth }    | Select-Object @{n='Tag'; e={'Does Not Require Pre-Auth'}}, Name
# * 0 Without an email address
$ADC1 += $ADComputers | Where-Object { '' -eq $_.UserPrincipalName }    | Select-Object @{n='Tag'; e={'Does Not have a UPN'}}, Name
# * 0 With an assigned SPN
## $ADC1 += $ADComputers | Where-Object { $_.ServicePrincipalNames.Count -gt 0 }    | Select-Object @{n='Tag'; e={'Has an SPN assigned'}}, Name

$ADC2 = $ADC1 | Group-Object Tag
$ADC2 | Select-Object Count, Name, @{n='Computer Accounts'; e={$_.Group.Name -join ", "}} | Format-Table -AutoSize -Wrap
Write-Output "`nTotal computer count: $($ADComputers.Count)"

## Computer Account Warnings
$ADCWarn = $ADC2 | Where-Object { $_.name -in "Locked Out", "Password not required", "Password never expires" }
$ADCWarn | ForEach-Object { ShowWarning "Computer accounts '$($_.Name)'" $_.Group.Name -ShowCount -Max 8 }

$F3 = ".\$FileNameRoot-ADComputers.csv"
$ADComputers | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $F3 -Encoding utf8
Write-Output "AD Computers details saved to: $((Resolve-Path $F3).Path)`n"

Write-Output "`n$($SeparatorLine)New Servers in the past $( $ObservationWindow ) days:`n"
$NewServers = $ADComputers | Where-Object { $_.OperatingSystem -Like "*Server*" -and (New-TimeSpan -Start $_.WhenCreated -End $Now).Days -le ( $ObservationWindow ) }  | Sort-Object created -Descending
$NewServers | Format-Table Name, IPv4Address, Created, LastLogonDate, OperatingSystem, OperatingSystemVersion, Description
If ( ($NewServers | Measure-Object).Count -gt 0 ) { ShowWarning "New Servers added in the past $( $ObservationWindow ) days" $NewServers.Name -ShowCount -TrimDomain -NoMax }
Else { Write-Output "No new Servers added in the past $($ObservationWindow ) days`n" }

Write-Output "`n$($SeparatorLine)New Workstations in the past $ObservationWindow days:`n"
$NewWorkstations = $ADComputers | Where-Object { $_.OperatingSystem -NotLike "*Server*" -and (New-TimeSpan -Start $_.WhenCreated -End $Now).Days -le $ObservationWindow }  | Sort-Object created -Descending
$NewWorkstations | Format-Table Name, IPv4Address, Created, LastLogonDate, OperatingSystem, OperatingSystemVersion, Description
If ( $NewWorkstations.Count -gt 0 ) { ShowWarning "New Workstations added in the past $ObservationWindow days" $NewWorkstations.Name  -ShowCount -TrimDomain -Max 8 }
Else { Write-Output "No new Workstations added in the past $ObservationWindow days`n" }

<# ───────── AD Optional Features ───────── #>
ElapsedTime
Write-Output "`n$($SeparatorLine)AD Optional Features: "
Get-ADOptionalFeature -Filter "*" -Properties * | Format-Table -Wrap Name, Modified, Created, Required*Mode, isDisableable, EnabledScopes

<# ───────── AD Deleted Objects ───────── #>
### https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944
Write-Output "`n$($SeparatorLine)Deleted objects in AD:`n`n"
$ADRB = Get-ADOptionalFeature -filter 'name -like "*Recycle Bin*"' -ErrorAction SilentlyContinue
$ADRBed = if ( $False -eq $ADRB.EnabledScopes ) { 'Disabled' } Else { 'Enabled' }
if ( $Null -ne $ADRB ) { Write-Output "AD '$($ADRB.Name)': $ADRBed" }
if ( $ADRBed -eq 'Enabled' )
{ Write-Output "Deleted objects container: $($AD.DeletedObjectsContainer)"
  $ADRBprop = get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$($AD.DistinguishedName)" -Properties *
  Write-Output "Tombstone Lifetime: $($ADRBprop.TombstoneLifetime) days" }
Else { ShowWarning "AD Recycle bin not enabled on domain '$($AD.DNSRoot)'" }

$ADDel = Get-ADObject -Filter { isDeleted -eq $True -and name -ne "Deleted Objects" } -IncludeDeletedObjects -Properties * | Select-Object * -ExcludeProperty *cert* | Sort-Object Modified -Descending
$ADDelTop = 12

if ( $ADDel.count -gt 0 ) {
 Write-Output "$($ADDel.Count) deleted objects in the AD Recycle Bin: (most recent $ADDelTop listed)"
 $ADDel | Where-Object { $_.ObjectClass -notin ( "dnsNode", "ServiceConnectionPoint" ) } | Select-Object -First $ADDelTop `
        | Format-Table -AutoSize sAMAccountName, @{n='Name'; e={$_.Name.substring(0,20)}}, ObjectClass, Modified, Created, LastKnownParent, Description, isCriticalSystemObject

 Write-Output "Deleted AD Objects Summary by Class: "
 $ADDel | Group-Object ObjectClass | Select-Object Count, Name `
                                                 , @{n='Deleted Object'; e={ Switch ( $_ ) { `
                                                                             { $_.Name -in 'computer','user','group' }  { $_.Group.samAccountName  -join ", " ; Break } `
                                                                             { $_.Name -eq 'contact' }                  { $_.Group.Mail -join ", " ; Break } `
                                                                             { $_.Name -eq 'serviceConnectionPoint' }   { "" ; Break } `
                                                                             { $_.Name -eq 'dnsNode' }                  { "" ; Break } `
                                                                             { $_.Name -like 'msExch*' }                { $_.Group."msDS-LastKnownRDN" -join ", " ; Break } `
                                                                             { $_.Name -like 'organiz*' }               { $_.Group."msDS-LastKnownRDN" -join ", " ; Break } `
                                                                             { $_.Name -eq 'printQueue' }               { $_.Group.UNCName -join ", " ; Break } `
                                                                             { $_.Name -eq 'container' }                { $_.Group.CanonicalName -join ", " ; Break } `
                                                                             { $Null -ne $_.Group.DisplayName }         { $_.Group.DisplayName -join ", " ; Break } `
                                                                             default                                    { $_.Group.Name -join ", " } `
                                                                                            } `
                                                                            } `
                                                 } | Format-Table -AutoSize -Wrap
 $ADDelDCs = $ADDel | Where-Object { $_.LastKnownParent -like "OU=Domain Controllers*" } 
 $ADDelDCs | ForEach-Object { ShowWarning "$($TextInfo.ToTitleCase($_.objectClass)) $($_."msDS-LastKnownRDN") deleted from 'Domain Controllers' OU on $($_.Modified.ToShortDateString()), created $($_.Created.ToShortDateString()): $($_.Description)" }

 $F3 = ".\$FileNameRoot-ADDeletedObjects.csv"
 $ADDel | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $F3 -Encoding utf8
 Write-Output "`nAD Deleted Objects details saved to: $((Resolve-Path $F3).Path)`n" }

<# ───────── GPO Backups Job ───────── #>
Wait-job -Name "GPOBackup" -Timeout 6 | Out-Null
Receive-Job -Name "GPOBackup" -Wait -AutoRemoveJob

$GPOBackupManifest = [xml](Get-Content "$GPOBackupFolder\manifest.xml")
$GPOBackupDetails = $GPOBackupManifest.Backups.BackupInst | 
                    Select-Object @{n='Domain'; e={$_.GPODomain.InnerText}}, @{n='ID-Folder'; e={$_.ID.InnerText}} `
                                , @{n='BackupDate'; e={([datetime]$_.BackupTime.InnerText).Date}} `
                                , @{n='GPO'; e={$_.GPODisplayname.InnerText}}, @{n='Comment'; e={$_.Comment.InnerText}} `
                                , @{n='BackupTime'; e={[datetime]$_.BackupTime.InnerText}} `
                                , * -ErrorAction SilentlyContinue
#    @{N='GPOGUID';E={$_.GpoGUID.'#cdata-section'}},
#    @{N='GPODisplayName';E={$_.GPODisplayName.'#cdata-section'}},

$GPOsBackedUp = $GPOBackupDetails | Measure-Object BackupDate -Minimum -Maximum
if ( $Null -ne $GPOsBackedUp ) { ShowInfo "$($GPOsBackedUp.count) GPOs backed up between $($GPOsBackedUp.Minimum.ToShortDateString()) and $($GPOsBackedUp.maximum.ToShortDateString()) saved to '$GPOBackupFile'" -NoTime }

### 2024-01-11 MJS: Add date to ZIP file name for the GPO Backups and delete GPO ZIPs older than 1 year
Write-Output "Deleting GPO Backups older than 1 year ($($365DaysAgo.ToShortDateString())):"
$GPOtoDelete = $GPOBackupDetails | Where-Object { $_.BackupTime -lt $365DaysAgo }
if ( $GPOtoDelete.Count -gt 0 ) { $GPOtoDelete | Format-Table -AutoSize
                                  Remove-Item "$GPOBackupFolder\$($x[0].'id-folder')" -Force -Confirm:$False -Recurse -ErrorAction SilentlyContinue }
Else { Write-Output "$($tab)No GPO backups deleted" }                                  

<# ───────── AD Servers ───────── #>
### List all domain-joined Servers
Write-Output "$($SeparatorLine)$($ServersInAD.Count) servers listed in AD:"
$ServersInAD | Format-Table -AutoSize DNSHostName, IPv4Address, Enabled, LastLogonDate, OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack, Description

ShowInfo "Waiting for background PING jobs to complete ..."`

Wait-job -Name "PING*" -Timeout 6 | Out-Null
$ServersPING = Receive-Job -Name "PING*" -Wait

If ( $null -eq $HasTestNet )
{ $ServersPING = $ServersPING | Sort-Object Address -Unique
  $List = [System.Linq.Enumerable]::ToList([psobject[]]$ServersPING)     ## This is to circumvent the overloaded property .Address
  $OnlineComputerNames = ($List).Address
}
Else {
  $ServersPING = $ServersPING | Where-Object { $_.pingsucceeded } | Sort-Object computername
  Write-Output "$($ServersPING.Count) servers online (responding to PING)"
  $OnlineComputerNames = ($ServersPING).ComputerName
}
$ServersOnline = $ServersInAD | Where-Object { $_.DNSHostName -in $OnlineComputerNames }
Remove-Job -Name "PING*" -Force -ErrorAction SilentlyContinue | Out-Null

<# ───────── Count by OS Version ───────── #>
Write-Output "`nOS Summary of $($ServersOnline.count) servers online:"
$ServersOnline | Sort-Object OperatingSystem | Group-Object OperatingSystem | Format-Table -AutoSize -Wrap Count, Name, @{n='Computer Name'; e={$_.Group.Name -join ", "}}

<# ───────── Servers Offline ───────── #>
$ServersOffline = $ServersInAD | Where-Object { $_.DNSHostName -notin $OnlineComputerNames }
$OfflineCount = ($ServersOffline | Measure-Object).Count
if ( $OfflineCount -gt 0 ) {
  ShowWarning "Servers offline" $ServersOffline.name -ShowCount -TrimDomain
  $ServersOffline| Format-Table -AutoSize DNSHostName, IPv4Address, Enabled, @{Name = 'Status'; Expression = { '* No reply' } }, LastLogonDate, OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack
}

<# ───────── Connect PS Sessions to all online servers ───────── #>
Write-Information "Setting up PSSessions to all online servers ..." -InformationAction Continue
if ( $Null -eq $ServersOnlineSessions  -or $ServersOnline.Count -ne $ServersOnlineSessions.Count  -or $ServersOnlineSessions.state  -contains 'Broken' ) { $ServersOnlineSessions  = New-PSSession ($ServersOnline.dnshostname -replace $LocalDNSHost, "localhost") -ErrorAction SilentlyContinue | Sort-Object ComputerName }
if ( $Null -eq $ServersOnlineSessions2 -or $ServersOnline.Count -ne $ServersOnlineSessions2.Count -or $ServersOnlineSessions2.state -contains 'Broken' ) { $ServersOnlineSessions2 = New-PSSession ($ServersOnlineSessions).ComputerName -ErrorAction SilentlyContinue | Sort-Object ComputerName }

if ( $RunningOnAServer ) { Write-Information "NOTE: 'localhost' = $env:computername.$env:USERDNSDOMAIN" -InformationAction Continue }

$ServersOnlineNOSessions = $ServersOnline | Where-Object { $_.DNSHostName -notin $ServersOnlineSessions.ComputerName -and $_.DNSHostName -ne $LocalDNSHost }
if ( $ServersOnlineNOSessions.Count -gt 0 ) { ShowWarning "Unable to establish PSSession with Server" $ServersOnlineNOSessions.CN -ShowCount -TrimDomain }

ElapsedTime

<# ───────── Connect CIM Sessions to all online servers ───────── #>
if ( $Null -eq $ServersCIMSessions -or $ServersOnline.Count -ne $ServersCIMSessions.Count ) { $ServersCIMSessions  = ($ServersOnline).DNSHostName, "localhost" | ForEach-Object { New-CimSession -ComputerName $_ -ErrorAction SilentlyContinue } | Sort-Object ComputerName }


<# ═════════════════════════════════════════════════════ #>
<# ───────── Start Background Jobs for servers ───────── #>
<# ═════════════════════════════════════════════════════ #>

<# ───────── Windows Defender ───────── #>


<# ───────── Local User Accounts ───────── #>
Write-Output "$($SeparatorLine)Local 'Well-Known' User Accounts: `n"
$ServerLocalUsers = Invoke-Command -Session $ServersOnlineSessions `
                                   -ScriptBlock { Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-50*" }     # -500=Admin, -501=Guest, -503=DefaultAccount
                                                } -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty Runspace* | Sort-Object PSComputerName, Name
FixLocalhostName $ServerLocalUsers -TrimDomain
$ServerLocalUsers | Sort-Object PSComputerName, LogonName | Format-Table PSComputerName, Name, Enabled, PasswordRequired, UserMayChangePassword, PasswordLastSet, Description

#Write-Output "Summary of Local 'Well-Known' User Accounts, Status: "
#$ServerLocalUsers | Group-Object name, enabled
ShowWarning "Local Administrator user account has not been renamed" ($ServerLocalUsers | Where-Object { $_.SID -like "S-1-5-*-500" -and $_.Name -eq "Administrator" }).PSComputerName -ShowCount -BlankIfZero
ShowWarning "Local Guest user account should be disabled"           ($ServerLocalUsers | Where-Object { $_.SID -like "S-1-5-*-501" -and $_.Enabled }).PSComputerName -ShowCount -BlankIfZero
ShowWarning "Local Guest user account has not been renamed"         ($ServerLocalUsers | Where-Object { $_.SID -like "S-1-5-*-501" -and $_.Name -like "Guest" }).PSComputerName -ShowCount -BlankIfZero
ShowWarning "Local 'DefaultAccount' account should be disabled"     ($ServerLocalUsers | Where-Object { $_.SID -like "S-1-5-*-503" -and $_.Enabled }).PSComputerName -ShowCount -BlankIfZero
## Local user accounts do not have a 'password required' option
## ShowWarning "Local Well-Known account does not require a password"  ($ServerLocalUsers | Where-Object { $_.SID -like "S-1-5-*-50*" -and -not $_.PasswordRequired }).Foreach({ "$($_.PSComputerName)\$($_.Name)" }) -ShowCount -BlankIfZero
ShowWarning "Local Well-Known account never or over 1 year since password was changed" `
            ($ServerLocalUsers | Where-Object { $_.SID -like "S-1-5-*-50[01]*" -and  ($Null -eq $_.PasswordLastSet -or ( `
                                                (New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date)).days -gt 365)) `
                                              }).Foreach({ "$($_.PSComputerName)\$($_.Name)" }) -ShowCount -BlankIfZero

<# ───────── Active and Disconnected sessions ───────── #>
Write-Output "$($SeparatorLine)User sessions: `n"
$ServersUsersSessions = Invoke-Command -Session $ServersOnlineSessions `
                        -ScriptBlock { (query user) -split "\n" -replace '\s{2,19}', ';' -replace 'none', 0 -replace '\.', 0 | convertfrom-csv -Delimiter ';'
                                       } -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty Runspace* | Sort-Object PSComputerName, State, UserName
FixLocalhostName $ServersUsersSessions -TrimDomain
$ServersUsersSessions | ForEach-Object { $_.'Logon Time' = [datetime]$_.'Logon Time' }
$ServersUsersSessions = $ServersUsersSessions | Select-Object *, @{ n = "Idle Minutes"; 
                                                                    e = { $t1 = $_."Idle Time" ;
                                                                          if ( $t1 -notlike "*:*") { $t1 = "0:$t1" } ;
                                                                          if ( $t1 -notlike "*+*") { $t1 = "0+$t1" } ;
                                                                          $t  = $t1 -split "[+:]" ;
                                                                          ([int]$T[0])*24*60 + [int]($t[1])*60 + [int]($t[2]) } }
$ServersUsersSessions | Format-Table PSComputerName, UserName, SessionName, ID, State, 'Idle Time', 'Logon Time', 'Idle Minutes'
## $q.ForEach({ Add-member -InputObject $_ -MemberType NoteProperty -Name 'IdleDays' -Value  ($_.'Idle Time' -split '\+')[0] } )

$ServersUsersDiscSessions = @($ServersUsersSessions | Where-Object { $_.State -like '*Disc*' })
if ( $ServersUsersDiscSessions.Count -gt 0 )
{ Write-Output "`n"
  $x6 = $ServersUsersDiscSessions | Select-Object @{n='User'; e={"$(($_.PSComputerName -Split "\.")[0])\$($_.Username)"}} | Sort-Object User | Select-Object User -Unique
  ShowWarning "Disconnected user sessions on servers" $x6.User -ShowCount }
  ## $ServersUsersDiscSessions | ForEach-Object { icm -ComputerName $_.pscomputername -ScriptBlock { quser ; logoff $using:_.id ; quser } }

<# ───────── Computer 'Hardware' details ───────── #>
Write-Output "$($SeparatorLine)Computer System details: "
$ServersComputerSystem = Invoke-Command -Session $ServersOnlineSessions -ScriptBlock { Try { $w2 = Get-WMIObject -Class Win32_BIOS    ## SMBIOSBIOSVersion,  SerialNumber
                                                                                             $PK = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\" -name 'BackupProductKeyDefault'
                                                                                             Get-WMIObject -Class Win32_ComputerSystem | Select-Object *, @{n='SerialNumber'; e={$w2.SerialNumber}}, @{n='BIOSVersion'; e={$w2.SMBIOSBIOSVersion}} `
                                                                                                                                         , @{n='ProductKey'; e={$PK.BackupProductKeyDefault}}
                                                                                            } Catch { }
                                                                                      } -ErrorAction SilentlyContinue

$ServersSummary = $ServersComputerSystem | Sort-Object Name | Select-Object Name `
                                          , @{Name='Status'; Expression={"$($_.Status) - $($_.BootupState)"}} `
                                          , @{Name='Virtual'; Expression={ $c1 = $_.manufacturer.split() ; $c1 -contains 'Amazon' -or $c1 -contains 'Nutanix' -or $c1 -like '*VMware*'  -or $_.Model -like '*virtual*' }} `
                                          , Manufacturer, Model `
                                          , @{Name='CPUs'; Expression={$_.NumberOfProcessors}} `
                                          , @{Name='Cores'; Expression={$_.NumberofLogicalProcessors}} `
                                          , @{Name='CoresPer'; Expression={$_.NumberOfLogicalProcessors / $_.NumberofProcessors}} `
                                          , @{Name='Memory (GB)';Expression={ [math]::Round($_.TotalPhysicalMemory / 1GB)}} `
                                          , @{Name='SerialNumber'; Expression={$_.SerialNumber.Replace(' ','')}} `
                                          , BIOSVersion, ProductKey
### $ServersSummary | Format-Table -AutoSize Name, Status, Virtual, manu*, model, CPUs, Cores, CoresPer, Memory*, bios*, ProductKey, serial*
$ServersSummary | Format-Table -AutoSize Name, Status, Virtual, manu*, model, CPUs, Cores, CoresPer, Memory*, bios*, serial*
$ServersSummary | Measure-Object -Sum Cores, 'Memory (GB)' | Format-Table -AutoSize @{Name='Resource'; Expression={$_.Property}}, @{Name='Total'; Expression={$_.Sum}}

ElapsedTime

<# ───────── Check for non-standard RDP port ───────── #>
$RDPPort = Invoke-Command -Session $ServersOnlineSessions2 -ScriptBlock  { Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP\" -Name PortNumber | Select-Object PortNumber }
FixLocalhostName $RDPPort
$RDPPortNot3389 = $RDPPort | Where-Object { $_.PortNumber -ne 3389 }
if ( $Null -ne $RDPPortNot3389 ) { ShowWarning "Servers with a non-default RDP port" ($RDPPortNot3389 | ForEach-Object { "$($_.pscomputername):$($_.PortNumber)" }) -ShowCount }

<# ───────── Windows Product Key and Activation Status ───────── #>
Write-Output "$($SeparatorLine)Windows Product Key and Activation: "

$ServersProductKey = Invoke-Command -Session $ServersOnlineSessions2 `
                     -ScriptBlock { Try { $PK = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\" -name 'BackupProductKeyDefault'
                                          Get-WMIObject -Class SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object { $_.PartialProductKey } `
                                           | Select-Object *, @{n='ProductKey'; e={$PK.BackupProductKeyDefault}}
                                        } Catch { }
                                  } -ErrorAction SilentlyContinue
FixLocalhostName $ServersProductKey
$ServersProductKey = $ServersProductKey | Sort-Object PSComputerName | Select-Object PSComputerName, @{n='Edition'; e={$_.Name.Replace(' edition', '')}}, ProductKeyChannel `
                                                              , @{n='License Status'; e={[WindowsLicenseStatus]$_.LicenseStatus}} `
                                                              , @{n='OS Version'; e={ $x2 = $ServersInAD.DNSHostName.IndexOf( $_.PSComputerName ) ; if ( $x2 -ne -1 ) { $ServersInAD[ $x2 ].OperatingSystem } }} `
                                                              , PartialProductKey, ProductKey, * -ErrorAction SilentlyContinue
$ServersProductKey | Sort-Object "OS Version", PartialProductKey | Format-Table -AutoSize PSComputerName, 'OS Version', Edition, ProductKeyChannel, 'License Status', PartialProductKey, ProductKey

$WPA = $ServersProductKey | Where-Object { $_.LicenseStatus -ne 1 }
$WPACount = ( $WPA | Measure-Object ).Count
if ( $WPACount -ne 0 ) { ShowWarning "Servers not activated/licensed" $WPA.__Server -ShowCount }

<# ─────────────────────────── #>
## OS Revision/Release # 
$OSRelease = Invoke-Command -Session $ServersOnlineSessions2 -ScriptBlock { 
  $OS = Get-CimInstance -ClassName win32_operatingsystem -Property * 
  $Version = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -ErrorAction SilentlyContinue
  Add-Member -InputObject $OS -MemberType NoteProperty -Name 'Release' -Value $Version.Release -Force
  Add-Member -InputObject $OS -MemberType NoteProperty -Name 'CurrentBuild' -Value $Version.UBR -Force
  Add-Member -InputObject $OS -MemberType NoteProperty -Name 'DisplayVer' -Value $Version.DisplayVersion -Force
  Add-Member -InputObject $OS -MemberType NoteProperty -Name 'ClassicVer' -Value $Version.CurrentVersion -Force
  Add-Member -InputObject $OS -MemberType NoteProperty -Name 'BaseBuildRevisionNumber' -Value $Version.BaseBuildRevisionNumber -Force
  Add-Member -InputObject $OS -MemberType NoteProperty -Name 'EditionID' -Value $Version.EditionID -Force
  ## LCUVer *LCU - Latest Cumulative Update
  Add-Member -InputObject $OS -MemberType NoteProperty -Name 'LCUVer' -Value $Version.LCUVer -Force
  
  $OS | Select-Object *, @{n='ShortVer'; e={($_.Version -split "\.")[0..1] -join "."}} `
                       , @{n='MajorVer'; e={($_.Version -split "\.")[0] }} `
                       , @{n='MinorVer'; e={($_.Version -split "\.")[1] }} `
                       , @{n='SKU'; e={$_.OperatingSystemSKU }}
  } -ErrorAction SilentlyContinue
$OSRelease | Sort-Object Caption, BuildNumber, CurrentBuild | Format-Table @{n='ComputerName'; e={$_.CSName}}, @{n='Operating System'; e={$_.Caption}}, Version, MajorVer, MinorVer, ShortVer, DisplayVer, LCUVer, BuildNumber, CurrentBuild, Release `
                        , CodeSet, EncryptionLevel, Locale, OSLanguage, SKU, OSArchitecture, CountryCode

<# ───────── Servers CPU Details ───────── #>
<#
$ServersCPUJob = Invoke-Command -Session $ServersOnlineSessions -ScriptBlock { Try { Get-WmiObject -Class Win32_processor -ErrorAction SilentlyContinue } `
                                                                               Catch { $ENV:COMPUTERNAME } } -ErrorAction SilentlyContinue -AsJob -JobName "ServersCPU"
ShowInfo "Waiting for CPU details info background jobs to complete ..."
Write-Output "$($SeparatorLine)Servers CPUs: "
Wait-Job -Name "ServersCPU*" -Timeout 10 | Out-Null
$ServersCPU = Receive-Job -Job $ServersCPUJob
Get-Job -Name "ServersCPU*" | Remove-Job -Force | Out-Null
#>

$ServersCPU = Get-CimInstance -Class Win32_processor -CimSession $ServersCIMSessions -ErrorAction SilentlyContinue
## Full CPU details:
#$ServersCPU | Format-Table SystemName, deviceid, status, name, caption, *ClockSpeed
## CPU Summary only:
$ServersCPU | Sort-Object Name | Group-Object Name | Format-Table -AutoSize -Wrap Count, @{n='CPU'; e={$_.Name}}, @{n='Servers';e={ ( $_.Group.SystemName | Sort-Object | Select-Object -Unique ) -join ", "}}

<# ───────── PowerShell Versions ───────── #>
$PSVersions = Invoke-Command -Session $ServersOnlineSessions -ScriptBlock{ $PSVersionTable.PSVersion | Select-Object *, @{n='ComputerName'; e={ "$env:COMPUTERNAME.$ENV:USERDNSDOMAIN" }} } -ErrorAction SilentlyContinue
Write-Output "$($SeparatorLine)$($PSVersions.Count) servers reporting PowerShell versions: "
$PSVersions = $PSVersions | Sort-Object Major, Minor, Build, Revision | Select-Object *, @{ Name = 'OperatingSystem'; Expression = { $idx = ($ServersInAD).DNSHostName.ToLower().IndexOf( ($_.ComputerName).ToLower() ) ; $ServersInAD[ $idx ].OperatingSystem } }
$PSVersions | Format-Table -AutoSize ComputerName, Major, Minor, Build, Revision, OPeratingSystem
ElapsedTime

<# ───────── Server Disk Space ───────── #>
Write-Output "$($SeparatorLine)Server disk space: (sorted by lowest % free)"
Clear-Variable ServerDiskSpace, JobDrives, ServerDrives, Drives, ServerDiskSpace, r1 -ErrorAction SilentlyContinue
$ServerDiskSpace = @()

<# ───────── Get only DriveType 3 (LocalDisks) for each Server ───────── #>
Invoke-Command -Session $ServersOnlineSessions2 -ScriptBlock { Try { Get-Disk } Catch { Get-WmiObject -Class Win32_DiskDrive } } -AsJob -JobName "ServerPhysicalDisks" | Out-Null

Invoke-Command -Session $ServersOnlineSessions `
               -ScriptBlock {
                              if ( Get-Command -name "Get-CimInstance" -ErrorAction SilentlyContinue )
                                   { $DS = Get-CimInstance win32_logicaldisk -Filter "Drivetype=3" -ErrorAction SilentlyContinue }
                              else { $DS = Get-WMIObject   win32_logicaldisk -Filter "Drivetype=3" -ErrorAction SilentlyContinue }

                              $BL = Try { Get-BitLockerVolume -ErrorAction SilentlyContinue } Catch { $Null }
                              $DS | ForEach-Object { $x = if ( $Null -eq $BL ) { 'Not Installed' } 
                                                          ElseIf ( $BL[ ($BL.MountPoint).IndexOf($_.Name) ].LockStatus -eq "Locked" ) { $BL[ ($BL.MountPoint).IndexOf($_.Name) ].LockStatus } 
                                                          Else { $BL[ ($BL.MountPoint).IndexOf($_.Name) ].ProtectionStatus }
                                                     $_ | Add-Member -MemberType NoteProperty -Name 'BitLockerStatus' -Value $X -ErrorAction SilentlyContinue
                                                   }  ## foreach

                              $DS

                            } -AsJob -JobName "ServerDisks" | Out-Null

$ServerDrives = Receive-Job -Name "ServerDisks" -AutoRemoveJob -Wait

$ServerDiskSpace = $ServerDrives | Select-Object @{Name = 'ComputerName'; Expression = { $_.SystemName } },
@{Name = 'DateTime';Expression = {((Get-Date).GetDateTimeFormats())[14]}},
@{Name = 'Drive';Expression = {$_.DeviceID}},
@{Name = 'Size_GB';Expression={[math]::Round($_.Size/1GB,0)}},
@{Name = 'Free_GB';Expression={[math]::Round($_.FreeSpace/1GB, 0)}},
@{Name = 'PctFree';Expression = {'{0,7:n2}' -F [math]::Round($_.FreeSpace/$_.Size*100,2) }},
@{Name = 'Status';Expression = {$x2=[math]::Round($_.FreeSpace/$_.Size*100,0);$idx3 = ( $Status.Get_Value() -ge $x2 )[-1]; ( $Status.GetEnumerator() | Where-Object { $_.value -eq $idx3 } ).name } } ,
@{Name = 'VolumeName';Expression={$_.VolumeName}},
@{Name = 'UNC';Expression={'\\'+$_.SystemName+'\'+$_.DeviceID[0]+'$'}},
BitLockerStatus, FileSystem

$r1 = $ServerDiskSpace | Sort-Object PctFree
$r1 | Format-Table -AutoSize ComputerName, Drive, *_GB, PctFree, Status, VolumeName, FileSystem, BitLockerStatus, UNC

$ServerDiskLocked =  $ServerDiskSpace | Where-Object { $_.BitLockerStatus -like "*Locked*" }
if ( $Null -ne $ServerDiskLocked ) { ShowWarning "BitLocker volume is Locked" $ServerDiskLocked.UNC -ShowCount -Critical }

$DiskSummary = $r1 | Group-Object Status | Select-Object Count, @{n='Status';e={$_.Name}}, @{n='ComputerName'; e={$_.Group.ComputerName -join ", "}}
$DiskSummary | Format-Table -Wrap

$DiskCritical = $r1 | Where-Object { $_.status -in ("Critical") } | Sort-Object UNC
$r2 = $DiskCritical | Group-Object Status | Select-Object Count, @{n='Status';e={$_.Name}}, @{n='UNC'; e={$_.Group.UNC -join ", "}}
If ( $r2.Count -gt 0 ) { ShowWarning "Server disks with free space at '$($r2.Status)' levels" $r2.UNC -Critical }

$DiskTotals = $ServerDiskSpace | Measure-Object -Sum -Property size_gb, free_gb | Sort-Object Property
$DiskTotalsCapacity = [math]::Round( ( $DiskTotals[1].Sum ) / 1024 , 2 )
$DiskTotalsUsed = [math]::Round( ( $DiskTotals[1].Sum - $DiskTotals[0].Sum ) / 1024 , 2 )
$DiskTotalsAvailable = [math]::Round( ( $DiskTotals[0].Sum ) / 1024 , 2 )
$DiskTotalsUsedPercent = [math]::Round( ( $DiskTotalsUsed / $DiskTotalsCapacity ) * 100 , 0 )
$DiskTotalsAvailablePercent = [math]::Round( ( $DiskTotalsAvailable / $DiskTotalsCapacity ) * 100 , 0 )
Write-Output "Total disk space for all servers: "
Write-Output ( "`t Capacity : $DiskTotalsCapacity TB" )
Write-Output ( "`t Used     : $DiskTotalsUsed TB  ($DiskTotalsUsedPercent %)" )
Write-Output ( "`t Available: $DiskTotalsAvailable TB  ($DiskTotalsAvailablePercent %)" )

$F6 = ".\$FileNameRoot-DiskSpace.clixml"
$ServerDiskSpace | Sort-Object UNC | Export-Clixml -Path $F6
Write-Output "Disk Space details saved to: $((Resolve-Path $F6).Path)`n"

<# Disk Space over time #>
$DiskFiles = Get-ChildItem "$PMOutputSubfolder*DiskSpace.*" | Sort-Object Name 
$DiskOverTime = Import-Clixml -Path $DiskFiles.FullName | Select-Object *, @{n='Date'; e={([datetime]($_.DateTime)).ToShortDateString()}} `
                                                        | Sort-Object ComputerName, Drive, Date 

<# ───────── Physical Disks ───────── #>
Invoke-Command -Session $ServersOnlineSessions -ScriptBlock { Try { Get-Partition } Catch { Get-WmiObject -Class Win32_DiskDrive } } -AsJob -JobName "ServerDiskPartitions" | Out-Null
Get-Volume | Out-Null    # This is a hack to get values loaded - like 'HealthStatus'

Write-Output "$($SeparatorLine)Physical/Virtual Disk Drives: "
$ServerPhysicalDisks = Receive-Job -Name "ServerPhysicalDisks" -AutoRemoveJob -Wait | Sort-Object PSComputerName, Number
FixLocalhostName $ServerPhysicalDisks -TrimDomain
$ServerPhysicalDisks | Format-Table PSComputerName, Number `
                                  , @{n='Style'; e={$_.PartitionStyle}} `
                                  , @{n='Type'; e={$_.ProvisioningType}} `
                                  , BusType `
                                  , @{n='AllocatedGB'; e={ [math]::Round(($_.AllocatedSize / (1GB)), 0) } } `
                                  , @{n='SizeGB'; e={ [math]::Round(($_.Size / (1GB)), 0) }} `
                                  , @{n='LargestFreeExtentGB'; e={ [math]::Round(($_.LargestFreeExtent / (1GB)), 0) }} `
                                  , OperationalStatus, HealthStatus, IsActive, IsOffline, IsReadOnly `
                                  , Location, FriendlyName, IsBoot, BootFromDisk, IsSystem

# Virtial/Physical Disk problems
$ServerPhysicalDisksIssues = $ServerPhysicalDisks | Where-Object { $_.IsOffline -or $_.HealthStatus -ne "Healthy" }
if ( @($ServerPhysicalDisksIssues).Count -ge 1 ) { ShowWarning "Disk Offline or not Healthy" `
                                                   ($ServerPhysicalDisksIssues | ForEach-Object { "\\$($_.pscomputername)$RightArrow$($_.Location)$RightArrow$($_.DiskNumber) ($($_.OperationalStatus), $($_.HealthStatus))" }) `
                                                   -ShowCount -Critical -TrimDomain  }

<# ───────── BitLocker Volumes and Key Protectors ───────── #>
Invoke-Command -Session $ServersOnlineSessions2 `
               -ScriptBlock { Try { $bv = Try { Get-BitlockerVolume -ErrorAction SilentlyContinue } Catch { }
###                                 if ( $Null -eq $bv ) { $Null } Else { $bv | Where-Object { $_.VolumeStatus -notin ("Off", "FullyDecrypted") } } 
                                    if ( $Null -eq $bv ) { $Null } Else { $bv | Where-Object { !(("Off", "FullyDecrypted") -contains $_.VolumeStatus) } } 
                                  } Catch { }  
                            } -AsJob -JobName "BitLockerVolumes" | Out-Null

                            Write-Output "$($SeparatorLine)BitLocker Volumes Details: "
$BitLockerVolumes = Receive-Job -Name "BitLockerVolumes" -AutoRemoveJob -Wait | Sort-Object PSComputerName, MountPoint | Select-Object * -ExcludeProperty RunspaceID, PSSourceJobInstanceID
FixLocalhostName $BitLockerVolumes -TrimDomain

# VolumeStatus: Off, FullyDecrypted, FullyEncrypted, Unlocked, EncryptionInProgress, ConversionInProgress
$BitLockerVolumesDetails = $BitLockerVolumes | Select-Object ComputerName, MountPoint, VolumeType `
                                         , @{n='Capacity'; e={[math]::Round($_.CapacityGB,0)}} `
                                         , EncryptionMethod, *Status, AutoUnlockEnabled, EncryptionPercentage `
                                         , @{n='KeyProtectors'; e={$_.KeyProtector -join "`n"}}
                                         
if ( $BitLockerVolumesDetails.Count -eq 0 ) { Write-Output "$tab No BitLocker volumes found"}
Else { $BitLockerVolumesDetails | Format-Table -AutoSize -Wrap ComputerName, MountPoint, VolumeType, Capacity, EncryptionMethod, *Status, AutoUnlockEnabled, *Percentage, KeyProtectors }
 
<# ───────── BitLocker Key Protectors ───────── #>
Invoke-Command -Session $ServersOnlineSessions2 `
               -ScriptBlock { Try { $BL = Get-BitlockerVolume -ErrorAction SilentlyContinue |
                                    Where-Object { $_.VolumeStatus -notin ("Off", "FullyDecrypted") }
                                    $BL | ForEach-Object { 
                                     $currobj = $_
                                     $keys = $_.KeyProtector
                                     $keys | ForEach-Object { Add-Member -InputObject $_ -MemberType NoteProperty -Name 'MountPoint' -Value ($currobj.MountPoint) -Force } 
                                     $keys
                                    }
                                  } Catch { } 
                            } -AsJob -JobName "BitLockerKeyProtector" | Out-Null

$BitLockerKeyProtector = Receive-Job -Name "BitLockerKeyProtector" -AutoRemoveJob -Wait | Sort-Object PSComputerName, MountPoint | Select-Object * -ExcludeProperty RunspaceID, PSSourceJobInstanceID
FixLocalhostName $BitLockerKeyProtector -TrimDomain

Write-Output "$($SeparatorLine)BitLocker Key Protectors: "
if ( $BitLockerKeyProtector.Count -eq 0 ) { Write-Output "$tab No BitLocker key protectors found"}
$BitLockerKeyProtector | Format-Table PSComputerName, MountPoint, KeyProtectorType, KeyProtectorID, KeyFilename, RecoveryPassword

<# ───────── Disk Partitions ───────── #>
Write-Output "$($SeparatorLine)Disk Partitions: "
$ServerDiskPartitions = Receive-Job -Name "ServerDiskPartitions" -AutoRemoveJob -Wait | Sort-Object PSComputerName, DiskNumber, PartitionNumber
Invoke-Command -Session $ServersOnlineSessions -ScriptBlock { Try { Get-Volume } Catch { Get-WmiObject -Class Win32_Volume } } -AsJob -JobName "ServerDiskVolumes" | Out-Null
FixLocalhostName $ServerDiskPartitions -TrimDomain
$ServerDiskPartitions | Format-Table -AutoSize PSComputerName `
                                   , @{n="Drive" ; e={ if ( "" -ne $_.DriveLetter ) { "$($_.DriveLetter):" } }} `
                                   , NoDefaultDriveLetter, OperationalStatus, Type, MBRType, DiskNumber, PartitionNumber `
                                   , @{n='SizeGB'; e={ [math]::Round(($_.Size / (1GB)), 0) }} `
                                   , IsActive, IsBoot, IsSystem, IsOffline, IsReadOnly, DiskPath

<# ───────── Disk Volumes ───────── #>
Write-Output "$($SeparatorLine)Disk Volumes: "
$ServerDiskVolumes = Receive-Job -Name "ServerDiskVolumes" -AutoRemoveJob -Wait | Sort-Object PSComputerName, DiskNumber, PartitionNumber
FixLocalhostName $ServerDiskVolumes -TrimDomain
$ServerDiskVolumes | Format-Table -AutoSize PSComputerName `
                                   , @{n="Drive" ; e={ if ( $Null -ne $_.DriveLetter ) { "$($_.DriveLetter):" } }} `
                                   , FileSystemLabel, DriveType, OperationalStatus, HealthStatus, FileSystem `
                                   , @{n='SizeGB'; e={ [math]::Round(($_.Size / (1GB)), 0) }} `
                                   , @{n='FreeGB'; e={ [math]::Round(($_.SizeRemaining / (1GB)), 0) }} 

<# ───────── Server Shares ───────── #>
Write-Output "$($SeparatorLine)Server Shares: (excluding default shares)"
$ServersShares = Invoke-Command -Session $serversonlineSessions -ScriptBlock { Try { Get-SmbShare -ErrorAction SilentlyContinue } `
                                                                               Catch { Try { Get-CimInstance -ClassName Win32_Share -Property * }  `
                                                                                       Catch { Get-WmiObject -Class Win32_Share -Property * } } `
                                                                             } `
                 | Sort-Object PSComputerName, Path
FixLocalhostName $ServersShares -TrimDomain
$ServersShares = $ServersShares | Select-Object *, @{n='UNC'; e={"\\$($_.PSComputerName.Split('.')[0])\$($_.Name)\"}}

$ServersSharesNonDefault = $ServersShares | Where-Object { $_.ShadowCopy -or ( -not $_.Special -and $_.Description -ne 'Printer Drivers' -and $_.Name -notin ("SYSVOL", "NETLOGON", "IPC$", "ADMIN$", "C$", "D$") ) }
$ServersSharesNonDefault | Format-Table PSComputerName, @{n='Name'; e={ $n=$_.Name; if ($n.length -gt 30) {"$($n.Substring(0,32))..."} else {$n} }}, ShadowCopy, UNC, Path, Description, CurrentUsers

$FileShares = $ServersSharesNonDefault | Sort-Object pscomputername| Where-Object { $_.ShareType -eq 0 } | Group-Object pscomputername
if ( $FileShares.Count -gt 0 ) { Write-Output "$(($FileShares | Measure-Object).Count) Servers with Folder Shares: " } Else { Write-Output "There are no Servers with File shares." }
$FileShares | Format-Table -Wrap Count, @{n='Server Name';e={$_.Name}}, @{n='Folder Share Names' ; e={$_.Group.Name -join ", "}}

$PrintShares = $ServersSharesNonDefault | Sort-Object pscomputername| Where-Object { $_.ShareType -eq 1 } | Group-Object pscomputername
if ( $PrintShares.Count -gt 0 ) { Write-Output "$(($PrintShares | Measure-Object).Count) Servers with Print Shares: " } Else { Write-Output "There are no Servers with Print shares." }
$PrintShares | Format-Table -Wrap Count, @{n='Server Name';e={$_.Name}}, @{n='Printer Share Names'; e={$_.Group.Name -join ", "}}

<# ───────── Server Shares Permissions ───────── #>
Write-Output "$($SeparatorLine)Server Shares Permissions: (excluding default shares)"

$ServersSharesPerms = Invoke-Command -Session $serversonlineSessions -ScriptBlock { Try { 
$shr = Get-SmbShare | Where-Object { -not $_.Special -and $_.ShareType -ne 1 -and $_.Name -ne 'print$' }
$shr | Select-Object @{n='ShareName'; e={$_.Name}}, @{n='Path'  ; e={ ($_.PresetPathAcl.Path -split "::")[-1] }} `
              , @{ n='Owner'  ; e={ $_.PresetPathAcl.owner } } `
              , @{ n="Access" ; e={ $_.PresetPathAcl.access.ForEach( {"$($_.AccessControlType) $($_.IdentityReference)==$($_.FileSystemRights)"} ) -Join "`n" } } `
              , @{ n='UNC'    ; e={ "\\$($env:COMPUTERNAME)\$($_.Name)" } } `
              , * -ErrorAction SilentlyContinue
} Catch { $Null } }

FixLocalhostName $ServersSharesPerms -TrimDomain
$ServersSharesPerms | Sort-Object PSComputerName, ShareName | Format-Table -Wrap PSComputerName, ShareName, Owner, Access
$X = $ServersSharesPerms | Where-Object { $_.Access -Like "*Everyone==FullControl*" }
if ( $X.Count -gt 0 ) { ShowWarning "Server Shares that grant 'Full Control' to 'Everyone'" $X.UNC -ShowCount }
$X = $ServersSharesPerms | Where-Object { $_.Access -Like "*S-1-5-*" }
if ( $X.Count -gt 0 ) { ShowWarning "Server Shares with permissions assigned to deleted AD objects" $X.UNC -ShowCount }

<# ───────── Server SMB Protocol job ───────── #>
$JobSMB = Invoke-Command -Session $ServersOnlineSessions2 `
          -ScriptBlock { Try { Get-SmbServerConfiguration } Catch { [PSCustomObject]@{ ComputerName = $env:computername
                                                                                       EnableSMB1Protocol = $Using:Unknown }
                                                                  } } -AsJob


<# ───────── Check and test various crypto related settings ───────── #>
Invoke-Command -Session $ServersOnlineSessions `
               -ScriptBlock {

## To list all Cipher suites when Get-TLSCipherSuite is not available
## Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002 -Name Functions

$FIPSAPE = Try { $x = Get-ItemPropertyValue -Path 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name 'Enabled' 
                 if ( $x -eq 1 ) { $True } Else { $False } } 
           Catch { Write-Host "Failed to query FIPS configuration on $ENV:COMPUTERNAME" -ForegroundColor Red }                                              ## FIPS enabled flag

$TestMD5    = Try { New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider } Catch { $Null } 
$TestSHA256 = Try { New-Object -TypeName System.Security.Cryptography.SHA256Managed } Catch { $Null } 

$Crypto = [PSCustomObject]@{ ## If these both return True, then FIPS mode is configured/enabled
                             FIPSAlgorithmPolicyEnabled     = $FIPSAPE 
                             AllowOnlyFIPSAlgorithmsEnabled = [System.Security.Cryptography.Cryptoconfig]::AllowOnlyFipsAlgorithms                          ## FIPS mode check
                             ## Trust but verify - if either of these are non-null, non-errors then FIPS mode is not actually enabled
                             TestMD5                        = $TestMD5                   ## FIPS Unaccredited crypto test
                             TestSHA256                     = $TestSHA256                ## FIPS Unaccredited crypto test
                           }  #custom obj

$Crypto | Add-Member -MemberType NoteProperty -Name 'FIPSEnabled'      -Value ( $Crypto.FIPSAlgorithmPolicyEnabled -and $Crypto.AllowOnlyFIPSAlgorithmsEnabled )
$Crypto | Add-Member -MemberType NoteProperty -Name 'FIPSValidated'    -Value ( ($Null -eq $Crypto.TestMD5) -and ($Null -eq $Crypto.TestSHA256) )
$Crypto | Add-Member -MemberType NoteProperty -Name 'ProtocolsEnabled' -Value ([Net.ServicePointManager]::SecurityProtocol).tostring().toupper()            ## SSL and TLS
$Crypto
                            } -AsJob -JobName "CryptoCheck" -ErrorAction SilentlyContinue | Out-Null

Write-Output "$($SeparatorLine)Crypto and Protocols:"
Wait-Job -Name "CryptoCheck" -Timeout 10 | Out-Null
$ServersFIPS = Receive-Job -Name "CryptoCheck" -ErrorVariable +WV
Get-Job -Name "CryptoCheck" | Remove-Job -Force | Out-Null
$ServersFIPS = $ServersFIPS | Select-Object * -ExcludeProperty Runspace*, ComputerName 
FixLocalhostName $ServersFIPS -TrimDomain
$ServersFIPS | Format-Table PSComputerName, *FIPS*, ProtocolsEnabled
$ServersSSL   = $ServersFIPS | Select-Object * -ExcludeProperty Runspace*, ComputerName | Where-Object { $_.ProtocolsEnabled -like "SSL*" } 
$ServersTLS10 = $ServersFIPS | Select-Object * -ExcludeProperty Runspace*, ComputerName | Where-Object { $_.ProtocolsEnabled -like "TLS,*" } 
if ( $Null -ne $ServersSSL   ) { ShowWarning "Servers with SSL protocol enabled" $ServersSSL.PSComputerName -ShowCount -TrimDomain }
if ( $Null -ne $ServersTLS10 ) { ShowWarning "Servers with TLS 1.0 protocol enabled" $ServersTLS10.PSComputerName -ShowCount -Max 6 -TrimDomain }

<# ───────── Server IPCONFIG ───────── #>
Write-Output "$($SeparatorLine)Servers IPCONFIG: "
 ## Need to convert to use CIMSesssions to avoid a PSSession deserialiation bug that on occassion produces an unsuppresable error message

$ServersIPCONFIGAll = Invoke-Command -Session $ServersOnlineSessions -ScriptBlock ${Function:Get-IPConfigAll}

$ServersIPCONFIG = $ServersIPCONFIGAll | Select-Object `
                    @{ n = 'Host'                 ; e = { $_.computername } } `
                  , @{ n = 'ProfileName'          ; e = { $_.ProfileName -Join "`n" } } `
                  , @{ n = 'ifAlias'       ; e = { $_.NetProfile.InterfaceAlias} } `
                  , @{ n = 'ifIndex'       ; e = { $_.NetProfile.InterfaceIndex -Join "`n" } } `
                  , @{ n = 'NetworkCategory'      ; e = { $_.NetProfile.NetworkCategory } } `
                  , @{ n = 'IPV4Connectivity'     ; e = { $_.NetProfile.IPV4Connectivity } } `
                  , @{ n = 'Status'               ; e = { $_.NetIPConfig.NetAdapter.Status } } `
                  , @{ n = 'ConnectionState'      ; e = { $_.NetIPConfig.NetAdapter.MediaConnectionState } } `
                  , @{ n = 'LinkSpeed'            ; e = { $_.NetIPConfig.NetAdapter.LinkSpeed } } `
                  , @{ n = 'MTU'                  ; e = { $_.NetIPConfig.NetAdapter.MTUSize } } `
                  , @{ n = 'MACAddress'           ; e = { $_.NetIPConfig.NetAdapter.MACAddress } } `
                  , @{ n = 'ifDescription' ; e = { $_.NetIPConfig.NetAdapter.InterfaceDescription } } `
                  , @{ n = 'Def. g/w'             ; e = { if ( $Null -ne $_.DefGW ) { $_.DefGW } Else { $_.netipconfig.IPv4DefaultGateway.nexthop } } } `
                  , @{ n = 'DNSServers' ; e = { $d = $_.NetIPConfig.DNSServer ; if ( $Null -ne $d ) { $d.serveraddresses -join "`n" } Else { '' } } } `
                  , @{ n = 'AddressFamily'        ; e = { $_.NetIPAddress.AddressFamily -Join "`n" } } `
                  , @{ n = 'IPAddress'            ; e = { if ( $Null -eq $_.NetIPAddress.IPAddress ) { $_.NetIPAddress } Else { $_.NetIPAddress.IPAddress -Join "`n" } } } `
                  , @{ n = 'SubnetMask'           ; e = { if ( $Null -ne $_.SubnetMask ) { $_.SubnetMask } Else { Try { (Convert-CIDRtoMask ([int]$_.NetIPAddress.PrefixLength)) } Catch { ($_.SubnetMask) } } } } `
                  , @{ n = 'IPAddressSort'        ; e = { ($_.NetIPAddress.IPAddress -as [IPAddress]).Address } } `
                  , @{ n = 'IPAddressSort2'       ; e = { $v = [version]$_.NetIPAddress.IPAddress ; ($v.Major * 1000000000) + ($v.Minor * 1000000) + ($v.Revision * 1000) + $v.Build} } `
                  , @{ n = 'Prefix'               ; e = { if ( $Null -ne $_.SubnetMask ) { Convert-MasktoCIDR $_.SubnetMask } Else { $_.NetIPAddress.PrefixLength -Join "`n" } } } `
                  , @{ n = 'DHCP'                 ; e = { $_.NetIPAddress.PrefixOrigin -Join "`n" } }

$ServersIPCONFIG | Sort-Object IPAddressSort2 | Format-table -Wrap Host, ProfileName, IPAddress, Prefix, SubnetMask, 'Def. g/w', @{e='DNSServers' ; Width=20 }, DHCP, LinkSpeed, MTU, MACAddress, ifIndex, ifDescription

$ServersIPAssignment = $ServersIPCONFIG | Group-Object DHCP | Select-Object Count, @{n='IP Assigned by'; e={$_.Name} }, @{n='Servers'; e={$_.Group.Host -join ", "} }
$ServersIPAssignment | Format-Table

$ServerAssignedByDHCP = $ServersIPAssignment | Where-Object { $_."IP Assigned by" -eq "Dhcp" }
if ( @($ServerAssignedByDHCP).Count -gt 0 ) { ShowWarning "Servers with IP addresses assigned by DHCP" (($ServerAssignedByDHCP.Servers -split ", ") | Sort-Object -Unique) -ShowCount } 

$ServerAssignedByDHCP = $ServersIPAssignment | Where-Object { $_."IP Assigned by" -eq "WellKnown" }
if ( @($ServerAssignedByDHCP).Count -gt 0 ) { ShowWarning "Servers with IP addresses assigned by APIPA" (($ServerAssignedByDHCP.Servers -split ", ") | Sort-Object -Unique) -ShowCount } 

$ServersVNIC = $ServersIPconfig | Where-Object { $_.MACAddress -like "00-50-56-*" -and $_.ifDescription -notlike "*vmxnet*" }
if ( @($ServersVNIC).Count -gt 0 ) { ShowWarning "VMWare Servers without VMXNET driver" ( @($ServersVNIC) | ForEach-Object {"\\$($_.host): $($_.ifAlias)/$($_.ifDescription)"}) -ShowCount -NoMax } 

$ServersSlowNIC = $serversipconfig | Where-Object { $_.linkspeed -notmatch "(Gbps)" } 
if ( @($ServersSlowNIC).Count -gt 0 ) { ShowWarning "Server NICs below gigabit speeds" ( @($ServersSlowNIC) | ForEach-Object { "\\$($_.host): $($_.ifAlias) @ $($_.LinkSpeed)" } ) -ShowCount -NoMax } 

$AvgLinkSpeed = ($serversipconfig | Group-Object linkspeed -NoElement)[0].name
$ServersDiffNIC = $serversipconfig | Where-Object { $_.linkspeed -notmatch $AvgLinkSpeed -and $_.linkspeed -notmatch "Gbps" } 
if ( @($ServersDiffNIC).Count -gt 0 ) { ShowWarning "Server NICs not running at $AvgLinkSpeed" ( @($ServersDiffNIC) | ForEach-Object {"\\$($_.host): $($_.ifAlias) @ $($_.LinkSpeed)"}) -ShowCount -NoMax } 


<# ───────── DHCP Servers ───────── #>
Write-Output "$($SeparatorLine)DHCP servers for domain $($AD.DNSRoot):"
$DHCPServers = Try { Get-DHCPServerInDC -ErrorAction SilentlyContinue } Catch { $Null }

If ( $Null -ne $DHCPServers )
{  $DHCPServers | Format-Table -AutoSize
   $DHCPScopes = $DHCPServers | ForEach-Object { $D = $_ ; Try { Get-DhcpServerv4Scope -ComputerName $D.dnsName -ErrorAction SilentlyContinue `
                                                   | Select-Object @{n='ComputerName'; e={ $D.DNSName } } `
                                                                 , @{n='IPType'; e={ if ( Test-PrivateIP -IP $_.ScopeID.IPAddressToString ) { 'Private' } Else { 'Public' } } } `
                                                                 , Name, * -ErrorAction SilentlyContinue  } `
                                             Catch { "Unable to retrieve DHCP info: '$_'" } }

   Write-Output "DHCP Scopes Summary: "
   $DHCPScopes | Group-Object computername | Select-Object Count, Name, @{n='Scopes'; e={$_.Group.ScopeID -Join ", " }}

   Write-Output "`nDHCP Scopes Details: "
   $DHCPScopes | Format-Table -AutoSize

   $PublicIPonDHCP = $DHCPScopes | Where-Object { $_.iptype -eq 'Public' } `
                                 | Select-Object *, @{n='Server'; e={ ($_.computername -split '\.')[0] }} `
                                 | Sort-Object ScopeID | Group-Object ScopeID `
                                 | Select-Object @{n='ScopeID'; e={$_.Name}}, @{n='Servers'; e={$_.Group.Server -Join ", " }}

   if ( $Null -ne $PublicIPonDHCP ) { Write-Warning ( "DHCP is configured with Public IP address Scopes: $($PublicIPonDHCP.ScopeID -Join ", ")" `
                                                    + " on Servers: $(($PublicIPonDHCP.Servers -Split ", " | Sort-Object | Select-Object -Unique ) -Join ", ")" ) `
                                                    -WarningAction Continue -WarningVariable +WV  }
  

   ## Get-DhcpServerv4Reservation '10.20.1.0' | Format-Table -AutoSize

}  ## DHCPServers not null
Else { ShowWarning "Unable to get list of DHCP servers"  }

If ( $Null -ne $DHCPServers ) { $DHCPServersOnline = $DHCPServers.DNSName | Test-NetConnection -ErrorAction SilentlyContinue | Where-Object { $_.PingSucceeded }
                                Write-Progress -Completed -Activity "PING DHCP servers completed" }
Else { $DHCPServersOnline = $Null }

If ( $Null -ne $DHCPServersOnline ) {
   

   ###################   $ServersCIMSessions
   $DHCPServerCIM = $ServersCIMSessions | Where-Object { $_.computername -in $DHCPServersOnline.ComputerName.replace($LocalDNSHost.ToLower(), "localhost") } 
   $CompName = @{n='ComputerName'; e={$_.PSComputerName -replace "localhost", $LocalDNSHost}}

     Write-Output "`nDHCP Failover Scopes: "    
     # $DHCPServerV4Failover = $DHCPServersOnline.ComputerName.replace($LocalDNSHost.ToLower(), "localhost") | ForEach-Object { Invoke-Command -ComputerName $_ -ScriptBlock { Try { Get-DHCPServerV4Failover } Catch {  } } }
     #FixLocalhostName $DHCPServerV4Failover -TrimDomain
     $DHCPServerV4Failover = $DHCPServerCIM | ForEach-Object { Get-DHCPServerV4Failover -CimSession $_ } 
     $DHCPServerV4Failover | Select-Object * -ExcludeProperty RunspaceID, PSShow*, CIM* | Format-Table -Autosize $CompName, *

     Write-Output "`nDHCP Scopes Statistics: "
     #$DhcpServerv4ScopeStatistics = $DHCPServersOnline.ComputerName.replace($LocalDNSHost.ToLower(), "localhost") | ForEach-Object { Invoke-Command -ComputerName $_ -ScriptBlock { Try { Get-DhcpServerv4ScopeStatistics } Catch {  } } }
     #fixLocalhostName $DhcpServerv4ScopeStatistics -TrimDomain
     $DhcpServerv4ScopeStatistics = $DHCPServerCIM | ForEach-Object { Get-DhcpServerv4ScopeStatistics -CimSession $_ } 
     $DhcpServerv4ScopeStatistics | Select-Object * -ExcludeProperty RunspaceID, PSShow*, CIM* | Format-Table -Autosize $CompName, ScopeID `
                                                , @{n="PercentUsed"; e={[math]::Round($_.PercentageInUse,2)}} `
                                                , Free, InUse, Reserved, Pending

     ## DHCP Scope high utilization
     $DHCPHighUtil = $DhcpServerv4ScopeStatistics | Where-Object { $_.PercentageInUse -gt 80 }
     if ( $DHCPHighUtil.Count -gt 0 ) { ShowWarning ($DHCPHighUtil.foreach({ "Scope $($_.scopeid.ipaddresstostring) at $([math]::Round($_.PercentageInUse,0))% in use on $($_.pscomputername)" } ) -join "; " ) }
            
     ## DHCP Server Settings
     Write-Output "`nDHCP Server Settings: "
     #$DHCPServerSettings = $DHCPServersOnline.ComputerName.replace($LocalDNSHost.ToLower(), "localhost") | ForEach-Object { Invoke-Command -ComputerName $_ -ScriptBlock { Try { Get-DhcpServerSetting } Catch {  } } }
     #FixLocalhostName $DHCPServerSettings -TrimDomain
     $DHCPServerSettings = $DHCPServerCIM | ForEach-Object { Get-DhcpServerSetting -CimSession $_ }  
     $DHCPServerSettings | Format-Table -AutoSize PSComputerName, Is*, NAP*, Conflict*, ActivatePolicies, DynamicBootP, NPS*, RestoreStatus

     ## Warn if: Not Auth, Conflict <1 or >4
     $DHCPx1 = $DHCPServerSettings | Where-Object { $_.conflictdetectionattempts -lt 1 -or $_.conflictdetectionattempts -gt 4 }
     if ( $DHCPx1.count -gt 0 ) { ShowWarning "DHCP Conflict Detection not enabled" $DHCPx1.PSComputerName -ShowCount -TrimDomain }

     $DHCPx2 = $DHCPServerSettings | Where-Object { -not $_.IsAuthorized }
     if ( $DHCPx2.count -gt 0 ) { ShowWarning "DHCP server not authorized" $DHCPx2.PSComputerName -ShowCount -TrimDomain }
    }


<# ───────── DNS Servers ───────── #>
Write-Output "$($SeparatorLine)DNS servers for domain $($AD.DNSRoot):"
$DNS | Sort-Object Name | Format-Table -AutoSize
# ShowInfo "Waiting for DNS info background jobs to complete ..."

Write-Output "`nDNS Forwarders:"
Get-Job     -Name "DNS-Forward*" | Where-Object { $_.State -eq 'Failed' } | Remove-Job -Force | Out-Null
Wait-Job    -Name "DNS-Forward*" -Timeout 10 | Out-Null
$DNSForwards = Receive-Job -Name "DNS-Forward*"
Get-Job     -Name "DNS-Forward*" | Remove-Job -Force | Out-Null
FixLocalhostName $DNSForwards
$DNSForwards | Select-Object * -ExcludeProperty Runspace*, cim* | Format-Table -AutoSize 
$DNSForwardersList = $DNSForwards.ipaddress | Sort-Object | Select-Object -Unique
if ( $Null -eq $DNSForwardersList -or $DNSForwardersList.Count -eq 0 ) { $DNSForwardersList = "8.8.8.8" }

Write-Output "`nDNS Scavenging:"
Get-Job     -Name "DNS-Scavenge*" | Where-Object { $_.State -eq 'Failed' } | Remove-Job -Force | Out-Null
Wait-Job    -Name "DNS-Scavenge*" -Timeout 10 | Out-Null
$DNSScavenge = Receive-Job -Name "DNS-Scavenge*" | Sort-Object PSComputerName
Get-Job     -Name "DNS-Scavenge*" | Remove-Job -Force | Out-Null
FixLocalhostName $DNSScavenge
$DNSScavenge | Select-Object * -ExcludeProperty Runspace*, cim* | Format-Table -AutoSize 
$DNSScavengeConcern2 = $DNSScavenge | Where-Object { $_.ScavengingState -eq $true }
if ( @($DNSScavengeConcern2).Count -lt 1 ) { ShowWarning "DNS Scavenging not enabled on any DNS servers"}

### DNS Scavenging from Event Log
Get-Job     -Name "DNS-EventLog*" | Where-Object { $_.State -eq 'Failed' } | Remove-Job -Force | Out-Null
Wait-Job    -Name "DNS-EventLog*" -Timeout 10 | Out-Null
$DNSEventLog = Receive-Job -Name "DNS-EventLog*"
Get-Job     -Name "DNS-EventLog*" | Remove-Job -Force | Out-Null

FixLocalhostName $DNSEventLog
$now = Get-Date  

$DNSEventLog2 = $DNSEventLog | Select-Object @{n='ScavengeInterval'; e={ $dx = ($DNSScavenge.PSComputerName).tolower().indexof($_.PSComputerName.tolower() ) ;
                                                                         $DNSScavenge[$dx].ScavengingInterval.TotalMinutes } } `
                                             , *, @{n='Message'; e={$_.Message.Replace("`n", " ") }}  -ErrorAction SilentlyContinue

$DNSEventLog2 | Format-Table -AutoSize MachineName, ScavengeInterval, TimeCreated, ID, LevelDisplayname, TaskDisplayName, Message
                                                   
$DNSScavengeConcern3 = $DNSEventLog2 | Where-Object { $_.TimeCreated -lt $now.AddMinutes( $_.ScavengeInterval * -1 ) } 

if ( $Null -ne $DNSScavengeConcern3 ) { $d2 = $DNSScavengeConcern3 | ForEach-Object { "$($_.PSComputerName) @ $($_.TimeCreated)" }
                                        ShowWarning "Last DNS Scavenging past interval" $d2 -ShowCount }

<# ───────── AD DNS Zones ───────── #>
Write-Output "`nDNS Zones:"
Get-Job     -Name "DNS-Zone*" | Where-Object { $_.State -eq 'Failed' } | Remove-Job -Force | Out-Null
Wait-Job    -Name "DNS-Zone*" -Timeout 10 | Out-Null
$DNSZones = Receive-Job -Name "DNS-Zone*"
Get-Job     -Name "DNS-Zone*" | Remove-Job -Force | Out-Null
FixLocalhostName $DNSZones
$DNSZones | Sort-Object IsReverseLookupZone, ZoneName, PSComputerName | Select-Object ZoneName, PSComputerName, * -ExcludeProperty Runspace*, cim*, Distinguish* -ErrorAction SilentlyContinue `
          | Format-Table -AutoSize -GroupBy IsReverseLookupZone 

<# ───────── Verify that each subnet has a reverse lookup zone in DNS ───────── #>
If ( $Null -ne $ADSites ) {
  $Revs = foreach ( $ssn in  $SiteSubnets ) { # $SubnetMask = [int]($ssn.name -split "/")[-1] 
                                      $SubnetArray = ($ssn.name -split "/")[0] -split "\." 
                                      ## $ssn.Description, $ssn.name
                                      $RevZone = @( "$($SubnetArray[0]).in-addr.arpa", 
                                                    "$($SubnetArray[1]).$($SubnetArray[0]).in-addr.arpa",  
                                                    "$($SubnetArray[2]).$($SubnetArray[1]).$($SubnetArray[0]).in-addr.arpa", 
                                                    "$($SubnetArray[3]).$($SubnetArray[2]).$($SubnetArray[1]).$($SubnetArray[0]).in-addr.arpa" 
                                                  )

                                      $RZ = $RevZone | ForEach-Object { if ( $_ -in $dnszones.zonename ) { "Reverse lookup zone $_ exists for $($ssn.name)" } Else { "Reverse lookup zone not found for $($ssn.name)" } } 
                                      if ( $RZ -like "*exists*" ) { $RZ -like "*exists*" } Else { $RZ -notlike "*exists*" }
                                     }  # foreach
    $Revs = $Revs | Sort-Object | Select-Object -Unique
    if ( $Revs -like "*not found*" ) { ShowWarning "Missing DNS Reverse lookup zones" ($Revs -like "*not found*") -ShowCount }
                           }  #if ADSites


<# ───────── DCDiag Analysis ───────── #>
Write-Output "$($SeparatorLine)DC Diag:"
Get-Job     -Name "DCDiag*" | Where-Object { $_.State -eq 'Failed' } | Remove-Job -Force | Out-Null
Wait-Job    -Name "DCDiag*" -Timeout 10 | Out-Null
$DCDiag = Receive-Job -Name "DCDiag*"
Get-Job     -Name "DCDiag*" | Remove-Job -Force | Out-Null

if ( $Null -eq $DCDiag ) { ShowWarning "Unable to run DCDiag on server" $DomainControllers[0].HostName }
Else { FixLocalhostName $DCDiag

$DCDiagSummary  = ($DCDiag | Where-Object { $_ -like "*ed Test *" }).Replace(".....", "").Trim()
$DCDiagServers  = ($DCDiag | Where-Object { $_ -like "*testing server*" } | Sort-Object -Unique ).substring(19) 
Write-Output "`n$($DCDiagServers.Count) servers tested: $($DCDiagServers -join ', ')"
$DCDiagPassed   = $DCDiagSummary | Where-Object { $_ -like "*passed test*" }
$DCDiagFailures = $DCDiagSummary | Where-Object { $_ -like "*failed test*" -and $_ -notlike "*SystemLog*" }
Write-Output "`nDCDiag: $($DCDiagPassed.Count) tests passed, $($DCDiagFailures.Count) tests failed (excluding 'SystemLog' failures): "
$DCDiagFailures.ForEach({"`t> $_"})
Write-Output " "
if ( $Null -ne $DCDiagFailures ) { ShowWarning "DCDiag failures on server" $DCDiagFailures }

$F6 = ".\$FileNameRoot-DCDiag.txt"
$DCDiag | Out-File -FilePath $F6 -Encoding utf8
Write-Output "DCDiag details saved to: $((Resolve-Path $F6).Path)`n"
}   ## else null $DCDiag



<# ───────── AD Integrated Cert Authority ───────── #>
Write-Output "$($SeparatorLine)$($AD.DNSRoot) AD Integrated Certificate Authorities (CA):"

$CA = Get-ADObject -Filter "objectClass -eq 'certificationAuthority'" `
                   -SearchBase "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,$($AD.DistinguishedName)" `
                   -Properties * | Sort-Object Created | Select-Object * -ExcludeProperty *Cert*
$CA | Format-Table -AutoSize -Wrap Name, objectClass, Created, Modified, DistinguishedName
if ( $CA.Count -gt 1 ) { ShowWarning "There should only be one Cert Authority (CA)" $CA.Name -ShowCount }

$CAES = Get-ADObject -Filter "objectClass -eq 'pkiEnrollmentService'" `
-SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$($AD.DistinguishedName)" `
                   -Properties * | Sort-Object Created | Select-Object * -ExcludeProperty *Cert*
$CAES | Format-Table -AutoSize -Wrap dnsHostName, Name, objectClass, Created, Modified, DistinguishedName
if ( $CAES.Count -gt 1 ) { ShowWarning "There should only be one Cert Enrollment Server (CES)" $CAES.Name -ShowCount }


<# ───────── Computers certs ───────── #>
Write-Output "$($SeparatorLine)Local Computer Certificates Status:"
$Certs = Invoke-Command -Session $ServersOnlineSessions2 -ScriptBlock { 
 Get-ChildItem "Cert:\LocalMachine\My\" | Sort-Object NotBefore | Select-Object * `
                    , @{n='Status'; e={ if ($_.NotAfter -lt $Using:RunStartDateTime) {'Expired'} 
                                        ElseIf ( ($Using:RunStartDateTime).AddDays($Using:ObservationWindow * 2) -gt $_.notafter) { "Expiring within $($Using:ObservationWindow * 2) days" }
                                        Else {'OK'} } } `
                    , @{n='Expires'; e={($_.NotAfter).toshortdatestring()}} `
                    , @{n='Issued'; e={($_.NotBefore).toshortdatestring()}} `
                    , @{n='IssuerDetails'; e={($_.Issuer).Replace(",", "`n`r")} } `
                    , @{n='SubjectDetails'; e={($_.Subject).Replace(",", "`n`r")} } `
                    -ErrorAction SilentlyContinue
                     } -ErrorAction SilentlyContinue

FixLocalhostName $certs
$Certs.foreach({ $_.PSComputerName = ($_.PSComputerName -split "\.")[0]})
$Certs  | Sort-Object Expires, PSComputerName | Format-Table  -AutoSize PSComputerName, Issued, Expires, Status, FriendlyName, *Details, *

$CertsSummary = $Certs | Sort-Object Status, PSComputerName | Group-Object Status
$CertsSummary | Format-Table Count, @{n='Status'; e={$_.Name}}, @{n='Servers'; e={ ( ($_.Group).PSComputerName | Sort-Object -Unique ) -join ", " } }

$CertsSummary | Where-Object { $_.name -like "Expir*" } | ForEach-Object {
 ShowWarning "Local Computer Certificates $($_.name)" $_.group.foreach({"\\$($_.PSComputername) | $(($_.SubjectName.Name -split ',')[0]) | $($_.FriendlyName)"}) -ShowCount -Max 6
}


<# ───────── Public IP ───────── #>
Write-Output "$($SeparatorLine)Public IP Info by Site:"
$URLARINbase = 'http://whois.arin.net/rest'
$ARINheader  = @{"Accept" = "application/xml"}   #default is XML anyway
$URLipify    = 'https://api64.ipify.org?format=json'

<# Get public IP info for each AD site #>
$DCbySite = $DomainControllers | Group-Object Site
$PublicIPInfoBySite = $DCbySite | ForEach-Object {
  $x = ($serversonlineSessions.computername).indexof($_.group[0].hostname)
  $PublicIPSite = Invoke-Command -Session $ServersOnlineSessions[$x] -ScriptBlock {

    $PublicIP = Try { Invoke-WebRequest -uri $Using:URLipify -UseBasicParsing } Catch { $Null }
    If ( $Null -ne $PublicIP ) { $PublicIP = $PublicIP.Content | ConvertFrom-Json }

    $PublicIPInfo = Try { Invoke-RestMethod "https://ipinfo.io/$($PublicIP.IP)/geo" -ErrorAction SilentlyContinue } Catch { $Null }
    If ( $Null -ne $PublicIPInfo.IP ) { $PublicIPInfo = $PublicIPInfo | Select-Object IP, HostName, @{Name='CityState'; Expression={ "$($_.City), $($_.Region)  $($_.Postal)  ($($_.Country)) " }}, loc, org, TimeZone, * -ErrorAction SilentlyContinue }

    Try {
       $ip1 = Invoke-Restmethod "$Using:URLARINbase/ip/$($PublicIP.IP)?showDetails=true" -Headers $Using:ARINheader -ErrorAction SilentlyContinue

      If ($ip1.net) { $ip2 = [pscustomobject]@{
                             PSTypeName   = "WhoIsResult"
                             IP           = $PublicIP.IP
                             Name         = $ip1.net.CustomerRef.name
                             StartAddress = $ip1.net.startAddress
                             EndAddress   = $ip1.net.endAddress
                             NetBlocks    = $ip1.net.netBlocks.netBlock | foreach-object {"$($_.startaddress)/$($_.cidrLength)"}
                             Registered   = $ip1.net.registrationDate -as [datetime]
                             Updated      = $ip1.net.updateDate -as [datetime]
                                              }

     }  ## If $ip1.net

    # Write-Output "Public IP details: "
    foreach ( $P in $ip2.psobject.properties )        { $PublicIPInfo | Add-Member -MemberType NoteProperty -Name $P.Name -Value $P.Value -ErrorAction SilentlyContinue }
    $PublicIPInfo

    } Catch { $Null }

  }  ## Invoke

  foreach ( $P in $_.Group[0].psobject.properties ) { $PublicIPSite | Add-Member -MemberType NoteProperty -Name $P.Name -Value $P.Value -ErrorAction SilentlyContinue }
  $PublicIPSite

}   ## ForEach

FixLocalhostName $PublicIPInfoBySite
$PublicIPInfoBySite | Format-Table -AutoSize -Wrap Site, PSComputerName, @{n='Public IP'; e={$_.IP}}, StartAddress, EndAddress, NetBlocks, Updated, CityState, org, TimeZone
## $PublicIPInfoBySite | Format-List Site, PSComputerName, @{n='Public IP'; e={$_.IP}}, StartAddress, EndAddress, NetBlocks, Updated, CityState, org, TimeZone, Name, Registered
Write-Output " "
Write-Progress -Activity "Done" -Completed

<# ───────── Email Domain, SPF, DKIM, DMARC ───────── #>
### Best guess at the public email domain name
### Summarize domain on primary email address
$e1 = $ADUsers | Where-Object { ( $Null -ne $_.EmailAddress   ) -and $_.OU -notlike "*External*" }
$Email1 = $e1 | ForEach-Object { ($_.emailaddress -split '@')[-1].tolower() } 
### Summarize SMTP address in list of proxy addresses - uppercase SMTP indicates the prefered/outbound email address
$e1 = $ADUsers | Where-Object { ( $Null -ne $_.proxyAddresses ) -and $_.OU -notlike "*External*" }
$Email2 = $e1.proxyAddresses | Where-Object { $_ -clike "SMTP*" } | ForEach-Object { ($_ -split "@")[-1] } 
$EmailDomain = ( $Email1 + $Email2 | Sort-Object | Group-Object -NoElement | Sort-Object Count )[-1].Name

$DNSBad = @() ; $DNSGood = @()
foreach ( $DNSsrv in $DNSForwardersList ) { $DNR = Resolve-DnsName $EmailDomain -Server $DNSsrv -ErrorAction SilentlyContinue
                                            if ( $Null -eq $DNR ) { $DNSBad += $DNSsrv } Else { $DNSGood += $DNSsrv } }
if ( $DNSBad.Count -gt 0 ) { ShowWarning "Public DNS forwarders not responding" $DNSBad -ShowCount -Critical }
Else { Write-Output "All $($DNSGood.Count) DNS forwarders are valid and responding: $($DNSGood -join ', ')" }

if ( -not [string]::IsNullOrEmpty( $EmailDomain ) )
{ Write-Output "$($SeparatorLine)SPF, DKIM, DMARC for Email domain: $EmailDomain"
  ### SPF/DKIM/DMARC query
  $EmailDomainSPF = Resolve-DnsName $EmailDomain -Type TXT -Server $DNSGood[0] -ErrorAction SilentlyContinue                              ## SPF
  if ( $Null -eq $EmailDomainSPF ) { $EmailDomainSPF = Resolve-DnsName $EmailDomain -Type TXT -Server $DNSGood[0] -ErrorAction SilentlyContinue }   # Retry once on error
  if ( [string]::IsNullOrEmpty( $EmailDomainSPF ) )
  { ShowWarning "Unable to locate SPF record for $EmailDomain" -Critical }
  Else  { $EmailDomainSPF | Where-Object { $_.Strings -like "*spf*" } | Format-Table -AutoSize }

  $EmailDomainDKIM  = @( "selector1", "selector2", "default", "dkim", "google", "k1", "mxvault", "zoho", "mailchimp", "sendgrid", "amazonses", "everlytickey1" ) `
                         | ForEach-Object { Resolve-DnsName "$_._domainkey.$EmailDomain" -Server $DNSGood[0] -Type TXT -ErrorAction SilentlyContinue }  `
                         | Where-Object { $_.querytype -notin ('SOA') }
  if ( [string]::IsNullOrEmpty( $EmailDomainDKIM ) )
  { ShowWarning "Unable to locate DKIM record for $EmailDomain" -Critical }
  Else  { $EmailDomainDKIM | Format-Table -AutoSize -wrap Name, Type, TTL, @{n='Data'; e={$_.NameHost + $_.Strings}} }

  $EmailDomainDMARC = Resolve-DnsName "_dmarc.$EmailDomain" -Type TXT -Server $DNSGood[0] -ErrorAction SilentlyContinue      ## DMARC
  if ( [string]::IsNullOrEmpty( $EmailDomainDMARC ) -or $EmailDomainDMARC.Name -notlike "_dmarc*"  )
  { ShowWarning "Unable to locate DMARC record for $EmailDomain" }
  Else  { $EmailDomainDMARC | Format-Table -AutoSize
          if ($EmailDomainDMARC.Strings -like "*p=none*") { ShowWarning "DMARC policy is 'none'; At minimum should be 'quarantine', best is 'reject'" -Critical } }

}  ## Null or empty $EmailDomain
Else { ShowWarning "Unable to determine email domain" }

<# ───────── Main Website (assumed) ───────── #>
$www = "www.$EmailDomain"
Write-Output "$($SeparatorLine)Web site '$www': "
$httpIP = Resolve-DnsName "www.$EmailDomain" 

### Enable secure protocols: 
# [Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"
# Not all server versions support TLS 1.3
Try { [Net.ServicePointManager]::SecurityProtocol = "Tls13, Tls12" } Catch { [Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11" }

if ( $Null -ne $httpIP ) { $httpIP | Format-Table Name, Address, QueryType, TTL
                           $http    = Try { Invoke-WebRequest "http://www.$EmailDomain"  -UseBasicParsing -UseDefaultCredentials } Catch { $Null }
                           $https   = Try { Invoke-WebRequest "https://www.$EmailDomain" -UseBasicParsing -UseDefaultCredentials } Catch { $Null }
                           $website = $http, $https | Select-Object -Unique
                           $website.BaseResponse | Format-Table ResponseUri, @{n='StatusCode'; e={$website.StatusCode}}, StatusDescription, Server, LastModified }
Else { ShowWarning "Unable to lookup 'www.$EmailDomain'" }

<# ───────── Windows Firewall ───────── #>
Write-Output "$($SeparatorLine)Windows Firewall Status: "
Get-NetFirewallProfile -PolicyStore "ActiveStore" | Out-Null      ## This is needed to trick PS into using value names instead of numbers
$fw = Invoke-Command -Session $ServersOnlineSessions -ScriptBlock { $x = Get-NetFirewallProfile -PolicyStore ActiveStore
                                                                    $y = Get-NetConnectionProfile 
                                                                    $x | Select-Object * `
                                                                    , @{n='CurrentProfile'; e={ if ( $y.NetworkCategory -like "$($_.Profile)*" ) { $y.IPv4Connectivity } }} `
} -ErrorAction SilentlyContinue | Sort-Object PSComputerName, Profile
FixLocalhostName $fw
$fw | Format-Table -AutoSize PSComputername, Profile, Enabled, CurrentProfile `
                           , @{n='DefInAction'; e={$_.DefaultInboundAction}} `
                           , @{n='DefOutAction'; e={$_.DefaultOutboundAction}} `
                           , @{n='AllowLocalRules'; e={$_.AllowLocalFirewallRules}}, Log*ed, LogFileName

$NotDomainProfile = $fw | Where-Object { "" -ne $_.currentprofile -and $_.Profile -ne 'Domain' }
if ( $Null -ne $NotDomainProfile ) { $x = $NotDomainProfile | ForEach-Object { "$($_.PSComputername):$($_.Profile)" }
                                     ShowWarning "Current network profile is not 'Domain'" $x -TrimDomain }

<# ───────── Server SMB Protocols ───────── #>
##$JobSMB = Invoke-Command -Session $ServersOnlineSessions2 `
##          -ScriptBlock { Try { Get-SmbServerConfiguration } Catch { "$($env:computername)`t`t`tUnknown" } } -AsJob
Write-Output "$($SeparatorLine)SMB Protocol Configuration: "
## https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
Wait-Job $JobSMB | Out-Null
$ServerSMB = Receive-Job $JobSMB -Wait -AutoRemoveJob
FixLocalhostName $ServerSMB
$ServerSMB | Format-Table @{Name='ComputerName'; Expression={$_.PSComputerName}}, EnableSMB1*, AuditSMB1Access, @{Name='EnableSMB2andSMB3'; Expression={$_.EnableSMB2Protocol}}, *Encrypt*

### [2023-02-21] Daniel F. Fortuna: # add in the bottom Warnings section any servers with SMBv1 turned on
$ServerSMB1 = $ServerSMB | Where-Object { $_.EnableSMB1Protocol }
if ( $null -ne $ServerSMB1 ) { ShowWarning "SMB1 is enabled on servers" $ServerSMB1.pscomputername -TrimDomain -ShowCount }

<# ───────── Server Roles ───────── #>
# get-package "Microsoft SQL Server*Setup*" | sort name
$ServerRolesJob = Invoke-Command -Session $ServersOnlineSessions -ScriptBlock { Try { Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object {$_.InstallState -eq 'Installed' -and $_.featuretype -eq 'Role' } } `
                                                                                Catch { [PSCustomObject]@{ ComputerName = $ENV:COMPUTERNAME
                                                                                                           Role         = $Using:Unknown } } } -ErrorAction SilentlyContinue -AsJob -JobName "ServerRoles"
ShowInfo "Waiting for Server Roles info background jobs to complete ..."

Write-Output "$($SeparatorLine)Server Roles summary: "
Wait-Job -Name "ServerRoles*" -Timeout 20 | Out-Null
$ServerRoles = Receive-Job -Job $ServerRolesJob
Get-Job -Name "ServerRoles*" | Remove-Job -Force | Out-Null
FixLocalhostName $ServerRoles -TrimDomain
$ServerRoles = $ServerRoles | Sort-Object displayname, pscomputername | Select-Object @{n='ComputerName'; e={ ($_.PSComputerName -split "\.")[0] } } , * -ErrorAction SilentlyContinue | Group-Object DisplayName 
$ServerRoles | Format-Table -AutoSize -Wrap `
                 Count `
                 , @{n='Role'; e={ if ($_.Name -eq '') { $Unknown } Else { $_.Name } }} `
                 , @{n='Computer Name'; e={ $_.Group.ComputerName -join ", "}}

<# ───────── Installed Programs ───────── #>
Write-Output "$($SeparatorLine)Installed Programs Summary by Major Version # (excludes updates and other noise): "

### List of installed programs (excluding MS updates)
$ServersInventory = Invoke-Command -Session $ServersOnlineSessions2 -ScriptBlock {
  $p = Try { Get-Package -ErrorAction SilentlyContinue | `
                Select-Object Name, * -Exclude SWID*, Meta*, Attrib* `
                            , PropertyOfSoftwareIdentity, FastPackageReference, IsCorpus, CanonicalID, VersionScheme, Tag* `
                            -ErrorAction SilentlyContinue 
                 } Catch { Write-Host "Get-Package not valid on \\$($ENV:Computername)" ; $Null }
  $p
} | Select-Object PSComputerName, Name, * -ExcludeProperty RunSpaceID -ErrorAction SilentlyContinue | Sort-Object Name, PSComputerName

FixLocalhostName $ServersInventory -TrimDomain
$F7 = ".\$FileNameRoot-InstalledPrograms.csv"
$ServersInventory | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $F7 -Encoding utf8
Write-Output "Complete list of Installed Programs details saved to: $((Resolve-Path $F7).Path)`n"

$SI2 = $ServersInventory | Where-Object { $_.ProviderName -Match '(Programs)|(msi)' -and $_.Name -notlike "*redist*" -and $_.Name -notlike "*update*" `
                                          -and $_.Name -notlike "*hotfix*" -and $_.Name -notlike "*.NET*" -and $_.Name -notlike "*Runtime*" -and $_.Name -notlike "*crystalreports.*" -and $_.Name -notlike "*connectivity.*" } `
                         | Select-Object @{n='NameAndVersion'; e={ if ( $Null -eq $_.Version ) { $_.Name } Else { "$($_.Name) ($($_.Version))" } }} `
                                       , @{n='ComputerName';   e={ ($_.PSComputername -Split "\.")[0] } } `
                                       , @{n='MajorVersion';   e={ if ( $null -eq $_.version ) { $_.version } else { $z = $_.version.indexof('.') ; if ( $z -gt 0 ) { $_.version.substring(0, $z) } Else { $_.Version} }  } } `
                                       , * -ErrorAction SilentlyContinue 

$SI2 = $SI2 | Select-Object @{n='NameAndMajorVersion'; e={ "$($_.Name) ($($_.MajorVersion))" } }, * -ErrorAction SilentlyContinue

$SI2        | Group-Object NameAndMajorVersion | Format-Table -AutoSize Count, Name, @{n='On Servers'; e={$_.Group.ComputerName -Join ", "}}

<# ───────── Check for installed 3rd-party web browsers ───────── #>
$ThirdPartyBrowsers = @("Google Chrome", "Mozilla Firefox", "Firefox", "Mozilla", "Opera", "Microsoft Edge (Chromium)", "Sogou Explorer", "Waterfox", "DuckDuckGo", 
                        "Comodo Dragon", "Comodo IceDragon", "QQ", "Yandex", "UC Browser", "Baidu", "Maxthon", "Amigo", "Netscape Navigator", 
                        "Brave", "Safari", "Vivaldi", "Microsoft Edge (Legacy)", "Internet Explorer") | Sort-Object
$InstalledThirdPartyBrowsers = $ServersInventory | Where-Object { $_.name -in $ThirdPartyBrowsers }
if ( $InstalledThirdPartyBrowsers.Count -gt 0 ) 
   { ShowWarning "3rd Party Browsers installed" ( $InstalledThirdPartyBrowsers.Foreach({ "\\$($_.PSComputerName)$Elipses$($_.Name)" }) ) -ShowCount }

<# Check for SharePoint server #>

<# ───────── Server WU job ───────── #>
Invoke-Command -Session $ServersOnlineSessions `
               -ScriptBlock { Try { $wul = Get-WULastResults -ErrorAction SilentlyContinue
                                    $wuh = Get-WUHistory -Last 100 | Where-Object { $_.Title -notLIKE "Security Intelligence*" -AND $_.Title -notlike "*Defender Antivirus*" } -ErrorAction SilentlyContinue

                                    [PSCustomObject]@{ ComputerName                = $wul.ComputerName
                                                       LastSearchSuccessDate       = $wul.LastSearchSuccessDate
                                                       LastInstallationSuccessDate = $wul.LastInstallationSuccessDate
                                                       PatchDate                   = $wuh[0].Date
                                                       OperationName               = $wuh[0].Operationname
                                                       Result                      = $wuh[0].Result
                                                       KB                          = $wuh[0].kb
                                                       Title                       = $wuh[0].Title }

                                  } Catch { $wul = (New-Object -com "Microsoft.Update.AutoUpdate").Results
                                            [PSCustomObject]@{ ComputerName                = $env:computername
                                                       LastSearchSuccessDate       = $wul.LastSearchSuccessDate
                                                       LastInstallationSuccessDate = $wul.LastInstallationSuccessDate
                                                       Result                      = "Missing"
                                                       Title                       = "Need to run: Install-Module PSWindowsUpdate -Scope AllUsers" }
                                          }
                            } -AsJob -JobName 'WU' | Out-Null

<# ───────── Server Uptime and Local Current Time ───────── #>
Write-Output "$($SeparatorLine)Clock and Uptime:"
Clear-Variable CurrentTime, j -ErrorAction SilentlyContinue
if ( $null -ne $NTP ) { $i = 0 
                        While ( $i -le 10 -and ($Null -eq $CurrentTime.ReferenceIdentifier -or '' -eq $CurrentTime.ReferenceIdentifier ) ) { $i++ ; $CurrentTime = Get-NtpTime -Server time.nist.gov -MaxOffset 86400000 -ErrorAction SilentlyContinue }
                        Write-Output "Current time from NTP server '$($CurrentTime.NTPServer)' $($CurrentTime.ReferenceIdentifier) $($CurrentTime.Stratum_text): $($CurrentTime.NtpTime)"

$NoTime = ( $CuurentTime.NTPTime.Year -eq 1899 )
$up1 = Invoke-Command -Session $ServersOnlineSessions2 -ScriptBlock { Get-CimInstance -ClassName win32_operatingsystem -Property * } -ErrorAction SilentlyContinue

$UpTime = $up1 | Sort-Object LastBootUpTime | Select-Object @{Name = 'ComputerName'  ; Expression = { $_.csname.trim() } } `
  , @{Name = 'OSName'        ; Expression = { $_.Caption } } `
  , LocalDateTime `
  , @{Name = 'OffsetSeconds' ; Expression = { [math]::Round( ((New-TimeSpan -start $CurrentTime.NtpTime -end $_.LocalDateTime -ErrorAction SilentlyContinue ).TotalSeconds  ) , 4 ) } } `
  , @{Name = 'Time Zone'     ; Expression = { $TZ = Get-TimeZone ; (( $TZ.ID -split " " | ForEach-Object { $_[0] }) -join "" ) + " " + ( $TZ.DisplayName -split ' ' )[0] } } `
  , LastBootUpTime `
  , @{Name = 'Day'           ; Expression = { (($_.LastBootUpTime).DayofWeek).tostring().substring(0, 3)} } `
  , @{Name = 'UpTime'        ; Expression = { $UT = ( (New-TimeSpan -start $_.LastBootUpTime -end $_.LocalDateTime).ToString() ) ; $UT.Substring(0, $UT.LastIndexOf('.')) } } `
  , @{Name = 'UpTimeSpan'    ; Expression = { (New-TimeSpan -start $_.LastBootUpTime -end $_.LocalDateTime) } } `
  , Description
$UpTime | Select-Object * -ExcludeProperty UpTimeSpan | Format-Table -AutoSize

if ( $NoTime ) { ShowWarning "Unable to contact public NTP (time) server '$($CurrentTime.NTPServer)'" $CurrentTime.Stratum_text }
Else { ## $AvgTimeOffset = $UpTime | Measure-Object -Average offsetseconds
       Write-Output "Aggregated server clock offset (in seconds): "
       $AvgTimeOffset = $UpTime | Measure-Object -Average offsetseconds -Maximum -Minimum
       $AvgTimeOffset | Format-List Minimum, Average, Maximum
       if ( [math]::abs($AvgTimeOffset.Average) -gt 2 ) { ShowWarning "Average server clock is off by $([math]::Round( $AvgTimeOffset.Average , 4 ) ) seconds" -Critical } }

}   ## $NTP

<# ───────── Services ───────── #>
Write-Output "$($SeparatorLine)Services with non-default LogonAs names: "
$ServerServices = Invoke-Command -Session $ServersOnlineSessions2 -ScriptBlock { 
       $Services = Try { Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue } Catch { Get-WmiObject -Class Win32_Service }
       $Services | Where-Object { $Null -ne $_.StartName -and $_.Startname -notmatch '^.*LocalService|^.*LocalSystem|^.*NetworkService' }
    } | Sort-Object PSComputerName, Name
FixLocalhostName $ServerServices -TrimDomain
$ServerServices | Sort-Object StartMode, SystemName | Format-Table SystemName, Name, StartName, StartMode, State, Status, DisplayName

Write-Output "$($SeparatorLine)Auto-start Services that are not running (excluding known stopped): "
$ServerServices = Invoke-Command -Session $ServersOnlineSessions2 -ScriptBlock { 
       $Services = Try { Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue } Catch { Get-WmiObject -Class Win32_Service }
       $Services = $Services | Where-Object { $_.StartMode -eq "Auto" -and $_.State -ne "Running" } 
       ### Servers with PowerShell older than version 3 do not support -notin, so we have to use this longer -ne line
       $Services = $Services | Where-Object { $_.Name -ne "VSS" -and $_.Name -ne "gupdate" -and $_.Name -ne "RemoteRegistry" -and $_.Name -ne "WbioSrvc" `
                                              -and $_.Name -ne "sppsvc" -and $_.Name -ne "CDPSvc" -and $_.Name -ne "tiledatamodelsvc" -and $_.Name -ne "edgeupdate" `
                                              -and $_.Name -ne "BITS" -and $_.DisplayName -notlike "*Framework NGEN*" -and $_.DisplayName -notlike "GoogleUpdate*" `
                                              -and $_.DisplayName -notlike "Sophos Clean*" -and $_.DisplayName -notlike "Sophos Safestore*" `
                                              -and $_.DisplayName -notlike "Windows*Installer" } 
       $Services
    } | Sort-Object PSComputerName, Name

$ServerServices | Format-Table SystemName, Name, StartName, StartMode, State, Status, DisplayName

### Get AD Managed Service Accounts
# https://blog.netwrix.com/2022/10/13/group-managed-service-accounts-gmsa/
# https://web.archive.org/web/20130627015803/http://blogs.technet.com/b/askpfeplat/archive/2012/12/17/windows-server-2012-group-managed-service-accounts.aspx
Write-Output "$($SeparatorLine)Managed Service Accounts: "
$gMSA = Get-ADServiceAccount -Filter * -Properties *
if ( $Null -eq $gMSA) { Write-Output "No Managed Services Accounts found" }
else { $gMSA | Format-Table Name, msDS-HostServiceAccountBL, Description, Created, PasswordlastSet, Principal*Password }

Write-Output "$($SeparatorLine)Servers with Associated Managed Service Accounts: "
$ServersInAD | Where-Object { $Null -ne $_."msDS-HostServiceAccount" } | Format-Table Name, msDS-HostServiceAccount, Description, Created, PasswordlastSet

<# ───────── Server WU ───────── #>
Write-Output "$($SeparatorLine)Windows Updates (and the one most recent update): "
Wait-Job -Name 'WU' -Timeout 60 | Out-Null
$ServerWU = Receive-Job -Name 'WU'
Stop-Job -Name "WU"
$ServerWU | Sort-Object Result, LastInstallationSuccessDate, ComputerName | Format-Table ComputerName, LastSearchSuccessDate, LastInstallationSuccessDate, PatchDate, OperationName, Result, KB, Title
$ServerWUFailed = $ServerWU | Where-Object { $_.Result -eq 'Failed' }
$ServerWUFailedCount = $ServerWUFailed | Measure-Object
if ( $ServerWUFailedCount.Count -gt 0 ) { ShowWarning "Servers with Windows Updates failures" $ServerWUFailed.PSComputerName -ShowCount -TrimDomain }
Get-Job "WU" | Remove-Job 


<# ───────── Pending reboots ───────── #>
## https://adamtheautomator.com/pending-reboot-registry/
Write-Output "$($SeparatorLine)"
ShowInfo "Checking reboot required status ...`n"
Clear-Variable RebootsNeeded, RebootsERROR -ErrorAction SilentlyContinue

$RebootsNeeded = ForEach ( $Server in $UpTime ) { ## $ServerName = if ( $Server.computername -eq $localhost ) { 'localhost' } Else { $Server.ComputerName }
                                                  $ServerName = $Server.ComputerName + ".$($AD.DNSRoot)"
                                                  ##Write-Host $ServerName -ForegroundColor Yellow -BackgroundColor DarkGray
                                                  if ( $ServerName -eq $LocalDNShost -and $ServersOnlineSessions.ComputerName -contains 'localhost' ) { $ServerName = 'localhost' }
                                                  ##Write-Host $ServerName -ForegroundColor Yellow -BackgroundColor DarkGray
                                                  $Server = $ServersOnlineSessions | Where-Object { $_.computername -like "$($ServerName)" }
                                                  
Invoke-Command -Session $Server -ScriptBlock { $r0 = @()
  ## Standard Windows reboot flags ##
  $RB1 = ( Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing' -ErrorAction SilentlyContinue )
  $RB1sk = ( $RB1 ).GetSubKeyNames()
  $r0 += if ( $Null -ne $RB1 -and $RB1sk -contains 'RebootPending' ) { "Reboot Pending" } else { $Null }
  $r0 += if ( $Null -ne $RB1 -and $RB1sk -contains 'RebootInProgress' ) { "Reboot in Progress" } else { $Null }
  $r0 += if ( $Null -ne $RB1 -and $RB1sk -contains 'PackagesPending' ) { "Packages Pending" } else { $Null }

  $RB2 = ( Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -ErrorAction SilentlyContinue )
  $RB2sk = ( $RB2 ).GetSubKeyNames()
  $r0 += if ( $Null -ne $RB2 -and $RB2sk -contains 'RebootRequired' ) { "Reboot Required" } else { $Null }
  $r0 += if ( $Null -ne $RB2 -and $RB2sk -contains 'PostRebootReporting' ) { "Post Reboot Reporting" } else { $Null }

  $r0 += if ( $Null -ne (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue) ) { "Pending File Rename Operations" } else { $Null }
  $r0 += if ( $Null -ne (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations2' -ErrorAction SilentlyContinue) ) { "Pending File Rename Operations 2" } else { $Null }
  $r0 += if ( $Null -ne (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'DVDRebootSignal' -ErrorAction SilentlyContinue) ) { "DVDRebootSignal" } else { $Null }
  $r0 += if ( $Null -ne (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Name 'JoinDomain' -ErrorAction SilentlyContinue) ) { "Joining Domain" } else { $Null }
  $r0 += if ( $Null -ne (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Name 'AvoidSpnSet' -ErrorAction SilentlyContinue) ) { "Avoid SPN Set" } else { $Null }

  ## Sophos 32-bit ##
  $s0 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Sophos\AutoUpdate\UpdateStatus\VolatileFlags' -ErrorAction SilentlyContinue
  $s1 = ((Get-Date).AddTicks( -$s0.RebootRequiredSince )).ToShortDateString()
  $r0 += if ( $s0.RebootRequired -eq 1 ) { "Sophos Reboot Required (32) - Since $s1" } else { $Null }
  $r0 += if ( $s0.UrgentRebootRequired -eq 1 ) { "Sophos Urgent Reboot Required (32) - Since $s1" } else { $Null }
  ## Sophos 64-bit ##
  $s0 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Sophos\AutoUpdate\UpdateStatus\VolatileFlags' -ErrorAction SilentlyContinue
  $s1 = ((Get-Date).AddTicks( -$s0.RebootRequiredSince )).ToShortDateString()
  $r0 += if ( $s0.RebootRequired -eq 1 ) { "Sophos Reboot Required - Since $s1" } else { $Null }
  $r0 += if ( $s0.UrgentRebootRequired -eq 1 ) { "Sophos Urgent Reboot Required - Since $s1" } else { $Null }
  ##$r0 += if ( (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Sophos\AutoUpdate\UpdateStatus\VolatileFlags' -Name 'RebootRequired' -ErrorAction SilentlyContinue).RebootRequired -eq 1 ) { "Sophos Reboot Required" } else { $Null }
  ##$r0 += if ( (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Sophos\AutoUpdate\UpdateStatus\VolatileFlags' -Name 'UrgentRebootRequired' -ErrorAction SilentlyContinue).UrgentRebootRequired -eq 1 ) { "Sophos URGENT! Reboot Required" } else { $Null }

  ## $r0 += if ( $Null -ne (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName' -ErrorAction SilentlyContinue) ) { "Computer Name Changed" } else { $Null }
  ## Write-Host "r0 = $r0" -ForegroundColor Cyan

  $rr = $r0 | Where-Object { $Null -ne $_ }
  if ( $Null -eq $rr ) { Return } Else { New-Object psObject -Property @{ ComputerName  = $ENV:ComputerName; RebootReasons = ( $rr -join ", " ) } }

 } -ErrorAction SilentlyContinue -ErrorVariable +RebootsERROR | Select-Object *ComputerName, Reboot*            # invoke
}   # foreach

### Add the 'RebootReasons' property to the existing uptime object array
$RebootsNeeded | ForEach-Object { $ix = $UpTime.ComputerName.IndexOf( $_.ComputerName ) 
                                  $UpTime[ $ix ] | Add-Member -MemberType NoteProperty -Name 'RebootReasons' -Value ( $_.RebootReasons ) -ErrorAction SilentlyContinue }

$UpTime | Where-Object { $Null -ne $_.RebootReasons } | Format-Table -AutoSize ComputerName, LastBootUpTime, Day, Uptime, RebootReasons, Description
$LongUpTime = $UpTime | Where-Object { $_.uptimespan.days -gt $ObservationWindow * 3 }
#if ( $null -ne $LongUpTime )    { ShowWarning "Computers have not been rebooted in over $($ObservationWindow * 3) days" $LongUpTime.ComputerName -ShowCount }
if ( $null -ne $LongUpTime )     { ShowWarning "Computers have not been rebooted in over $([int](($LongUpTime.UptimeSpan.totaldays) `
                                   | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum)) days" $LongUpTime.ComputerName -ShowCount -Critical }
if ( $RebootsERROR.Count -gt 0 ) { ShowWarning "Errors accessing reboot status" $RebootsERROR -ShowCount }
if ( $Null -ne $RebootsNeeded )  { ShowWarning "Computers need to be rebooted" $RebootsNeeded.ComputerName -ShowCount -TrimDomain }


<# ───────── Cleanup - close transcript ───────── #>
$OutputFiles = Get-Item "$FileNameRoot*.*" | Sort-Object Name
if ($Null -ne $OutputFiles ) { $P1 = Resolve-Path $PMOutputSubfolder
                               Write-Output "$($SeparatorLine)$($OutputFiles.Count) Files Created on \\$($env:computername) in $($P1.Path)`n `n `n"
                     for ( $x=0; $x -lt $OutputFiles.Count; $x++ ) { Write-Output ("{0}. {1}" -f ($x + 1).tostring().PadLeft(3), $OutputFiles[$x].Name )} }

if ($Null -ne $WV) { Write-Output "$($SeparatorLine)$($WV.Count) Warnings for $($AD.DNSRoot)`n `n"
                     for ( $x=0; $x -lt $WV.Count; $x++ ) { Write-Output ("{0}. {1}" -f ($x + 1).tostring().PadLeft(3), $WV[$x] )} }

if ($Null -ne $CV) { Write-Output "$($SeparatorLine)$($CV.Count) Critical Warnings for $($AD.DNSRoot)`n `n"
                     for ( $x=0; $x -lt $CV.Count; $x++ ) { Write-Output ("{0}. {1}" -f ($x + 1).tostring().PadLeft(3), $CV[$x] )} }

### $ServersOnlineSessions | Remove-PSSession     ## Close all PS sessions

$RunEndDateTime = get-date
Write-Output "$($SeparatorLine)Completed: $RunEndDateTime"
ElapsedTime -Total
Write-Output ""
ShowInfo "Copyright $cpy $($ThisScriptFileVersion.Copyright) - $($ThisScriptFileVersion.CompanyName)" -NoTime
Stop-Transcript
$Global:ProgressPreference = $OriginalProgressPreference

<# ───────── Copy the transcript file contents to the clipboard ───────── #>
$T = Get-Content -Path $TranscriptFile
<# Remove extra blank lines #>
$T2 = @() ; $Blanks = 0
foreach ( $L in $T ) { if ( $L -eq '' ) { $Blanks++ } else { $Blanks = 0 }
                       if ( $Blanks -le 1 ) { $T2 += $L }
                     }
$T2 | Set-Clipboard
Set-Content -Path $TranscriptFile -Value $T2 -Encoding UTF8
$x = $T2 -match "(TerminatingError)|(FullyQualifiedErrorId)|(not recognized)"
if ( $x.Count -gt 0 ) { ShowInfo "$($x.Count) errors detected in the transcript" -NoTime
                        Write-Output $x }

ShowWarning "The transcript file contents have been copied to the clipboard, however it is recommended to copy these files as attachments into OneNote."
#Start-Process ((Get-Location).Path)
Start-Process ($PMOutputSubfolder)
