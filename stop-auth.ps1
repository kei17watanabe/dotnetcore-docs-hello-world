<#
   ***Directory Services Authentication Scripts***

   Requires: PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)

   Last Updated: 27/02/2023

   Version: 5.0
#>
#Requires -RunAsAdministrator
[cmdletbinding(PositionalBinding = $false)]
param(
    [string]$containerId
)

function Check-GMSA {
    param($ContainerId)

    $CredentialString = docker inspect -f "{{ .HostConfig.SecurityOpt }}" $ContainerId

    if ($CredentialString -ne "[]") {
        Write-Verbose "GMSA Credential String: $CredentialString"
        # NOTE(will): We need to check if we have RSAT installed
        if ((Get-Command "Test-ADServiceAccount" -ErrorAction "SilentlyContinue") -ne $null) {
            $ServiceAccountName = $(docker inspect -f "{{ .Config.Hostname }}" $ContainerId)
            $Result = "`nSTOP:`n`nRunning Test-ADServiceAccount $ServiceAccountName`nResult:"
            try {
                $Result += Test-ADServiceAccount -Identity $ServiceAccountName -Verbose -ErrorAction SilentlyContinue
            }
            catch {
                $Result += "Unable to find object with identity $containerId"
            }

            Out-File $_CONTAINER_DIR\gMSATest.txt -InputObject $Result -Append
        }

        $CredentialName = $CredentialString.Replace("[", "").Replace("]", "")
        $CredentialName = $CredentialName.Split("//")[-1]
        $CredentialObject = Get-CredentialSpec | Where-Object { $_.Name -eq $CredentialName }
        Copy-Item $CredentialObject.Path $_CONTAINER_DIR
    }
}

function Get-ContainersInfo {

    param($ContainerId)
    Get-NetFirewallProfile > $_CONTAINER_DIR\firewall_profile.txt
    Get-NetConnectionProfile >> $_CONTAINER_DIR\firewall_profile.txt
    netsh advfirewall firewall show rule name=* > $_CONTAINER_DIR\firewall_rules.txt
    netsh wfp show filters file=$_CONTAINER_DIR\wfpfilters.xml 2>&1 | Out-Null
    docker ps > $_CONTAINER_DIR\container-info.txt
    docker inspect $(docker ps -q) >> $_CONTAINER_DIR\container-info.txt
    docker network ls > $_CONTAINER_DIR\container-network-info.txt
    docker network inspect $(docker network ls -q) >> $_CONTAINER_DIR\container-network-info.txt

    docker top $containerId > $_CONTAINER_DIR\container-top.txt
    docker logs $containerId > $_CONTAINER_DIR\container-logs.txt

    wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:false 2>&1 | Out-Null
    wevtutil.exe export-log "Microsoft-Windows-Containers-CCG/Admin" $_CONTAINER_DIR\Containers-CCG_Admin.evtx /overwrite:true 2>&1 | Out-Null
    wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null
    Get-EventLog -LogName Application -Source Docker -After (Get-Date).AddMinutes(-30)  | Sort-Object Time | Export-CSV $_CONTAINER_DIR\docker_events.csv

}


function Invoke-Container {

    [Cmdletbinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContainerId,
        [switch]$Nano,
        [Parameter(ParameterSetName = "PreTraceDir")]
        [switch]$PreTrace,
        [Parameter(ParameterSetName = "AuthDir")]
        [switch]$AuthDir,
        [switch]$UseCmd,
        [switch]$Record,
        [switch]$Silent,
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $Workingdir = "C:\AuthScripts"
    if ($PreTrace) {
        $Workingdir += "\authlogs\PreTraceLogs"
    }

    if ($AuthDir) {
        $Workingdir += "\authlogs"
    }

    Write-Verbose "Running Container command: $Command"
    if ($Record) {
        if ($Nano) {
            docker exec -u Administrator -w $Workingdir $ContainerId cmd /c "$Command" *>> $_CONTAINER_DIR\container-output.txt
        }
        elseif ($UseCmd) {
            docker exec -w $Workingdir $ContainerId cmd /c "$Command" *>> $_CONTAINER_DIR\container-output.txt
        }
        else {
            docker exec -w $Workingdir $ContainerId powershell -ExecutionPolicy Unrestricted "$Command" *>> $_CONTAINER_DIR\container-output.txt
        }
    }
    elseif ($Silent) {
        if ($Nano) {
            docker exec -u Administrator -w $Workingdir $ContainerId cmd /c "$Command" *>> Out-Null
        }
        elseif ($UseCmd) {
            docker exec -w $Workingdir $ContainerId cmd /c "$Command" *>> Out-Null
        }
        else {
            docker exec -w $Workingdir $ContainerId powershell -ExecutionPolicy Unrestricted "$Command" *>> Out-Null
        }
    }
    else {
        $Result = ""
        if ($Nano) {
            $Result = docker exec -u Administrator -w $Workingdir $ContainerId cmd /c "$Command"
        }
        elseif ($UseCmd) {
            $Result = docker exec -w $Workingdir $ContainerId cmd /c "$Command"
        }
        else {
            $Result = docker exec -w $Workingdir $ContainerId powershell -ExecutionPolicy Unrestricted "$Command"
        }
        return $Result
    }
}

function Stop-NanoTrace {
    param($ContainerId)

    Get-Content "$_CONTAINER_DIR\RunningProviders.txt" | ForEach-Object {
        Invoke-Container -ContainerId $ContainerId -Nano -AuthDir -Record -Command "wpr -stop $_`.etl -instancename $_"
    }

    # Cleaning up registry keys
    foreach ($RegDelete in $_REG_DELETE) {
        $DeleteParams = $RegDelete.Split("!")
        $DeleteKey = $DeleteParams[0]
        $DeleteValue = $DeleteParams[1]
        Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "reg delete `"$DeleteKey`" /v $DeleteValue /f"
    }

    # Querying registry keys
    foreach ($RegQuery in $_REG_QUERY) {
        $QueryParams = $RegQuery.Split("!")
        $QueryKey = $QueryParams[0]
        $QueryOptions = $QueryParams[1]
        $QueryOutput = $QueryParams[2]

        $QueryOutput = "$QueryOutput`-key.txt"
        $AppendFile = Invoke-Container -ContainerId $ContainerId -AuthDir -Nano -Command "if exist $QueryOutput (echo True)"

        Write-Verbose "Append Result: $AppendFile"
        $Redirect = "> $QueryOutput"

        if ($AppendFile -eq "True") {
            $Redirect = ">> $QueryOutput"
        }


        if ($QueryOptions -eq "CHILDREN") {
            Invoke-Container -ContainerId $ContainerId -AuthDir -Nano -Record -Command "reg query `"$QueryKey`" /s $Redirect"
        }
        else {
            Invoke-Container -ContainerId $ContainerId -AuthDir -Nano -Record -Command "reg query `"$QueryKey`" $Redirect"
        }

    }

    foreach ($EventLog in $_EVENTLOG_LIST) {
        $EventLogParams = $EventLog.Split("!")
        $EventLogName = $EventLogParams[0]
        $EventLogOptions = $EventLogParams[1]

        $ExportName = $EventLogName.Replace("Microsoft-Windows-", "").Replace(" ", "_").Replace("/", "_")

        if ($EventLogOptions -ne "DEFAULT") {
            Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wevtutil set-log $EventLogName /enabled:false"
        }

        Invoke-Container -ContainerId $ContainerId -Nano -Record -AuthDir -Command "wevtutil export-log $EventLogName $ExportName.evtx /overwrite:true"

        if ($EventLogOptions -eq "ENABLE") {
            Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wevtutil set-log $EventLogName /enabled:true /rt:false" *>> $_CONTAINER_DIR\container-output.txt
        }
    }
}


[float]$_Authscriptver = "5.0"
$_BASE_LOG_DIR = ".\authlogs"
$_LOG_DIR = $_BASE_LOG_DIR
$_CH_LOG_DIR = "$_BASE_LOG_DIR\container-host"
$_BASE_C_DIR = "$_BASE_LOG_DIR`-container"
$_C_LOG_DIR = "$_BASE_LOG_DIR\container"

# *** Set some system specifc variables ***
$wmiOSObject = Get-WmiObject -class Win32_OperatingSystem
$osVersionString = $wmiOSObject.Version
$osBuildNumString = $wmiOSObject.BuildNumber


$_EVENTLOG_LIST = @(
    # LOGNAME!FLAGS
    "Application!DEFAULT"
    "System!DEFAULT"
    "Microsoft-Windows-CAPI2/Operational!NONE"
    "Microsoft-Windows-Kerberos/Operational!NONE"
    "Microsoft-Windows-Kerberos-key-Distribution-Center/Operational!NONE"
    "Microsoft-Windows-Kerberos-KdcProxy/Operational!NONE"
    "Microsoft-Windows-WebAuth/Operational!NONE"
    "Microsoft-Windows-WebAuthN/Operational!ENABLE"
    "Microsoft-Windows-CertPoleEng/Operational!NONE"
    "Microsoft-Windows-IdCtrls/Operational!ENABLE"
    "Microsoft-Windows-User Control Panel/Operational!NONE"
    "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController!NONE"
    "Microsoft-Windows-Authentication/ProtectedUser-Client!NONE"
    "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController!NONE"
    "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController!NONE"
    "Microsoft-Windows-Biometrics/Operational!ENABLE"
    "Microsoft-Windows-LiveId/Operational!ENABLE"
    "Microsoft-Windows-AAD/Analytic!NONE"
    "Microsoft-Windows-AAD/Operational!ENABLE"
    "Microsoft-Windows-User Device Registration/Debug!NONE"
    "Microsoft-Windows-User Device Registration/Admin!ENABLE"
    "Microsoft-Windows-HelloForBusiness/Operational!ENABLE"
    "Microsoft-Windows-Shell-Core/Operational!ENABLE"
    "Microsoft-Windows-WMI-Activity/Operational!ENABLE"
    "Microsoft-Windows-GroupPolicy/Operational!DEFAULT"
    "Microsoft-Windows-Crypto-DPAPI/Operational!ENABLE"
    "Microsoft-Windows-Containers-CCG/Admin!ENABLE"
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational!ENABLE"
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational!ENABLE"
)

# Reg Delete
$_REG_DELETE = @(
    # KEY!NAME
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA!SPMInfoLevel"
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA!LogToFile"
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA!NegEventMask"
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA\NegoExtender\Parameters!InfoLevel"
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA\Pku2u\Parameters!InfoLevel"
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA!LspDbgInfoLevel"
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA!LspDbgTraceOptions"
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics!GPSvcDebugLevel"
)

# Reg Query
$_REG_QUERY = @(
    # KEY!CHILD!FILENAME
    # File will be written ending with <FILENAME>-key.txt
    # If the export already exists it will be appended
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa!CHILDREN!Lsa"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies!CHILDREN!Polices"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System!CHILDREN!SystemGP"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer!CHILDREN!Lanmanserver"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation!CHILDREN!Lanmanworkstation"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon!CHILDREN!Netlogon"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!CHILDREN!Schannel"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography!CHILDREN!Cryptography-HKLMControl"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography!CHILDREN!Cryptography-HKLMSoftware"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography!CHILDREN!Cryptography-HKLMSoftware-Policies"
    "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Cryptography!CHILDREN!Cryptography-HKCUSoftware-Policies"
    "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Cryptography!CHILDREN!Cryptography-HKCUSoftware"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider!CHILDREN!SCardCredentialProviderGP"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication!CHILDREN!Authentication"
    "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication!CHILDREN!Authentication-Wow64"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon!CHILDREN!Winlogon"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Winlogon!CHILDREN!Winlogon-CCS"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityStore!CHILDREN!Idstore-Config"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityCRL!CHILDREN!Idstore-Config"
    "HKEY_USERS\.Default\Software\Microsoft\IdentityCRL!CHILDREN!Idstore-Config"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc!CHILDREN!KDC"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KPSSVC!CHILDREN!KDCProxy"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin!CHILDREN!RegCDJ"
    "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin!CHILDREN!RegWPJ"
    "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\AADNGC!CHILDREN!RegAADNGC"
    "HKEY_LOCAL_MACHINE\Software\Policies\Windows\WorkplaceJoin!CHILDREN!REGWPJ-Policy"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Winbio!CHILDREN!Wbio"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc!CHILDREN!Wbiosrvc"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics!CHILDREN!Wbio-Policy"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\EAS\Policies!CHILDREN!EAS"
    "HKEY_CURRENT_USER\SOFTWARE\Microsoft\SCEP!CHILDREN!Scep"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient!CHILDREN!MachineId"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork!CHILDREN!NgcPolicyIntune"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork!CHILDREN!NgcPolicyGp"
    "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\PassportForWork!CHILDREN!NgcPolicyGpUser"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc!CHILDREN!NgcCryptoConfig"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock!CHILDREN!DeviceLockPolicy"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\SecurityKey!CHILDREN!FIDOPolicyIntune"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FIDO!CHILDREN!FIDOGp"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc!CHILDREN!RpcGP"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters!CHILDREN!NTDS"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP!CHILDREN!LdapClient"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard!CHILDREN!DeviceGuard"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCMSetup!CHILDREN!CCMSetup"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCM!CHILDREN!CCM"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727!NONE!DotNET-TLS"
    "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319!NONE!DotNET-TLS"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319!NONE!DotNET-TLS"
    "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727!NONE!DotNET-TLS"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC!NONE!SharedPC"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess!NONE!Passwordless"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authz!CHILDREN!Authz"
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp!NONE!WinHttp-TLS"
    "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp!NONE!WinHttp-TLS"
    "HKEY_LOCAL_MACHINE\Software\Microsoft\Enrollments!CHILDREN!MDMEnrollments"
    "HKEY_LOCAL_MACHINE\Software\Microsoft\EnterpriseResourceManager!CHILDREN!MDMEnterpriseResourceManager"
    "HKEY_CURRENT_USER\Software\Microsoft\SCEP!CHILDREN!MDMSCEP-User"
    "HKEY_CURRENT_USER\S-1-5-18\Software\Microsoft\SCEP!CHILDREN!MDMSCEP-SystemUser"
)

if ($containerId -ne "") {
    $_CONTAINER_DIR = "$_BASE_C_DIR`-$containerId"

    if (!(Test-Path "$_CONTAINER_DIR\started.txt")) {
        Write-Host "
===== Microsoft CSS Authentication Scripts started tracing =====`n
We have detected that tracing has not been started in container $containerId.
Please run start-auth.ps1 -containerId $containerId to start the tracing.`n"
        return
    }

    Write-Verbose "Stopping Container auth scripts"
    $RunningContainers = $(docker ps -q)
    if ($containerId -in $RunningContainers) {
        Write-Verbose "$containerId Found"
        Write-Host "Stopping data collection..."
        if ((Get-Content $_CONTAINER_DIR\container-base.txt) -eq "Nano") {
            Write-Verbose "Stopping Nano container data collection"
            # NOTE(will) Stop the wprp
            Stop-NanoTrace -ContainerId $containerId
        }
        else {
            Write-Verbose "Stopping Standard container data collection"
            Invoke-Container -ContainerId $containerId -Record -Command ".\stop-auth.ps1"
        }
    }
    else {
        Write-Host "Failed to find $containerId"
        return
    }

    Write-Host "`nCollecting Container Host Device configuration information, please wait....`n"
    Check-GMSA -ContainerId $containerId
    Get-ContainersInfo -ContainerId $containerId

    # Stop Pktmon
    if ((Get-HotFix | Where-Object { $_.HotFixID -gt "KB5000854" -and $_.Description -eq "Update" } | Measure-object).Count -ne 0) {
        pktmon stop 2>&1 | Out-Null
        pktmon list -a > $_CONTAINER_DIR\pktmon_components.txt
    }
    else {
        netsh trace stop | Out-Null
    }

    Add-Content -Path $_CONTAINER_DIR\script-info.txt -Value ("Data collection stopped on: " + (Get-Date -Format "yyyy/MM/dd HH:mm:ss"))
    Remove-Item -Path $_CONTAINER_DIR\started.txt -Force | Out-Null

    Write-Host "`n
===== Microsoft CSS Authentication Scripts tracing stopped =====`n
The tracing has now stopped. Please copy the collected data to the logging directory`n"

    Write-Host "Example:
`tdocker stop $containerId
`tdocker cp $containerId`:\AuthScripts\authlogs $_CONTAINER_DIR
`tdocker start $containerId" -ForegroundColor Yellow

    Write-Host "`n
======================= IMPORTANT NOTICE =======================`n
The authentication script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows.
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, Device names, and User names.`n
Once the tracing and data collection has completed, the script will save the data in a subdirectory from where this script is launched called ""$_CONTAINER_DIR"".
The ""$_CONTAINER_DIR"" directory and subdirectories will contain data collected by the Microsoft CSS Authentication scripts.
This folder and its contents are not automatically sent to Microsoft.
You can send this folder and its contents to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.`n"
    return
}

# *** Check if script is running ***
If (!(Test-Path $_LOG_DIR\started.txt) -eq "True") {
    Write-Host "
===== Microsoft CSS Authentication Scripts started tracing =====`n
We have detected that tracing has not been started.
Please run start-auth.ps1 to start the tracing.`n"
    exit
}

# Replaced with #Requires -RunAsAdministrator
## *** Check for elevation ***
#Write-Host "`nChecking token for Elevation - please wait..."
#
#If((whoami /groups) -match "S-1-16-12288"){
#Write-Host "`nToken elevated"}
#Else{
#Write-Host
#"============= Microsoft CSS Authentication Scripts =============`n
#The script must be run from an elevated Powershell console.
#The script has detected that it is not being run from an elevated PowerShell console.`n
#Please run the script from an elevated PowerShell console.`n"
#exit
#}

# *** Disclaimer ***
Write-Host "`n
***************** Microsoft CSS Authentication Scripts ****************`n
This Data collection is for Authentication, smart card and Credential provider scenarios.`n
This script will stop the tracing that was previously activated with the start-auth.ps1 script.
Data is collected into a subdirectory of the directory from where this script is launched, called ""authlogs"".`n
Please wait whilst the tracing stops and data is collected....
"


$ProductType = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType

# ***STOP LOGMAN TRACING***
$NGCSingleTraceName = "NGC"
$BiometricSingleTraceName = "Biometric"
$LSASingleTraceName = "LSA"
$Ntlm_CredSSPSingleTraceName = "Ntlm_CredSSP"
$KerberosSingleTraceName = "Kerberos"
$KDCSingleTraceName = "KDC"
$SSLSingleTraceName = "SSL"
$WebauthSingleTraceName = "Webauth"
$SmartcardSingleTraceName = "Smartcard"
$CredprovAuthuiSingleTraceName = "CredprovAuthui"
$CryptNcryptDpapiSingleTraceName = "CryptNcryptDpapi"
$SAMSingleTraceName = "SAM"
$AppxSingleTraceName = "AppX"
$KernelSingleTraceName = "NT Kernel Logger"

$_WAM_LOG_DIR = "$_LOG_DIR\WAM"
$_SCCM_LOG_DIR = "$_LOG_DIR\SCCM-enrollment"
$_MDM_LOG_DIR = "$_LOG_DIR\DeviceManagement_and_MDM"
$_CERT_LOG_DIR = "$_LOG_DIR\Certinfo_and_Certenroll"

New-Item -Path $_WAM_LOG_DIR -ItemType Directory | Out-Null
New-Item -Path $_SCCM_LOG_DIR -ItemType Directory | Out-Null
New-Item -Path $_MDM_LOG_DIR -ItemType Directory | Out-Null
New-Item -Path $_CERT_LOG_DIR -ItemType Directory | Out-Null

Add-Content -Path $_LOG_DIR\Tasklist.txt -Value (tasklist /svc 2>&1) | Out-Null
Add-Content -Path $_LOG_DIR\Tickets.txt -Value(klist) | Out-Null
Add-Content -Path $_LOG_DIR\Tickets-localsystem.txt -Value (klist -li 0x3e7) | Out-Null
Add-Content -Path $_LOG_DIR\Klist-Cloud-Debug.txt -Value (klist Cloud_debug) | Out-Null

# Stop NGC logman
logman stop $NGCSingleTraceName -ets

# Stop Biometric logman
logman stop $BiometricSingleTraceName -ets

# Stop LSA logman
logman stop $LSASingleTraceName -ets

# Stop Ntlm_CredSSP logman
logman stop $Ntlm_CredSSPSingleTraceName -ets

# Stop Kerberos logman
logman stop $KerberosSingleTraceName -ets

# Stop KDC logman
if ($ProductType -eq "LanmanNT") { logman stop $KDCSingleTraceName -ets }

# Stop SSL logman
logman stop $SSLSingleTraceName -ets

# Stop Webauth logman
logman stop $WebauthSingleTraceName -ets

# Stop Smartcard logman
logman stop $SmartcardSingleTraceName -ets

# Stop CredprovAuthui logman
logman stop $CredprovAuthuiSingleTraceName -ets

# Stop CryptNcryptDpapi logman
if ($ProductType -eq "WinNT") { logman stop $CryptNcryptDpapiSingleTraceName -ets }

# Stop SAM logman
logman stop $SAMSingleTraceName -ets

# Stop AppX logman
# Check if the '-v' switch was passed
$CheckIfVWasPassed = get-content $_LOG_DIR\script-info.txt | Select-String -pattern "passed: v"
if (($ProductType -eq "WinNT") -or (($CheckIfVWasPassed.Pattern -eq "passed: v") -and ($ProductType -ne "LanmanNT"))) {
    logman stop $AppxSingleTraceName -ets
}

# Stop Kernel logman
if ($ProductType -eq "WinNT") { logman stop $KernelSingleTraceName -ets }

# Stop WPR
#checking if the slowlogon switched was passed on the start-auth.ps1
$CheckIfslowlogonWasPassed = get-content $_LOG_DIR\script-info.txt | Select-String -pattern "slowlogon"
if ($CheckIfslowlogonWasPassed.Pattern -eq "slowlogon") {
    Write-Host "`n
Stopping WPR. This may take some time depending on the size of the WPR Capture, please wait....`n"

    # Stop WPRF
    wpr -stop $_LOG_DIR\SBSL.etl
}

# ***CLEAN UP ADDITIONAL LOGGING***
reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /f  2>&1 | Out-Null
reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /f  2>&1 | Out-Null
reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /f  2>&1 | Out-Null
reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\NegoExtender\Parameters /v InfoLevel /f  2>&1 | Out-Null
reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Pku2u\Parameters /v InfoLevel /f  2>&1 | Out-Null
reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgInfoLevel /f  2>&1 | Out-Null
reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgTraceOptions /f  2>&1 | Out-Null

if ($ProductType -eq "WinNT") {
    reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters /v LogLevel /f  2>&1 | Out-Null
}

reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /f  2>&1 | Out-Null
nltest /dbflag:0x0  2>&1 | Out-Null


# *** Event/Operational logs

wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:false  2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" $_LOG_DIR\Capi2_Oper.evtx /overwrite:true  2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:false  2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Kerberos/Operational" $_LOG_DIR\Kerb_Oper.evtx /overwrite:true  2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Kerberos-key-Distribution-Center/Operational" /enabled:false  2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Kerberos-key-Distribution-Center/Operational" $_LOG_DIR\Kdc_Oper.evtx /overwrite:true  2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" /enabled:false  2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" $_LOG_DIR\KdcProxy_Oper.evtx /overwrite:true  2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-WebAuth/Operational" /enabled:false  2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-WebAuth/Operational" $_LOG_DIR\WebAuth_Oper.evtx /overwrite:true  2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:false  2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-WebAuthN/Operational" $_LOG_DIR\\WebAuthn_Oper.evtx /overwrite:true  2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-CertPoleEng/Operational" /enabled:false  2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-CertPoleEng/Operational" $_LOG_DIR\Certpoleng_Oper.evtx /overwrite:true  2>&1 | Out-Null

wevtutil query-events Application "/q:*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll']]]" > $_CERT_LOG_DIR\CertificateServicesClientLog.xml 2>&1 | Out-Null
certutil -policycache $_LOG_DIR\CertificateServicesClientLog.xml > $_LOG_DIR\ReadableClientLog.txt 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-IdCtrls/Operational" $_LOG_DIR\Idctrls_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational"  /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-User Control Panel/Operational" $_LOG_DIR\UserControlPanel_Oper.evtx /overwrite:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" $_LOG_DIR\Auth_Policy_Fail_DC.evtx /overwrite:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUser-Client" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUser-Client" $_LOG_DIR\Auth_ProtectedUser_Client.evtx /overwrite:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" $_LOG_DIR\Auth_ProtectedUser_Fail_DC.evtx /overwrite:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" $_LOG_DIR\Auth_ProtectedUser_Success_DC.evtx /overwrite:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:false  2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Biometrics/Operational" $_LOG_DIR\WinBio_oper.evtx /overwrite:true  2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-LiveId/Operational" $_LOG_DIR\LiveId_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-AAD/Analytic" $_LOG_DIR\Aad_Analytic.evtx /overwrite:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-AAD/Operational" $_LOG_DIR\Aad_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-AAD/Operational"  /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Debug" $_LOG_DIR\UsrDeviceReg_Dbg.evtx /overwrite:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Admin" $_LOG_DIR\UsrDeviceReg_Adm.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:false  2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-HelloForBusiness/Operational" $_LOG_DIR\Hfb_Oper.evtx /overwrite:true  2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

wevtutil.exe export-log SYSTEM $_LOG_DIR\System.evtx /overwrite:true  2>&1 | Out-Null
wevtutil.exe export-log APPLICATION $_LOG_DIR\Application.evtx /overwrite:true  2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Shell-Core/Operational" $_LOG_DIR\ShellCore_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-WMI-Activity/Operational" $_LOG_DIR\WMI-Activity_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe export-log "Microsoft-Windows-GroupPolicy/Operational" $_LOG_DIR\GroupPolicy.evtx /overwrite:true  2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Crypto-DPAPI/Operational" $_LOG_DIR\DPAPI_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Containers-CCG/Admin" $_LOG_DIR\Containers-CCG_Admin.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" $_LOG_DIR\CertificateServicesClient-Lifecycle-System_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational" $_LOG_DIR\CertificateServicesClient-Lifecycle-User_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

# ***COLLECT NGC DETAILS***
Switch -Regex ($osVersionString) {
    '^6\.1\.7600' { 'Windows Server 2008 R2, Skipping dsregcmd...' }
    '^6\.1\.7601' { 'Windows Server 2008 R2 SP1, Skipping dsregcmd...' }
    '^6\.2\.9200' { 'Windows Server 2012, Skipping dsregcmd...' }
    '^6\.3\.9600' { 'Windows Server 2012 R2, Skipping dsregcmd...' }
    default {
        Add-Content -Path $_LOG_DIR\Dsregcmd.txt -Value (dsregcmd /status 2>&1) | Out-Null
        Add-Content -Path $_LOG_DIR\Dsregcmddebug.txt -Value (dsregcmd /status /debug /all 2>&1) | Out-Null
    }
}

certutil -delreg Enroll\Debug  2>&1 | Out-Null
certutil -delreg ngc\Debug  2>&1 | Out-Null
certutil -delreg Enroll\LogLevel  2>&1 | Out-Null

Copy-Item -Path "$($env:windir)\Ngc*.log" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
Get-ChildItem -Path $_LOG_DIR -Filter "Ngc*.log" | Rename-Item -NewName { "Pregenlog_" + $_.Name } 2>&1 | Out-Null

Copy-Item -Path "$($env:LOCALAPPDATA)\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\settings\settings.dat" -Destination $_WAM_LOG_DIR\settings.dat -Force 2>&1 | Out-Null

if ((Test-Path "$($env:LOCALAPPDATA)\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts\") -eq "True") {
    $WAMAccountsFullPath = GCI "$($env:LOCALAPPDATA)\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts\*.tbacct"
    foreach ($WAMAccountsFile in $WAMAccountsFullPath) {
        "File Name: " + $WAMAccountsFile.name + "`n" >> $_WAM_LOG_DIR\tbacct.txt
        Get-content -Path $WAMAccountsFile.FullName >> $_WAM_LOG_DIR\tbacct.txt -Encoding Unicode | Out-Null
        "`n`n" >> $_WAM_LOG_DIR\tbacct.txt
    }
}

#checking if Network trace is running
$CheckIfNonetWasPassed = get-content $_LOG_DIR\script-info.txt | Select-String -pattern "nonet"
if ($CheckIfNonetWasPassed.Pattern -ne "nonet") {
    Write-Host "`n
    Stopping Network Trace and merging
    This may take some time depending on the size of the network capture, please wait....`n"

    # Stop Network Trace
    netsh trace stop 2>&1 | Out-Null
}

Add-Content -Path $_LOG_DIR\Ipconfig-info.txt -Value (ipconfig /all 2>&1) | Out-Null
Add-Content -Path $_LOG_DIR\Displaydns.txt -Value (ipconfig /displaydns 2>&1) | Out-Null
Add-Content -Path $_LOG_DIR\netstat.txt -Value (netstat -ano 2>&1) | Out-Null

# ***Netlogon, LSASS, LSP, Netsetup and Gpsvc log***
Copy-Item -Path "$($env:windir)\debug\Netlogon.*" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
Copy-Item -Path "$($env:windir)\system32\Lsass.log" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
Copy-Item -Path "$($env:windir)\debug\Lsp.*" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
Copy-Item -Path "$($env:windir)\debug\Netsetup.log" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
Copy-Item -Path "$($env:windir)\debug\usermode\gpsvc.*" -Destination $_LOG_DIR -Force 2>&1 | Out-Null

# ***Credman***
Add-Content -Path $_LOG_DIR\Credman.txt -Value (cmdkey.exe /list 2>&1) | Out-Null

# ***Build info***
$ProductName = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ProductName
$DisplayVersion = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").DisplayVersion
$InstallationType = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").InstallationType
$CurrentVersion = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion
$ReleaseId = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ReleaseId
$BuildLabEx = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").BuildLabEx
$CurrentBuildHex = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentBuild
$UBRHEX = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").UBR

Add-Content -Path $_LOG_DIR\Build.txt -Value ($env:COMPUTERNAME + " " + $ProductName + " " + $InstallationType + " Version:" + $CurrentVersion + " " + $DisplayVersion + " Build:" + $CurrentBuildHex + "." + $UBRHEX) | Out-Null
Add-Content -Path $_LOG_DIR\Build.txt -Value ("-------------------------------------------------------------------") | Out-Null
Add-Content -Path $_LOG_DIR\Build.txt -Value ("BuildLabEx: " + $BuildLabEx) | Out-Null
Add-Content -Path $_LOG_DIR\Build.txt -Value ("---------------------------------------------------") | Out-Null

# ***Reg Exports***
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /s > $_LOG_DIR\Lsa-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s > $_LOG_DIR\Policies-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /s > $_LOG_DIR\SystemGP-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer" /s > $_LOG_DIR\Lanmanserver-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /s > $_LOG_DIR\Lanmanworkstation-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon" /s > $_LOG_DIR\Netlogon-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /s > $_LOG_DIR\Schannel-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography" /s > $_LOG_DIR\Cryptography-HKLMControl-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKLMSoftware-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKLMSoftware-Policies-key.txt 2>&1 | Out-Null

reg query "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKCUSoftware-Policies-key.txt 2>&1 | Out-Null
reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKCUSoftware-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" /s > $_LOG_DIR\SCardCredentialProviderGP-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication" /s > $_LOG_DIR\Authentication-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication" /s > $_LOG_DIR\Authentication-key-Wow64.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /s > $_LOG_DIR\Winlogon-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Winlogon" /s > $_LOG_DIR\Winlogon-CCS-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityStore" /s > $_LOG_DIR\Idstore-Config-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityCRL" /s >> $_LOG_DIR\Idstore-Config-key.txt 2>&1 | Out-Null
reg query "HKEY_USERS\.Default\Software\Microsoft\IdentityCRL" /s >> $_LOG_DIR\Idstore-Config-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc" /s > $_LOG_DIR\KDC-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KPSSVC" /s > $_LOG_DIR\KDCProxy-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin" /s > $_LOG_DIR\RegCDJ-key.txt 2>&1 | Out-Null
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin" /s > $_LOG_DIR\Reg-WPJ-key.txt 2>&1 | Out-Null
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\AADNGC" /s > $_LOG_DIR\RegAADNGC-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Windows\WorkplaceJoin" /s > $_LOG_DIR\Reg-WPJ-Policy-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Winbio" /s > $_LOG_DIR\Winbio-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" /s > $_LOG_DIR\Wbiosrvc-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics" /s > $_LOG_DIR\Winbio-Policy-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\EAS\Policies" /s > $_LOG_DIR\Eas-key.txt 2>&1 | Out-Null

reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\SCEP" /s > $_LOG_DIR\Scep-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient" /s > $_LOG_DIR\MachineId.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork" /s > $_LOG_DIR\NgcPolicyIntune-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork" /s > $_LOG_DIR\NgcPolicyGp-key.txt 2>&1  | Out-Null
reg query "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\PassportForWork" /s > $_LOG_DIR\NgcPolicyGpUser-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc" /s > $_LOG_DIR\NgcCryptoConfig-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock" /s > $_LOG_DIR\DeviceLockPolicy-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\SecurityKey " /s > $_LOG_DIR\FIDOPolicyIntune-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FIDO" /s > $_LOG_DIR\FIDOGp-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /s > $_LOG_DIR\RpcGP-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /s > $_LOG_DIR\NTDS-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP" /s > $_LOG_DIR\LdapClient-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /s > $_LOG_DIR\DeviceGuard-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCMSetup" /s > $_SCCM_LOG_DIR\CCMSetup-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCM" /s > $_SCCM_LOG_DIR\CCM-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" > $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" >> $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" >> $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" >> $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC" > $_LOG_DIR\SharedPC.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess" > $_LOG_DIR\Passwordless.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authz" /s > $_LOG_DIR\Authz-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" > $_LOG_DIR\WinHttp-TLS-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" >> $_LOG_DIR\WinHttp-TLS-key.txt 2>&1 | Out-Null

reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" > $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" >> $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" >> $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" >> $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null

Add-Content -Path $_LOG_DIR\http-show-sslcert.txt -Value (netsh http show sslcert 2>&1) | Out-Null
Add-Content -Path $_LOG_DIR\http-show-urlacl.txt -Value (netsh http show urlacl 2>&1) | Out-Null

Add-Content -Path $_LOG_DIR\trustinfo.txt -Value (nltest /DOMAIN_TRUSTS /ALL_TRUSTS /V 2>&1) | Out-Null

$domain = (Get-WmiObject Win32_ComputerSystem).Domain
switch ($ProductType) {
    "WinNT" {
        Add-Content -Path $_LOG_DIR\SecureChannel.txt -Value (nltest /sc_query:$domain 2>&1) | Out-Null
    }
    "ServerNT" {
        Add-Content -Path $_LOG_DIR\SecureChannel.txt -Value (nltest /sc_query:$domain 2>&1) | Out-Null
    }
}

# ***Cert info***
Add-Content -Path $_CERT_LOG_DIR\Machine-Store.txt -Value (certutil -v -silent -store my 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\User-Store.txt -Value (certutil -v -silent -user -store my 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Scinfo.txt -Value (Certutil -v -silent -scinfo 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Tpm-Cert-Info.txt -Value (certutil -tpminfo 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\CertMY_SmartCard.txt -Value (certutil -v -silent -user -store my "Microsoft Smart Card Key Storage Provider" 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Cert_MPassportKey.txt -Value (Certutil -v -silent -user -key -csp "Microsoft Passport Key Storage Provider" 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Homegroup-Machine-Store.txt -Value (certutil -v -silent -store "Homegroup Machine Certificates" 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\NTAuth-store.txt -Value (certutil -v -enterprise -store NTAuth 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Machine-Root-AD-store.txt -Value (certutil -v -store -enterprise root 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Machine-Root-Registry-store.txt -Value (certutil -v -store root 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Machine-Root-GP-Store.txt -Value (certutil -v -silent -store -grouppolicy root 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Machine-Root-ThirdParty-Store.txt -Value (certutil -v -store authroot 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Machine-CA-AD-store.txt -Value (certutil -v -store -enterprise ca 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Machine-CA-Registry-store.txt -Value (certutil -v -store ca 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Machine-CA-GP-Store.txt -Value (certutil -v -silent -store -grouppolicy ca 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Cert-template-cache-machine.txt -Value (certutil -v -template 2>&1) | Out-Null
Add-Content -Path $_CERT_LOG_DIR\Cert-template-cache-user.txt -Value (certutil -v -template -user 2>&1) | Out-Null


# *** Cert enrolment info
Copy-Item "$($env:windir)\CertEnroll.log" -Destination $_CERT_LOG_DIR\CertEnroll-fromWindir.log -Force 2>&1 | Out-Null

Copy-Item "$($env:windir)\certmmc.log" -Destination $_CERT_LOG_DIR\CAConsole.log -Force 2>&1 | Out-Null
Copy-Item "$($env:windir)\certocm.log" -Destination $_CERT_LOG_DIR\ADCS-InstallConfig.log -Force 2>&1 | Out-Null
Copy-Item "$($env:windir)\certsrv.log" -Destination $_CERT_LOG_DIR\ADCS-Debug.log -Force 2>&1 | Out-Null
Copy-Item "$($env:windir)\CertUtil.log" -Destination $_CERT_LOG_DIR\CertEnroll-Certutil.log -Force 2>&1 | Out-Null
Copy-Item "$($env:windir)\certreq.log" -Destination $_CERT_LOG_DIR\CertEnroll-Certreq.log -Force 2>&1 | Out-Null

Copy-Item "$($env:userprofile)\CertEnroll.log" -Destination $_CERT_LOG_DIR\CertEnroll-fromUserProfile.log -Force 2>&1 | Out-Null
Copy-Item "$($env:LocalAppData)\CertEnroll.log" -Destination $_CERT_LOG_DIRCertEnroll\CertEnroll-fromLocalAppData.log -Force 2>&1 | Out-Null

Add-Content -Path $_LOG_DIR\Schtasks.query.v.txt -Value (schtasks.exe /query /v 2>&1) | Out-Null
Add-Content -Path $_LOG_DIR\Schtasks.query.xml.txt -Value (schtasks.exe /query /xml 2>&1) | Out-Null

Write-Host "`nCollecting Device enrollment information, please wait....`n"

# **SCCM**
$_SCCM_DIR = "$($env:windir)\CCM\Logs"
If (Test-Path $_SCCM_DIR) {
    Copy-Item $_SCCM_DIR\CertEnrollAgent*.log -Destination $_SCCM_LOG_DIR -Force 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\StateMessage*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\DCMAgent*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\ClientLocation*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\CcmEval*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\CcmRepair*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\PolicyAgent.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\CIDownloader.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\PolicyEvaluator.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\DcmWmiProvider*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\CIAgent*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\CcmMessaging.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\ClientIDManagerStartup.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
    Copy-Item $_SCCM_DIR\LocationServices.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
}

$_SCCM_DIR_Setup = "$($env:windir)\CCMSetup\Logs"
If (Test-Path $_SCCM_DIR_Setup) {
    Copy-Item $_SCCM_DIR_Setup\ccmsetup.log -Destination $_SCCM_LOG_DIR -Force 2>&1 | Out-Null
}

# ***MDM***
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Enrollments" /s > $_MDM_LOG_DIR\MDMEnrollments-key.txt 2>&1 | Out-Null
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\EnterpriseResourceManager" /s > $_MDM_LOG_DIR\MDMEnterpriseResourceManager-key.txt 2>&1 | Out-Null
reg query "HKEY_CURRENT_USER\Software\Microsoft\SCEP" /s > $_MDM_LOG_DIR\MDMSCEP-User-key.txt 2>&1 | Out-Null
reg query "HKEY_CURRENT_USER\S-1-5-18\Software\Microsoft\SCEP" /s > $_MDM_LOG_DIR\MDMSCEP-SystemUser-key.txt 2>&1 | Out-Null

wevtutil query-events Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin /format:text > $_MDM_LOG_DIR\DmEventLog.txt 2>&1 | Out-Null

#DmEventLog.txt and Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider-Admin.txt might contain the same content
$DiagProvierEntries = wevtutil el
foreach ($DiagProvierEntry in $DiagProvierEntries) {
    $tempProvider = $DiagProvierEntry.Split('/')
    if ($tempProvider[0] -eq "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider") {
        wevtutil qe $($DiagProvierEntry) /f:text /l:en-us > "$_MDM_LOG_DIR\$($tempProvider[0])-$($tempProvider[1]).txt"   2>&1 | Out-Null
    }
}

Write-Host "`nCollecting Device configuration information, please wait....`n"


Add-Content -Path $_LOG_DIR\Services-config.txt -Value (sc.exe queryex state=all 2>&1) | Out-Null
Add-Content -Path $_LOG_DIR\Services-started.txt -Value (net start 2>&1) | Out-Null
Add-Content -Path $_LOG_DIR\FilterManager.txt -Value (fltmc 2>&1) | Out-Null
Gpresult /h $_LOG_DIR\GPOresult.html 2>&1 | Out-Null

(Get-ChildItem env:*).GetEnumerator() | Sort-Object Name | Out-File -FilePath $_LOG_DIR\Env.txt | Out-Null

$env:COMPUTERNAME + " " + $ProductName + " " + $InstallationType + " Version:" + $CurrentVersion + " " + $DisplayVersion + " Build:" + $CurrentBuildHex + "." + $UBRHEX | Out-File -Append $_LOG_DIR\Build.txt
"BuildLabEx: " + $BuildLabEx | Out-File -Append $_LOG_DIR\Build.txt

$SystemFiles = @(
    "$($env:windir)\System32\kerberos.dll"
    "$($env:windir)\System32\lsasrv.dll"
    "$($env:windir)\System32\netlogon.dll"
    "$($env:windir)\System32\kdcsvc.dll"
    "$($env:windir)\System32\msv1_0.dll"
    "$($env:windir)\System32\schannel.dll"
    "$($env:windir)\System32\dpapisrv.dll"
    "$($env:windir)\System32\basecsp.dll"
    "$($env:windir)\System32\scksp.dll"
    "$($env:windir)\System32\bcrypt.dll"
    "$($env:windir)\System32\bcryptprimitives.dll"
    "$($env:windir)\System32\ncrypt.dll"
    "$($env:windir)\System32\ncryptprov.dll"
    "$($env:windir)\System32\cryptsp.dll"
    "$($env:windir)\System32\rsaenh.dll"
    "$($env:windir)\System32\Cryptdll.dll"
    "$($env:windir)\System32\cloudAP.dll"
)

ForEach ($File in $SystemFiles) {
    if (Test-Path $File -PathType leaf) {
        $FileVersionInfo = (get-Item $File).VersionInfo
        $FileVersionInfo.FileName + ",  " + $FileVersionInfo.FileVersion | Out-File -Append $_LOG_DIR\Build.txt
    }
}

# ***Hotfixes***
Get-WmiObject -Class "win32_quickfixengineering" | Select -Property Description, HotfixID, @{Name = "InstalledOn"; Expression = { ([DateTime]($_.InstalledOn)).ToLocalTime() } }, Caption | Out-File -Append $_LOG_DIR\Qfes_installed.txt

Add-Content -Path $_LOG_DIR\whoami.txt -Value (Whoami /all 2>&1) | Out-Null

Add-Content -Path $_LOG_DIR\script-info.txt -Value ("Data collection stopped on: " + (Get-Date -Format "yyyy/MM/dd HH:mm:ss"))

Remove-Item -Path $_LOG_DIR\started.txt -Force | Out-Null

Write-Host "`n
===== Microsoft CSS Authentication Scripts tracing stopped =====`n
The tracing has now stopped and data has been saved to the ""Authlogs"" sub-directory.
The ""Authlogs"" directory contents (including subdirectories) can be supplied to Microsoft CSS engineers for analysis.`n`n
======================= IMPORTANT NOTICE =======================`n
The authentication script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows.
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, Device names, and User names.`n
Once the tracing and data collection has completed, the script will save the data in a subdirectory from where this script is launched called ""Authlogs"".
The ""Authlogs"" directory and subdirectories will contain data collected by the Microsoft CSS Authentication scripts.
This folder and its contents are not automatically sent to Microsoft.
You can send this folder and its contents to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.`n"

# SIG # Begin signature block
# MIInzgYJKoZIhvcNAQcCoIInvzCCJ7sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCLPo4iPFE+H9Aj
# Q+XVDMXC2wV/gFcNkeLGwlc38f2zaqCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
# v/jUTF1RAAAAAALNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAyWhcNMjMwNTExMjA0NjAyWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDrIzsY62MmKrzergm7Ucnu+DuSHdgzRZVCIGi9CalFrhwtiK+3FIDzlOYbs/zz
# HwuLC3hir55wVgHoaC4liQwQ60wVyR17EZPa4BQ28C5ARlxqftdp3H8RrXWbVyvQ
# aUnBQVZM73XDyGV1oUPZGHGWtgdqtBUd60VjnFPICSf8pnFiit6hvSxH5IVWI0iO
# nfqdXYoPWUtVUMmVqW1yBX0NtbQlSHIU6hlPvo9/uqKvkjFUFA2LbC9AWQbJmH+1
# uM0l4nDSKfCqccvdI5l3zjEk9yUSUmh1IQhDFn+5SL2JmnCF0jZEZ4f5HE7ykDP+
# oiA3Q+fhKCseg+0aEHi+DRPZAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU0WymH4CP7s1+yQktEwbcLQuR9Zww
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ3MDUzMDAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AE7LSuuNObCBWYuttxJAgilXJ92GpyV/fTiyXHZ/9LbzXs/MfKnPwRydlmA2ak0r
# GWLDFh89zAWHFI8t9JLwpd/VRoVE3+WyzTIskdbBnHbf1yjo/+0tpHlnroFJdcDS
# MIsH+T7z3ClY+6WnjSTetpg1Y/pLOLXZpZjYeXQiFwo9G5lzUcSd8YVQNPQAGICl
# 2JRSaCNlzAdIFCF5PNKoXbJtEqDcPZ8oDrM9KdO7TqUE5VqeBe6DggY1sZYnQD+/
# LWlz5D0wCriNgGQ/TWWexMwwnEqlIwfkIcNFxo0QND/6Ya9DTAUykk2SKGSPt0kL
# tHxNEn2GJvcNtfohVY/b0tuyF05eXE3cdtYZbeGoU1xQixPZAlTdtLmeFNly82uB
# VbybAZ4Ut18F//UrugVQ9UUdK1uYmc+2SdRQQCccKwXGOuYgZ1ULW2u5PyfWxzo4
# BR++53OB/tZXQpz4OkgBZeqs9YaYLFfKRlQHVtmQghFHzB5v/WFonxDVlvPxy2go
# a0u9Z+ZlIpvooZRvm6OtXxdAjMBcWBAsnBRr/Oj5s356EDdf2l/sLwLFYE61t+ME
# iNYdy0pXL6gN3DxTVf2qjJxXFkFfjjTisndudHsguEMk8mEtnvwo9fOSKT6oRHhM
# 9sZ4HTg/TTMjUljmN3mBYWAWI5ExdC1inuog0xrKmOWVMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGZ8wghmbAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAALN82S/+NRMXVEAAAAA
# As0wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIWR
# sXdOuZRooph2r4oNpZu5QW1NDsaaHVCE/SiRpjsaMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAKY7TL25N6MeJ0wg9IEbUl6GePUkGPcyKJbsw
# WrSYN9/KzX+IuXmKqpSY4CsFaiDUFU142iL2GRwlH0T8eLK44kOMB/r6N/SF2Kor
# uxS5LaQYpq1gcwjnbdAjE6Sb2ZnY66I1MTX3diifx2HpwuFnsjjkAt9fPzwszMNg
# vfzAqDijSlMd1fXxFW9GZBFa0+VMsGDUZXRs20YIMsUltpBV3pIT/qjtWyuCYBCi
# hJQZUPVt/DVYmVRxqIkNIW4Mvrd/2mIBM6Shh4teR1ZNNVl9y0ESt6lMBNk1eu7I
# RP804hgTOrjFEMQnL/12YY6MfsfG+StIS3QBVpgZG39rxD6RMKGCFykwghclBgor
# BgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCAm2qr5C8Si0EzN4AYIqMQiAleC3ZIdOG41
# jPalaM3LWwIGY/dYnaknGBMyMDIzMDMwMzExMDU1OC40NjlaMASAAgH0oIHYpIHV
# MIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjg2REYtNEJCQy05MzM1MSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAG3ISca
# B6IqhkYAAQAAAbcwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjIwOTIwMjAyMjE0WhcNMjMxMjE0MjAyMjE0WjCB0jELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjo4NkRGLTRCQkMtOTMzNTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMf9
# z1dQNBNkTBq3HJclypjQcJIlDAgpvsw4vHJe06n532RKGkcn0V7p65OeA1wOoO+8
# NsopnjPpVZ8+4s/RhdMCMNPQJXoWdkWOp/3puIEs1fzPBgTJrdmzdyUYzrAloICY
# x722gmdpbNf3P0y5Z2gRO48sWIYyYeNJYch+ZfJzXqqvuvq7G8Nm8IMQi8Zayvx+
# 5dSGBM5VYHBxCEjXF9EN6Qw7A60SaXjKjojSpUmpaM4FmVec985PNdSh8hOeP2tL
# 781SBan92DT19tfNHv9H0FAmE2HGRwizHkJ//mAZdS0s6bi/UwPMksAia5bpnIDB
# OoaYdWkV0lVG5rN0+ltRz9zjlaH9uhdGTJ+WiNKOr7mRnlzYQA53ftSSJBqsEpTz
# Cv7c673fdvltx3y48Per6vc6UR5e4kSZsH141IhxhmRR2SmEabuYKOTdO7Q/vlvA
# fQxuEnJ93NL4LYV1IWw8O+xNO6gljrBpCOfOOTQgWJF+M6/IPyuYrcv79Lu7lc67
# S+U9MEu2dog0MuJIoYCMiuVaXS5+FmOJiyfiCZm0VJsJ570y9k/tEQe6aQR9MxDW
# 1p2F3HWebolXj9su7zrrElNlHAEvpFhcgoMniylNTiTZzLwUj7TH83gnugw1FCEV
# Vh5U9lwNMPL1IGuz/3U+RT9wZCBJYIrFJPd6k8UtAgMBAAGjggFJMIIBRTAdBgNV
# HQ4EFgQUs/I5Pgw0JAVhDdYB2yPII8l4tOwwHwYDVR0jBBgwFoAUn6cVXQBeYl2D
# 9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1l
# LVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQAD
# ggIBAA2dZMybhVxSXTbJzFgvNiMCV5/Ayn5UuzJU495YDtcefold0ehR9QBGBhHm
# AMt10WYCHz2WQUyM3mQD4IsHfEL1JEwgG9tGq71ucn9dknLBHD30JvbQRhIKcvFS
# nvRCCpVpilM8F/YaWXC9VibSef/PU2GWA+1zs64VFxJqHeuy8KqrQyfF20SCnd8z
# RZl4YYBcjh9G0GjhJHUPAYEx0r8jSWjyi2o2WAHD6CppBtkwnZSf7A68DL4OwwBp
# mFB3+vubjgNwaICS+fkGVvRnP2ZgmlfnaAas8Mx7igJqciqq0Q6An+0rHj1kxisN
# dIiTzFlu5Gw2ehXpLrl59kvsmONVAJHhndpx3n/0r76TH+3WNS9UT9jbxQkE+t2t
# hif6MK5krFMnkBICCR/DVcV1qw9sg6sMEo0wWSXlQYXvcQWA65eVzSkosylhIlIZ
# ZLL3GHZD1LQtAjp2A5F7C3Iw4Nt7C7aDCfpFxom3ZulRnFJollPHb3unj9hA9xvR
# iKnWMAMpS4MZAoiV4O29zWKZdUzygp7gD4WjKK115KCJ0ovEcf92AnwMAXMnNs1o
# 0LCszg+uDmiQZs5eR7jzdKzVfF1z7bfDYNPAJvm5pSQdby3wIOsN/stYjM+EkaPt
# Uzr8OyMwrG+jpFMbsB4cfN6tvIeGtrtklMJFtnF68CcZZ5IAMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9AgEBMIIBAKGB2KSB1TCB
# 0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMk
# TWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjo4NkRGLTRCQkMtOTMzNTElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAyGdBGMObODlsGBZm
# SUX2oWgfqcaggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOeruhEwIhgPMjAyMzAzMDMwODEzMDVaGA8yMDIzMDMw
# NDA4MTMwNVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA56u6EQIBADAHAgEAAgIN
# DzAHAgEAAgIRbTAKAgUA560LkQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# ABJqNWgZJVB7aTfzhK4vlP1/R5Ug7YYZI2w6+iFOvZiWqnpmMwxNA+algoFLyW5B
# QbLbIS94iZ+/1BwmPDvLrgfgpaUQahCGU4sUHCY8cCeDI2H0ZpjxkhYXM++5jyc4
# TJeHXaWzBYIv0/4NAsfK1iWXg+d7saOIDwrjdAwcEIMXMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG3IScaB6IqhkYAAQAA
# AbcwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQgye2uwIr/UrecFDGQ0VCfphaZc9AFDa0XT83/TRI4
# cL4wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBsJ3jTsh7aL8hNeiYGL5/8
# IBn8zUfr7/Q7rkM8ic1wQTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABtyEnGgeiKoZGAAEAAAG3MCIEINUDOAGe5e2n5LqhXEgA+6E3
# ofJEsv5BdLnq/j49LQjGMA0GCSqGSIb3DQEBCwUABIICACzPX4W5JTXpsbqh99a/
# AjzR6HE/EKrPiv53NRPQKgkpjKxVGiX0HnvZFliyWMS8F34Z0FCksfKIkrxKdZUT
# 6zKa76pIsjURC0NrWw20xgHLyRZjYJNJCYTG4/jsUVZhJFbpHvU1MawJfa0DhQ0Q
# yFJlL30s6STdS6x9clT5iGYqsaAwP9I6mmbAJwo5jWR/KHcSi9BK8OCik18q8Rg6
# eV05YnXwaCVsrqxu4jjieabNzLEoaaNuY6uwK6YEEOEs9SPs2htDAVgbRPY5hhdL
# 3w50qWpi1gTwulPHtbsFSMsmtuKtC71F2sdBQE6NHpHNMByeIIFVJY4Y+cFlKoX2
# H7Ls/mtuKdRLmhooX2AOLLaw+s4nisdQeTCV5u5yzxgWRE0DXXWpLAwNYCY09gtg
# JZxd8MQ0jJu/d9ldJyUzJPRiFrYkDBiwEph9pK0xj+cel1JfQexMIYv3s0CMNlLJ
# +g3dVlx9BgqMHarG6Wka9st5/pv/y8uvdCA/5D7ja7pC1qRhOF8VhQayURjFmHQA
# Cok5Xy+8Isn/Qvzu+Rg/o2+YY9kkZtYG/h3hCkR3K0KS7SlR52f3viiNiGBh2Vv9
# 8KKXOyUrbVtotOlUWzNiwil6yNaOAsOpQdQXyjWBU2LIhCX09XdXbS534zzVpJoq
# pRvshg2HD6Zew2LswJKme4HU
# SIG # End signature block
