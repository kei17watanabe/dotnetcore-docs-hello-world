<#
   ***Directory Services Authentication Scripts***

   Requires: PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)

   Last Updated: 12/12/2022

   Version: 5.0
#>

[cmdletbinding(PositionalBinding = $false, DefaultParameterSetName = "Default")]
param(
    [Parameter(ParameterSetName = "Default")]
    [Parameter(ParameterSetName = "Container")]
    [Parameter(ParameterSetName = "WatchProcess")]
    [switch]$accepteula,
    [Parameter(ParameterSetName = "Default")]
    [Parameter(ParameterSetName = "Container")]
    [Parameter(ParameterSetName = "WatchProcess")]
    [switch]$v,
    [Parameter(ParameterSetName = "Default")]
    [Parameter(ParameterSetName = "WatchProcess")]
    [switch]$nonet,
    [Parameter(ParameterSetName = "Container")]
    [string]$containerId,
    [Parameter(ParameterSetName = "WatchProcess")]
    [string]$watchProcess,
    [Parameter(ParameterSetName = "Default")]
    [Parameter(ParameterSetName = "Container")]
    [Parameter(ParameterSetName = "WatchProcess")]
    [switch]$version,
    [switch]$slowlogon)


[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')

function ShowEULAPopup($mode) {
    $EULA = New-Object -TypeName System.Windows.Forms.Form
    $richTextBox1 = New-Object System.Windows.Forms.RichTextBox
    $btnAcknowledge = New-Object System.Windows.Forms.Button
    $btnCancel = New-Object System.Windows.Forms.Button

    $EULA.SuspendLayout()
    $EULA.Name = "EULA"
    $EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"

    $richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $richTextBox1.Location = New-Object System.Drawing.Point(12, 12)
    $richTextBox1.Name = "richTextBox1"
    $richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
    $richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
    $richTextBox1.TabIndex = 0
    $richTextBox1.ReadOnly = $True
    $richTextBox1.Add_LinkClicked({ Start-Process -FilePath $_.LinkText })
    $richTextBox1.Rtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fswiss\fprq2\fcharset0 Segoe UI;}{\f1\fnil\fcharset0 Calibri;}{\f2\fnil\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue255;}
{\*\generator Riched20 10.0.19041}{\*\mmathPr\mdispDef1\mwrapIndent1440 }\viewkind4\uc1
\pard\widctlpar\f0\fs19\lang1033 MICROSOFT SOFTWARE LICENSE TERMS\par
Microsoft Diagnostic Scripts and Utilities\par
\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}\par
\pard
{\pntext\f0 1.\tab}{\*\pn\pnlvlbody\pnf0\pnindent0\pnstart1\pndec{\pntxta.}}
\fi-360\li360 INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (\ldblquote Microsoft\rdblquote ) grants you (\ldblquote Customer\rdblquote  or \ldblquote you\rdblquote ) a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the "Software"), solely for Customer\rquote s internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). \ldblquote Use\rdblquote  means to copy, install, execute, access, display, run or otherwise interact with the Software. \par
\pard\widctlpar\par
\pard\widctlpar\li360 You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft\rquote s IT systems or impair anyone else\rquote s use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above.\par
\par
\pard\widctlpar\fi-360\li360 2.\tab DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at {{\field{\*\fldinst{HYPERLINK https://aka.ms/privacy }}{\fldrslt{https://aka.ms/privacy\ul0\cf0}}}}\f0\fs19 . Your use of the Software operates as your consent to these practices.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 3.\tab FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose.\~ You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 4.\tab EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit {{\field{\*\fldinst{HYPERLINK https://aka.ms/exporting }}{\fldrslt{https://aka.ms/exporting\ul0\cf0}}}}\f0\fs19 .\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 5.\tab REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party\rquote s intellectual property to any other license terms or require the other party to distribute source code to any of its technologies.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 6.\tab DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED \ldblquote AS IS,\rdblquote  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\par
\pard\widctlpar\qj\par
\pard\widctlpar\fi-360\li360\qj 7.\tab LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 8.\tab BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States.  If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can\rquote t, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (\ldblquote FAA\rdblquote ), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at {{\field{\*\fldinst{HYPERLINK https://aka.ms/arb-agreement-4 }}{\fldrslt{https://aka.ms/arb-agreement-4\ul0\cf0}}}}\f0\fs19 . You and Microsoft agree to these terms. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 9.\tab LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration).\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 10.\tab ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software.\par
\pard\sa200\sl276\slmult1\f1\fs22\lang9\par
\pard\f2\fs17\lang2057\par
}
"@
    $richTextBox1.BackColor = [System.Drawing.Color]::White
    $btnAcknowledge.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnAcknowledge.Location = New-Object System.Drawing.Point(544, 415)
    $btnAcknowledge.Name = "btnAcknowledge";
    $btnAcknowledge.Size = New-Object System.Drawing.Size(119, 23)
    $btnAcknowledge.TabIndex = 1
    $btnAcknowledge.Text = "Accept"
    $btnAcknowledge.UseVisualStyleBackColor = $True
    $btnAcknowledge.Add_Click({ $EULA.DialogResult = [System.Windows.Forms.DialogResult]::Yes })

    $btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnCancel.Location = New-Object System.Drawing.Point(669, 415)
    $btnCancel.Name = "btnCancel"
    $btnCancel.Size = New-Object System.Drawing.Size(119, 23)
    $btnCancel.TabIndex = 2
    if ($mode -ne 0) {
        $btnCancel.Text = "Close"
    }
    else {
        $btnCancel.Text = "Decline"
    }
    $btnCancel.UseVisualStyleBackColor = $True
    $btnCancel.Add_Click({ $EULA.DialogResult = [System.Windows.Forms.DialogResult]::No })

    $EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
    $EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    $EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
    $EULA.Controls.Add($btnCancel)
    $EULA.Controls.Add($richTextBox1)
    if ($mode -ne 0) {
        $EULA.AcceptButton = $btnCancel
    }
    else {
        $EULA.Controls.Add($btnAcknowledge)
        $EULA.AcceptButton = $btnAcknowledge
        $EULA.CancelButton = $btnCancel
    }
    $EULA.ResumeLayout($false)
    $EULA.Size = New-Object System.Drawing.Size(800, 650)

    Return ($EULA.ShowDialog())
}

function ShowEULAIfNeeded($toolName, $mode) {
    $eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
    $eulaAccepted = "No"
    $eulaValue = $toolName + " EULA Accepted"
    if (Test-Path $eulaRegPath) {
        $eulaRegKey = Get-Item $eulaRegPath
        $eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
    }
    else {
        $eulaRegKey = New-Item $eulaRegPath
    }
    if ($mode -eq 2) {
        # silent accept
        $eulaAccepted = "Yes"
        $ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
    }
    else {
        if ($eulaAccepted -eq "No") {
            $eulaAccepted = ShowEULAPopup($mode)
            if ($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes) {
                $eulaAccepted = "Yes"
                $ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
            }
        }
    }
    return $eulaAccepted
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

function Check-ContainerIsNano {
    param($ContainerId)

    # This command is finicky and cannot use a powershell variable for the command
    $ContainerBase = Invoke-Container -ContainerId $containerId -UseCmd -Command "reg query `"hklm\software\microsoft\windows nt\currentversion`" /v EditionID"
    Write-Verbose "Container Base: $ContainerBase"
    # We only check for nano server as it is the most restrictive
    if ($ContainerBase -like "*Nano*") {
        return $true
    }
    else {
        return $false
    }
}


function Check-ContainsScripts {
    param(
        $ContainerId,
        [switch]$IsNano
    )

    if ($IsNano) {
        $Result = Invoke-Container -ContainerId $containerId -Nano -Command "if exist auth.wprp (echo true)"

        if ($Result -eq "True") {

            $Result = Invoke-Container -ContainerId $containerId -Nano -Command "type auth.wprp"
            $Result = $Result[1]
            if (!$Result.Contains($_Authscriptver)) {
                $InnerScriptVersion = $Result.Split(" ")[1].Split("=")[1].Trim("`"")
                Write-Host "$ContainerId Script Version mismatch" -ForegroundColor Yellow
                Write-Host "Container Host Version: $_Authscriptver" -ForegroundColor Yellow
                Write-Host "Container Version: $InnerScriptVersion" -ForegroundColor Yellow
                return $false
            }
            Out-File -FilePath $_CONTAINER_DIR\script-info.txt -InputObject "SCRIPT VERSION: $_Authscriptver"
            return $true
        }
        else {
            return $false
        }
    }
    else {
        $StartResult = Invoke-Container -ContainerId $containerId -Command "Test-Path start-auth.ps1"
        $StopResult = Invoke-Container -ContainerId $containerId -Command "Test-Path stop-auth.ps1"
        if ($StartResult -eq "True" -and $StopResult -eq "True") {
            # Checking script version
            $InnerScriptVersion = Invoke-Container -ContainerId $containerId -Command ".\start-auth.ps1 -accepteula -version"
            if ($InnerScriptVersion -ne $_Authscriptver) {
                Write-Host "$ContainerId Script Version mismatch" -ForegroundColor Yellow
                Write-Host "Container Host Version: $_Authscriptver" -ForegroundColor Yellow
                Write-Host "Container Version: $InnerScriptVersion" -ForegroundColor Yellow
                return $false
            }
            else {
                Out-File -FilePath $_CONTAINER_DIR\script-info.txt -InputObject "SCRIPT VERSION: $_Authscriptver"
                return $true
            }
        }
        else {
            Write-Host "Container: $ContainerId missing tracing scripts!" -ForegroundColor Yellow
            return $false
        }
    }
}

function Check-GMSA {
    param($ContainerId)

    $CredentialString = docker inspect -f "{.HostConfig.SecurityOpt}" $ContainerId
    if ($CredentialString -ne "[]") {
        Write-Verbose "GMSA Credential String: $CredentialString"
        # We need to check if we have Test-ADServiceAccount
        if ((Get-Command "Test-ADServiceAccount" -ErrorAction "SilentlyContinue") -ne $null) {
            $ServiceAccountName = $(docker inspect -f "{{ .Config.Hostname }}" $ContainerId)
            $Result = "START:`n`nRunning: Test-ADServiceAccount $ServiceAccountName`nResult:"

            try {
                $Result += Test-ADServiceAccount -Identity $ServiceAccountName -Verbose -ErrorAction SilentlyContinue
            }
            catch {
                $Result += "Unable to find object with identity $containerId"
            }

            Out-File $_CONTAINER_DIR\gMSATest.txt -InputObject $Result
        }
    }
}

function Generate-WPRP {
    param($ContainerId)
    $Header = @"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="$_Authscriptver" Author="Microsoft Corporation" Copyright="Microsoft Corporation" Company="Microsoft Corporation">
  <Profiles>

"@
    $Footer = @"
  </Profiles>
</WindowsPerformanceRecorder>
"@


    $Netmon = "{2ED6006E-4729-4609-B423-3EE7BCD678EF}"

    $ProviderList = (("NGC", $NGC),
     ("Biometric", $Biometric),
     ("LSA", $LSA),
     ("Ntlm_CredSSP", $Ntlm_CredSSP),
     ("Kerberos", $Kerberos),
     ("KDC", $KDC),
     ("SSL", $SSL),
     ("WebAuth", $WebAuth),
     ("Smartcard", $Smartcard),
     ("CredprovAuthui", $CredprovAuthui),
     ("AppX", $AppX),
     ("SAM", $SAM),
     ("kernel", $Kernel),
     ("Netmon", $Netmon))

    # NOTE(will): Checking if Client SKU
    $ClientSKU = Invoke-Container -ContainerId $ContainerId -Nano -Command "reg query HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions /v ProductType | findstr WinNT"
    if ($ClientSKU -ne $null) {
        $ProviderList.Add(("CryptNcryptDpapi", $CryptNcryptDpapi))
    }

    foreach ($Provider in $ProviderList) {
        $ProviderName = $Provider[0]
        $Header += @"
    <EventCollector Id="EventCollector$ProviderName" Name="EventCollector$ProviderName">
      <BufferSize Value="64" />
      <Buffers Value="4" />
    </EventCollector>

"@
    }

    $Header += "`n`n"

    # Starting on provider generation

    foreach ($Provider in $ProviderList) {
        $ProviderCount = 0
        $ProviderName = $Provider[0]

        foreach ($ProviderItem in $Provider[1]) {
            $ProviderParams = $ProviderItem.Split("!")
            $ProviderGuid = $ProviderParams[0].Replace("{", '').Replace("}", '')
            $ProviderFlags = $ProviderParams[1]

            $Header += @"
    <EventProvider Id="$ProviderName$ProviderCount" Name="$ProviderGuid"/>

"@
            $ProviderCount++
        }
    }

    # Generating profiles
    foreach ($Provider in $ProviderList) {
        $ProviderName = $Provider[0]
        $Header += @"
  <Profile Id="$ProviderName.Verbose.File" Name="$ProviderName" Description="$ProviderName.1" LoggingMode="File" DetailLevel="Verbose">
    <Collectors>
      <EventCollectorId Value="EventCollector$ProviderName">
        <EventProviders>

"@
        $ProviderCount = 0
        for ($i = 0; $i -lt $Provider[1].Count; $i++) {
            $Header += "`t`t`t<EventProviderId Value=`"$ProviderName$ProviderCount`" />`n"
            $ProviderCount++
        }

        $Header += @"
        </EventProviders>
      </EventCollectorId>
    </Collectors>
  </Profile>
  <Profile Id="$ProviderName.Light.File" Name="$ProviderName" Description="$ProviderName.1" Base="$ProviderName.Verbose.File" LoggingMode="File" DetailLevel="Light" />
  <Profile Id="$ProviderName.Verbose.Memory" Name="$ProviderName" Description="$ProviderName.1" Base="$ProviderName.Verbose.File" LoggingMode="Memory" DetailLevel="Verbose" />
  <Profile Id="$ProviderName.Light.Memory" Name="$ProviderName" Description="$ProviderName.1" Base="$ProviderName.Verbose.File" LoggingMode="Memory" DetailLevel="Light" />

"@

        # Keep track of the providers that are currently running
        Out-File -FilePath "$_CONTAINER_DIR\RunningProviders.txt" -InputObject "$ProviderName" -Append
    }


    $Header += $Footer

    # Writing to a file
    Out-file -FilePath "auth.wprp" -InputObject $Header -Encoding ascii

}

function Start-NanoTrace {
    param($ContainerId)

    # Event Logs
    foreach ($EventLog in $_EVENTLOG_LIST) {
        $EventLogParams = $EventLog.Split("!")
        $EventLogName = $EventLogParams[0]
        $EventLogOptions = $EventLogParams[1]

        $ExportLogName += ".evtx"

        if ($EventLogOptions -ne "NONE") {
            Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wevtutil set-log $EventLogName /enabled:true /rt:false /q:true"

            if ($EventLogOptions.Contains("EXPORT")) {
                $ExportName = $EventLogName.Replace("Microsoft-Windows-", "").Replace(" ", "_").Replace("/", "_")
                Invoke-Container -ContainerId $ContainerId -Nano -Record -PreTrace -Command "wevtutil export-log $EventLogName $ExportName /overwrite:true"
            }
            if ($EventLogOptions.Contains("CLEAR")) {
                Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wevtutil clear-log $EventLogName"
            }
            if ($EventLogOptions.Contains("SIZE")) {
                Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wevtutil set-log $EventLogName /ms:102400000"
            }
        }
    }

    # Reg Add
    foreach ($RegAction in $_REG_ADD) {
        $RegParams = $RegAction.Split("!")
        $RegKey = $RegParams[0]
        $RegName = $RegParams[1]
        $RegType = $RegParams[2]
        $RegValue = $RegParams[3]

        Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "reg add $RegKey /v $RegName /t $RegType /d $RegValue /f"
    }

    Get-Content "$_CONTAINER_DIR\RunningProviders.txt" | ForEach-Object {
        Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wpr -start auth.wprp!$_ -instancename $_"
    }


}


# *** DEFINE ETL PROVIDER GROUPINGS ***

# **NGC**
$NGC = @(
    '{B66B577F-AE49-5CCF-D2D7-8EB96BFD440C}!0x0'                # Microsoft.Windows.Security.NGC.KspSvc
    '{CAC8D861-7B16-5B6B-5FC0-85014776BDAC}!0x0'                # Microsoft.Windows.Security.NGC.CredProv
    '{6D7051A0-9C83-5E52-CF8F-0ECAF5D5F6FD}!0x0'                # Microsoft.Windows.Security.NGC.CryptNgc
    '{0ABA6892-455B-551D-7DA8-3A8F85225E1A}!0x0'                # Microsoft.Windows.Security.NGC.NgcCtnr
    '{9DF6A82D-5174-5EBF-842A-39947C48BF2A}!0x0'                # Microsoft.Windows.Security.NGC.NgcCtnrSvc
    '{9B223F67-67A1-5B53-9126-4593FE81DF25}!0x0'                # Microsoft.Windows.Security.NGC.KeyStaging
    '{89F392FF-EE7C-56A3-3F61-2D5B31A36935}!0x0'                # Microsoft.Windows.Security.NGC.CSP
    '{CDD94AC7-CD2F-5189-E126-2DEB1B2FACBF}!0x0'                # Microsoft.Windows.Security.NGC.LocalAccountMigPlugin
    '{1D6540CE-A81B-4E74-AD35-EEF8463F97F5}!0xffff'             # Microsoft-Windows-Security-NGC-PopKeySrv
    '{CDC6BEB9-6D78-5138-D232-D951916AB98F}!0x0'                # Microsoft.Windows.Security.NGC.NgcIsoCtnr
    '{C0B2937D-E634-56A2-1451-7D678AA3BC53}!0x0'                # Microsoft.Windows.Security.Ngc.Truslet
    '{9D4CA978-8A14-545E-C047-A45991F0E92F}!0x0'                # Microsoft.Windows.Security.NGC.Recovery
    '{3b9dbf69-e9f0-5389-d054-a94bc30e33f7}!0x0'                # Microsoft.Windows.Security.NGC.Local
    '{34646397-1635-5d14-4d2c-2febdcccf5e9}!0x0'                # Microsoft.Windows.Security.NGC.KeyCredMgr
    '{c12f629d-37d4-58f7-22a8-94ac45ad8648}!0x0'                # Microsoft.Windows.Security.NGC.Utils
    '{3A8D6942-B034-48e2-B314-F69C2B4655A3}!0xffffffff'         # TPM
    '{5AA9A3A3-97D1-472B-966B-EFE700467603}!0xffffffff'         # TPM Virtual Smartcard card simulator
    '{EAC19293-76ED-48C3-97D3-70D75DA61438}!0xffffffff'         # Cryptographic TPM Endorsement Key Services

    '{23B8D46B-67DD-40A3-B636-D43E50552C6D}!0x0'                # Microsoft-Windows-User Device Registration (event)

    '{2056054C-97A6-5AE4-B181-38BC6B58007E}!0x0'                # Microsoft.Windows.Security.DeviceLock

    '{7955d36a-450b-5e2a-a079-95876bca450a}!0x0'                # Microsoft.Windows.Security.DevCredProv
    '{c3feb5bf-1a8d-53f3-aaa8-44496392bf69}!0x0'                # Microsoft.Windows.Security.DevCredSvc
    '{78983c7d-917f-58da-e8d4-f393decf4ec0}!0x0'                # Microsoft.Windows.Security.DevCredClient
    '{36FF4C84-82A2-4B23-8BA5-A25CBDFF3410}!0x0'                # Microsoft.Windows.Security.DevCredWinRt
    '{86D5FE65-0564-4618-B90B-E146049DEBF4}!0x0'                # Microsoft.Windows.Security.DevCredTask

    '{D5A5B540-C580-4DEE-8BB4-185E34AA00C5}!0x0'                # MDM SCEP Trace
    '{9FBF7B95-0697-4935-ADA2-887BE9DF12BC}!0x0'                # Microsoft-Windows-DM-Enrollment-Provider (event)
    '{3DA494E4-0FE2-415C-B895-FB5265C5C83B}!0x0'                # Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider (event)

    '{73370BD6-85E5-430B-B60A-FEA1285808A7}!0x0'                # Microsoft-Windows-CertificateServicesClient (event)
    '{F0DB7EF8-B6F3-4005-9937-FEB77B9E1B43}!0x0'                # Microsoft-Windows-CertificateServicesClient-AutoEnrollment (event)
    '{54164045-7C50-4905-963F-E5BC1EEF0CCA}!0x0'                # Microsoft-Windows-CertificateServicesClient-CertEnroll (event)
    '{89A2278B-C662-4AFF-A06C-46AD3F220BCA}!0x0'                # Microsoft-Windows-CertificateServicesClient-CredentialRoaming (event)
    '{BC0669E1-A10D-4A78-834E-1CA3C806C93B}!0x0'                # Microsoft-Windows-CertificateServicesClient-Lifecycle-System (event)
    '{BEA18B89-126F-4155-9EE4-D36038B02680}!0x0'                # Microsoft-Windows-CertificateServicesClient-Lifecycle-User (event)
    '{B2D1F576-2E85-4489-B504-1861C40544B3}!0x0'                # Microsoft-Windows-CertificateServices-Deployment (event)
    '{98BF1CD3-583E-4926-95EE-A61BF3F46470}!0x0'                # Microsoft-Windows-CertificationAuthorityClient-CertCli (event)
    '{AF9CC194-E9A8-42BD-B0D1-834E9CFAB799}!0x0'                # Microsoft-Windows-CertPolEng (event)

    '{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b}!0xFFFFFFFF'         # Microsoft.Windows.Shell.CloudExperienceHost
    '{99eb7b56-f3c6-558c-b9f6-09a33abb4c83}!0xFFFFFFFF'         # Microsoft.Windows.Shell.CloudExperienceHost.Common
    '{aa02d1a4-72d8-5f50-d425-7402ea09253a}!0x0'                # Microsoft.Windows.Shell.CloudDomainJoin.Client
    '{507C53AE-AF42-5938-AEDE-4A9D908640ED}!0x0'                # Microsoft.Windows.Security.Credentials.UserConsentVerifier

    '{02ad713f-20d4-414f-89d0-da5a6f3470a9}!0xffffffffffffffff' # Microsoft.Windows.Security.CFL.API
    '{acc49822-f0b2-49ff-bff2-1092384822b6}!0xffffffffffffffff' # Microsoft.CAndE.ADFabric.CDJ
    '{f245121c-b6d1-5f8a-ea55-498504b7379e}!0xffffffffffffffff' # Microsoft.Windows.DeviceLockSettings
)

# **NGC** **Add additional NGC providers in case it's a client and the '-v' switch is added**
if ($v) {
    if ($ProductType -eq "WinNT") {
        $NGC = $NGC + @(
            '{6ad52b32-d609-4be9-ae07-ce8dae937e39}!0xffffffffffffffff'     # Microsoft-Windows-RPC
            '{f4aed7c7-a898-4627-b053-44a7caa12fcd}!0xffffffffffffffff'     # Microsoft-Windows-RPC-Events
            '{ac01ece8-0b79-5cdb-9615-1b6a4c5fc871}!0xffffffffffffffff'     # Microsoft.Windows.Application.Service
        )
    }
}

# **Biometric**
$Biometric = @(
    '{34BEC984-F11F-4F1F-BB9B-3BA33C8D0132}!0xffff'
    '{225b3fed-0356-59d1-1f82-eed163299fa8}!0x0'
    '{9dadd79b-d556-53f2-67c4-129fa62b7512}!0x0'
    '{1B5106B1-7622-4740-AD81-D9C6EE74F124}!0x0'
    '{1d480c11-3870-4b19-9144-47a53cd973bd}!0x0'
    '{e60019f0-b378-42b6-a185-515914d3228c}!0x0'
    '{48CAFA6C-73AA-499C-BDD8-C0D36F84813E}!0x0'
    '{add0de40-32b0-4b58-9d5e-938b2f5c1d1f}!0x0'
    '{e92355c0-41e4-4aed-8d67-df6b2058f090}!0x0'
    '{85be49ea-38f1-4547-a604-80060202fb27}!0x0'
    '{F4183A75-20D4-479B-967D-367DBF62A058}!0x0'
    '{0279b50e-52bd-4ed6-a7fd-b683d9cdf45d}!0x0'
    '{39A5AA08-031D-4777-A32D-ED386BF03470}!0x0'
    '{22eb0808-0b6c-5cd4-5511-6a77e6e73a93}!0x0'
    '{63221D5A-4D00-4BE3-9D38-DE9AAF5D0258}!0x0'
    '{9df19cfa-e122-5343-284b-f3945ccd65b2}!0x0'
    '{beb1a719-40d1-54e5-c207-232d48ac6dea}!0x0'
    '{8A89BB02-E559-57DC-A64B-C12234B7572F}!0x0'
    '{a0e3d8ea-c34f-4419-a1db-90435b8b21d0}!0xffffffffffffffff'
)

# **LSA**
$LSA = @(
    '{D0B639E0-E650-4D1D-8F39-1580ADE72784}!0xC43EFF'               # (WPP)LsaTraceControlGuid
    '{169EC169-5B77-4A3E-9DB6-441799D5CACB}!0xffffff'               # LsaDs
    '{DAA76F6A-2D11-4399-A646-1D62B7380F15}!0xffffff'               # (WPP)LsaAuditTraceControlGuid
    '{366B218A-A5AA-4096-8131-0BDAFCC90E93}!0xfffffff'              # (WPP)LsaIsoTraceControlGuid
    '{4D9DFB91-4337-465A-A8B5-05A27D930D48}!0xff'                   # (TL)Microsoft.Windows.Security.LsaSrv
    '{7FDD167C-79E5-4403-8C84-B7C0BB9923A1}!0xFFF'                  # (WPP)VaultGlobalDebugTraceControlGuid
    '{CA030134-54CD-4130-9177-DAE76A3C5791}!0xfffffff'              # (WPP)NETLOGON
    '{5a5e5c0d-0be0-4f99-b57e-9b368dd2c76e}!0xffffffffffffffff'     # (WPP)VaultCDSTraceGuid
    '{2D45EC97-EF01-4D4F-B9ED-EE3F4D3C11F3}!0xffffffffffffffff'     # (WPP)GmsaClientTraceControlGuid
    '{C00D6865-9D89-47F1-8ACB-7777D43AC2B9}!0xffffffffffffffff'     # (WPP)CCGLaunchPadTraceControlGuid
    '{7C9FCA9A-EBF7-43FA-A10A-9E2BD242EDE6}!0xffffffffffffffff'     # (WPP)CCGTraceControlGuid
    '{794FE30E-A052-4B53-8E29-C49EF3FC8CBE}!0xffffffffffffffff'
    '{ba634d53-0db8-55c4-d406-5c57a9dd0264}!0xffffffffffffffff'     # (TL)Microsoft.Windows.Security.PasswordlessPolicy
    '{45E7DBC5-E130-5CEF-9353-CC5EBF05E6C8}!0xFFFF'                 # (EVT)Microsoft-Windows-Containers-CCG/Admin
    '{A4E69072-8572-4669-96B7-8DB1520FC93A}!0xffffffffffffffff'
    '{C5D12E1B-84A0-4fe6-9E5F-FEBA123EAE66}!0xffffffffffffffff'     # (WPP)RoamingSecurityDebugTraceControlGuid
    '{E2E66F29-4D71-4646-8E58-20E204C3C25B}!0xffffffffffffffff'     # (WPP)RoamingSecurityDebugTraceControlGuid
    '{6f2c1ee5-1dfd-519b-2d55-702756f5964d}!0xffffffffffffffff'
    '{FB093D76-8964-11DF-9EA1-CB38E0D72085}!0xFFFF'                 # (WPP)KDSSVCCtlGuid
    '{3353A14D-EE30-436E-8FF5-575A4351EA80}!0xFFFF'                 # (WPP)KDSPROVCtlGuid
    '{afda4fd8-2fe5-5c75-ba0e-7d5c0b225e12}!0xffffffffffffffff'
    '{cbb61b6d-a2cf-471a-9a58-a4cd5c08ffba}!0xff'                   # (WPP)UACLog
)

# **Ntlm_CredSSP**
$Ntlm_CredSSP = @(
    '{5BBB6C18-AA45-49b1-A15F-085F7ED0AA90}!0x5ffDf'
    '{AC69AE5B-5B21-405F-8266-4424944A43E9}!0xffffffff'
    '{6165F3E2-AE38-45D4-9B23-6B4818758BD9}!0xffffffff'
    '{AC43300D-5FCC-4800-8E99-1BD3F85F0320}!0xffffffffffffffff'
    '{DAA6CAF5-6678-43f8-A6FE-B40EE096E06E}!0xffffffffffffffff'
)

# **Kerberos**
$Kerberos = @(
    '{6B510852-3583-4e2d-AFFE-A67F9F223438}!0x7ffffff'
    '{60A7AB7A-BC57-43E9-B78A-A1D516577AE3}!0xffffff'
    '{FACB33C4-4513-4C38-AD1E-57C1F6828FC0}!0xffffffff'
    '{97A38277-13C0-4394-A0B2-2A70B465D64F}!0xff'
    '{8a4fc74e-b158-4fc1-a266-f7670c6aa75d}!0xffffffffffffffff'
    '{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}!0xffffffffffffffff'
)

# **KDC**
$KDC = @(
    '{1BBA8B19-7F31-43c0-9643-6E911F79A06B}!0xfffff'
    '{f2c3d846-1d17-5388-62fa-3839e9c67c80}!0xffffffffffffffff'
    '{6C51FAD2-BA7C-49b8-BF53-E60085C13D92}!0xffffffffffffffff'
)

# **SAM**
$SAM = @(
    '{8E598056-8993-11D2-819E-0000F875A064}!0xffffffffffffffff'
    '{0D4FDC09-8C27-494A-BDA0-505E4FD8ADAE}!0xffffffffffffffff'
    '{BD8FEA17-5549-4B49-AA03-1981D16396A9}!0xffffffffffffffff'
    '{F2969C49-B484-4485-B3B0-B908DA73CEBB}!0xffffffffffffffff'
    '{548854B9-DA55-403E-B2C7-C3FE8EA02C3C}!0xffffffffffffffff'
)

# **SSL**
$SSL = @(
    '{37D2C3CD-C5D4-4587-8531-4696C44244C8}!0x4000ffff'
)

# **Crypto/Dpapi**
$CryptNcryptDpapi = @(
    '{EA3F84FC-03BB-540e-B6AA-9664F81A31FB}!0xFFFFFFFF'
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473302}!0xFFFFFFFF'
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473301}!0xFFFFFFFF'
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473303}!0xFFFFFFFF'
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473305}!0xFFFFFFFF'
    '{786396CD-2FF3-53D3-D1CA-43E41D9FB73B}!0x0'
    '{a74efe00-14be-4ef9-9da9-1484d5473304}!0xffffffffffffffff'
    '{9d2a53b2-1411-5c1c-d88c-f2bf057645bb}!0xffffffffffffffff'
)

# **WebAuth**
$WebAuth = @(

    '{B1108F75-3252-4b66-9239-80FD47E06494}!0x2FF'                  #IDCommon
    '{82c7d3df-434d-44fc-a7cc-453a8075144e}!0x2FF'                  #IdStoreLib
    '{D93FE84A-795E-4608-80EC-CE29A96C8658}!0x7FFFFFFF'             #idlisten

    '{EC3CA551-21E9-47D0-9742-1195429831BB}!0xFFFFFFFF'             #cloudap
    '{bb8dd8e5-3650-5ca7-4fea-46f75f152414}!0xffffffffffffffff'     #Microsoft.Windows.Security.CloudAp
    '{7fad10b2-2f44-5bb2-1fd5-65d92f9c7290}!0xffffffffffffffff'     #Microsoft.Windows.Security.CloudAp.Critical

    '{077b8c4a-e425-578d-f1ac-6fdf1220ff68}!0xFFFFFFFF'             #Microsoft.Windows.Security.TokenBroker
    '{7acf487e-104b-533e-f68a-a7e9b0431edb}!0xFFFFFFFF'             #Microsoft.Windows.Security.TokenBroker.BrowserSSO
    '{5836994d-a677-53e7-1389-588ad1420cc5}!0xFFFFFFFF'             #Microsoft.Windows.MicrosoftAccount.TBProvider

    '{3F8B9EF5-BBD2-4C81-B6C9-DA3CDB72D3C5}!0x7'                    #wlidsvc
    '{C10B942D-AE1B-4786-BC66-052E5B4BE40E}!0x3FF'                  #livessp
    '{05f02597-fe85-4e67-8542-69567ab8fd4f}!0xFFFFFFFF'             #Microsoft-Windows-LiveId, MSAClientTraceLoggingProvider

    '{74D91EC4-4680-40D2-A213-45E2D2B95F50}!0xFFFFFFFF'             #Microsoft.AAD.CloudAp.Provider
    '{4DE9BC9C-B27A-43C9-8994-0915F1A5E24F}!0xFFFFFFFF'             #Microsoft-Windows-AAD
    '{bfed9100-35d7-45d4-bfea-6c1d341d4c6b}!0xFFFFFFFF'             #AADPlugin
    '{556045FD-58C5-4A97-9881-B121F68B79C5}!0xFFFFFFFF'             #AadCloudAPPlugin
    '{F7C77B8D-3E3D-4AA5-A7C5-1DB8B20BD7F0}!0xFFFFFFFF'             #AadWamExtension
    '{9EBB3B15-B094-41B1-A3B8-0F141B06BADD}!0xFFF'                  #AadAuthHelper
    '{6ae51639-98eb-4c04-9b88-9b313abe700f}!0xFFFFFFFF'             #AadWamPlugin
    '{7B79E9B1-DB01-465C-AC8E-97BA9714BDA2}!0xFFFFFFFF'             #AadTB
    '{86510A0A-FDF4-44FC-B42F-50DD7D77D10D}!0xFFFFFFFF'             #AadBrokerPluginApp
    '{5A9ED43F-5126-4596-9034-1DCFEF15CD11}!0xFFFFFFFF'             #AadCloudAPPluginBVTs

    '{08B15CE7-C9FF-5E64-0D16-66589573C50F}!0xFFFFFF7F'             #Microsoft.Windows.Security.Fido

    '{5AF52B0D-E633-4ead-828A-4B85B8DAAC2B}!0xFFFF'                 #negoexts
    '{2A6FAF47-5449-4805-89A3-A504F3E221A6}!0xFFFF'                 #pku2u

    '{EF98103D-8D3A-4BEF-9DF2-2156563E64FA}!0xFFFF'                 #webauth
    '{2A3C6602-411E-4DC6-B138-EA19D64F5BBA}!0xFFFF'                 #webplatform

    '{FB6A424F-B5D6-4329-B9B5-A975B3A93EAD}!0x000003FF'             #wdigest

    '{2745a526-23f5-4ef1-b1eb-db8932d43330}!0xffffffffffffffff'     #Microsoft.Windows.Security.TrustedSignal
    '{c632d944-dddb-599f-a131-baf37bf22ef0}!0xffffffffffffffff'     #Microsoft.Windows.Security.NaturalAuth.Service

    '{63b6c2d2-0440-44de-a674-aa51a251b123}!0xFFFFFFFF'             #Microsoft.Windows.BrokerInfrastructure
    '{4180c4f7-e238-5519-338f-ec214f0b49aa}!0xFFFFFFFF'             #Microsoft.Windows.ResourceManager
    '{EB65A492-86C0-406A-BACE-9912D595BD69}!0xFFFFFFFF'             #Microsoft-Windows-AppModel-Exec
    '{d49918cf-9489-4bf1-9d7b-014d864cf71f}!0xFFFFFFFF'             #Microsoft-Windows-ProcessStateManager
    '{072665fb-8953-5a85-931d-d06aeab3d109}!0xffffffffffffffff'     #Microsoft.Windows.ProcessLifetimeManager
    '{EF00584A-2655-462C-BC24-E7DE630E7FBF}!0xffffffffffffffff'     #Microsoft.Windows.AppLifeCycle
    '{d48533a7-98e4-566d-4956-12474e32a680}!0xffffffffffffffff'     #RuntimeBrokerActivations
    '{0b618b2b-0310-431e-be64-09f4b3e3e6da}!0xffffffffffffffff'     #Microsoft.Windows.Security.NaturalAuth.wpp
)


# **WebAuth** **Add additional WebAuth providers in case it's a client and the -v switch is added**
if ($v) {
    if ($ProductType -eq "WinNT") {
        $WebAuth = $WebAuth + @(
            '{20f61733-57f1-4127-9f48-4ab7a9308ae2}!0xffffffffffffffff'
            '{b3a7698a-0c45-44da-b73d-e181c9b5c8e6}!0xffffffffffffffff'
            '{4e749B6A-667D-4C72-80EF-373EE3246B08}!0xffffffffffffffff'
        )
    }
}

# **Smartcard**
$Smartcard = @(
    '{30EAE751-411F-414C-988B-A8BFA8913F49}!0xffffffffffffffff'
    '{13038E47-FFEC-425D-BC69-5707708075FE}!0xffffffffffffffff'
    '{3FCE7C5F-FB3B-4BCE-A9D8-55CC0CE1CF01}!0xffffffffffffffff'
    '{FB36CAF4-582B-4604-8841-9263574C4F2C}!0xffffffffffffffff'
    '{133A980D-035D-4E2D-B250-94577AD8FCED}!0xffffffffffffffff'
    '{EED7F3C9-62BA-400E-A001-658869DF9A91}!0xffffffffffffffff'
    '{27BDA07D-2CC7-4F82-BC7A-A2F448AB430F}!0xffffffffffffffff'
    '{15DE6EAF-EE08-4DE7-9A1C-BC7534AB8465}!0xffffffffffffffff'
    '{31332297-E093-4B25-A489-BC9194116265}!0xffffffffffffffff'
    '{4fcbf664-a33a-4652-b436-9d558983d955}!0xffffffffffffffff'
    '{DBA0E0E0-505A-4AB6-AA3F-22F6F743B480}!0xffffffffffffffff'
    '{125f2cf1-2768-4d33-976e-527137d080f8}!0xffffffffffffffff'
    '{beffb691-61cc-4879-9cd9-ede744f6d618}!0xffffffffffffffff'
    '{545c1f45-614a-4c72-93a0-9535ac05c554}!0xffffffffffffffff'
    '{AEDD909F-41C6-401A-9E41-DFC33006AF5D}!0xffffffffffffffff'
    '{09AC07B9-6AC9-43BC-A50F-58419A797C69}!0xffffffffffffffff'
    '{AAEAC398-3028-487C-9586-44EACAD03637}!0xffffffffffffffff'
    '{9F650C63-9409-453C-A652-83D7185A2E83}!0xffffffffffffffff'
    '{F5DBD783-410E-441C-BD12-7AFB63C22DA2}!0xffffffffffffffff'
    '{a3c09ba3-2f62-4be5-a50f-8278a646ac9d}!0xffffffffffffffff'
    '{15f92702-230e-4d49-9267-8e25ae03047c}!0xffffffffffffffff'
    '{179f04fd-cf7a-41a6-9587-a3d22d5e39b0}!0xffffffffffffffff'
)


#  **SHELL/CREDPROVIDER FRAMEWORK AUTHUI/Winlogon - Winlogon provider will not be added to the $CredprovAuthui array if the '-slowlogon' switch is added so that it can be used by WPR**
$CredprovAuthui = @(
    '{5e85651d-3ff2-4733-b0a2-e83dfa96d757}!0xffffffffffffffff'
    '{D9F478BB-0F85-4E9B-AE0C-9343F302F9AD}!0xffffffffffffffff'
    '{462a094c-fc89-4378-b250-de552c6872fd}!0xffffffffffffffff'
    '{8db3086d-116f-5bed-cfd5-9afda80d28ea}!0xffffffffffffffff'
    '{a55d5a23-1a5b-580a-2be5-d7188f43fae1}!0xFFFF'
    '{4b8b1947-ae4d-54e2-826a-1aee78ef05b2}!0xFFFF'
    '{176CD9C5-C90C-5471-38BA-0EEB4F7E0BD0}!0xffffffffffffffff'
    '{3EC987DD-90E6-5877-CCB7-F27CDF6A976B}!0xffffffffffffffff'
    '{41AD72C3-469E-5FCF-CACF-E3D278856C08}!0xffffffffffffffff'
    '{4F7C073A-65BF-5045-7651-CC53BB272DB5}!0xffffffffffffffff'
    '{A6C5C84D-C025-5997-0D82-E608D1ABBBEE}!0xffffffffffffffff'
    '{C0AC3923-5CB1-5E37-EF8F-CE84D60F1C74}!0xffffffffffffffff'
    '{DF350158-0F8F-555D-7E4F-F1151ED14299}!0xffffffffffffffff'
    '{FB3CD94D-95EF-5A73-B35C-6C78451095EF}!0xffffffffffffffff'
    '{d451642c-63a6-11d7-9720-00b0d03e0347}!0xffffffffffffffff'
    '{b39b8cea-eaaa-5a74-5794-4948e222c663}!0xffffffffffffffff'
    if (!$slowlogon) { '{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}!0xffffffffffffffff' }
    '{c2ba06e2-f7ce-44aa-9e7e-62652cdefe97}!0xffffffffffffffff'
    '{5B4F9E61-4334-409F-B8F8-73C94A2DBA41}!0xffffffffffffffff'
    '{a789efeb-fc8a-4c55-8301-c2d443b933c0}!0xffffffffffffffff'
    '{301779e2-227d-4faf-ad44-664501302d03}!0xffffffffffffffff'
    '{557D257B-180E-4AAE-8F06-86C4E46E9D00}!0xffffffffffffffff'
    '{D33E545F-59C3-423F-9051-6DC4983393A8}!0xffffffffffffffff'
    '{19D78D7D-476C-47B6-A484-285D1290A1F3}!0xffffffffffffffff'
    '{EB7428F5-AB1F-4322-A4CC-1F1A9B2C5E98}!0xffffffffffffffff'
    '{D9391D66-EE23-4568-B3FE-876580B31530}!0xffffffffffffffff'
    '{D138F9A7-0013-46A6-ADCC-A3CE6C46525F}!0xffffffffffffffff'
    '{2955E23C-4E0B-45CA-A181-6EE442CA1FC0}!0xffffffffffffffff'
    '{012616AB-FF6D-4503-A6F0-EFFD0523ACE6}!0xffffffffffffffff'
    '{5A24FCDB-1CF3-477B-B422-EF4909D51223}!0xffffffffffffffff'
    '{63D2BB1D-E39A-41B8-9A3D-52DD06677588}!0xffffffffffffffff'
    '{4B812E8E-9DFC-56FC-2DD2-68B683917260}!0xffffffffffffffff'
    '{169CC90F-317A-4CFB-AF1C-25DB0B0BBE35}!0xffffffffffffffff'
    '{041afd1b-de76-48e9-8b5c-fade631b0dd5}!0xffffffffffffffff'
    '{39568446-adc1-48ec-8008-86c11637fc74}!0xffffffffffffffff'
    '{d1731de9-f885-4e1f-948b-76d52702ede9}!0xffffffffffffffff'
    '{d5272302-4e7c-45be-961c-62e1280a13db}!0xffffffffffffffff'
    '{55f422c8-0aa0-529d-95f5-8e69b6a29c98}!0xffffffffffffffff'
)


# **AppX**
$Appx = @(
    '{f0be35f8-237b-4814-86b5-ade51192e503}!0xffffffffffffffff'
    '{8127F6D4-59F9-4abf-8952-3E3A02073D5F}!0xffffffffffffffff'
    '{3ad13c53-cf84-4522-b349-56b81ffcd939}!0xffffffffffffffff'
    '{b89fa39d-0d71-41c6-ba55-effb40eb2098}!0xffffffffffffffff'
    '{fe762fb1-341a-4dd4-b399-be1868b3d918}!0xffffffffffffffff'
)


# **Kernel**
$kernel = @(
    '{9E814AAD-3204-11D2-9A82-006008A86939}!0x0000000000000005'
)

# Event Log Providers

$_EVENTLOG_LIST = @(
    # LOGNAME!FLAG1|FLAG2|FLAG3
    "Application!NONE"
    "System!NONE"
    "Microsoft-Windows-CAPI2/Operational!CLEAR|SIZE|EXPORT"
    "Microsoft-Windows-Kerberos/Operational!CLEAR"
    "Microsoft-Windows-Kerberos-key-Distribution-Center/Operational!DEFAULT"
    "Microsoft-Windows-Kerberos-KdcProxy/Operational!DEFAULT"
    "Microsoft-Windows-WebAuth/Operational!DEFAULT"
    "Microsoft-Windows-WebAuthN/Operational!EXPORT"
    "Microsoft-Windows-CertPoleEng/Operational!CLEAR"
    "Microsoft-Windows-IdCtrls/Operational!EXPORT"
    "Microsoft-Windows-User Control Panel/Operational!EXPORT"
    "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController!DEFAULT"
    "Microsoft-Windows-Authentication/ProtectedUser-Client!DEFAULT"
    "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController!DEFAULT"
    "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController!DEFAULT"
    "Microsoft-Windows-Biometrics/Operational!EXPORT"
    "Microsoft-Windows-LiveId/Operational!EXPORT"
    "Microsoft-Windows-AAD/Analytic!DEFAULT"
    "Microsoft-Windows-AAD/Operational!EXPORT"
    "Microsoft-Windows-User Device Registration/Debug!DEFAULT"
    "Microsoft-Windows-User Device Registration/Admin!EXPORT"
    "Microsoft-Windows-HelloForBusiness/Operational!EXPORT"
    "Microsoft-Windows-Shell-Core/Operational!DEFAULT"
    "Microsoft-Windows-WMI-Activity/Operational!DEFAULT"
    "Microsoft-Windows-GroupPolicy/Operational!DEFAULT"
    "Microsoft-Windows-Crypto-DPAPI/Operational!EXPORT"
    "Microsoft-Windows-Containers-CCG/Admin!NONE"
)

# Registry Lists

$_REG_ADD = @(
    # KEY!NAME!TYPE!VALUE
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters!InfoLevel!REG_DWORD!0xFFFF"
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters!InfoLevel!REG_DWORD!0xFFFF"
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA!SPMInfoLevel!REG_DWORD!0xC43EFF"
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA!LogToFile!REG_DWORD!1"
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA!NegEventMask!REG_DWORD!0xF"
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA!LspDbgInfoLevel!REG_DWORD!0x41C24800"
    "HKLM\SYSTEM\CurrentControlSet\Control\LSA!LspDbgTraceOptions!REG_DWORD!0x1"
)



[float]$_Authscriptver = "5.0"
$_WatchProcess = $null
$_BASE_LOG_DIR = ".\authlogs"
$_LOG_DIR = $_BASE_LOG_DIR
$_CH_LOG_DIR = "$_BASE_LOG_DIR\container-host"
$_BASE_C_DIR = "$_BASE_LOG_DIR`-container"
$_C_LOG_DIR = "$_BASE_LOG_DIR\container"
$_ScriptStartedMsg = "`n
===== Microsoft CSS Authentication Scripts started tracing =====`n
The tracing has now started.
Once you have created the issue or reproduced the scenario, please run stop-auth.ps1 from this same directory to stop the tracing.`n"

if ($version) {
    Write-Host $_Authscriptver
    return
}

if ($accepteula) {
    ShowEULAIfNeeded "DS Authentication Scripts:" 2
    "EULA Accepted"
}
else {
    $eulaAccepted = ShowEULAIfNeeded "DS Authentication Scripts:" 0
    if ($eulaAccepted -ne "Yes") {
        "EULA Declined"
        exit
    }
    "EULA Accepted"
}


# *** Set some system specifc variables ***
$wmiOSObject = Get-WmiObject -class Win32_OperatingSystem
$osVersionString = $wmiOSObject.Version
$osBuildNumString = $wmiOSObject.BuildNumber


# *** Disclaimer ***
Write-Host "`n
***************** Microsoft CSS Authentication Scripts ****************`n
This Data collection is for Authentication, smart card and Credential provider scenarios`n
Data is collected into a subdirectory of the directory from where this script is launched, called ""Authlogs"".`n
*************************** IMPORTANT NOTICE **************************`n
The authentication script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows.
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses; PC names; and user names.`n

You can send this folder and its contents to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.`n"

Write-Host "`nPlease wait whilst the tracing starts.....`n"

# *** Check for PowerShell version ***
$PsVersion = ($PSVersionTable).PSVersion.ToString()

if ($psversiontable.psversion.Major -lt "4") {
    Write-Host
    "============= Microsoft CSS Authentication Scripts =============`n
The script requires PowerShell version 4.0 or above to run.`n
Version detected is $PsVersion`n
Stopping script`n"
    exit
}

# *** Check for elevation ***
Write-Host "`nChecking token for Elevation - please wait..."

If ((whoami /groups) -match "S-1-16-12288") {
    Write-Host "`nToken elevated"
}
Else {
    Write-Host
    "============= Microsoft CSS Authentication Scripts =============`n
The script must be run from an elevated Powershell console.
The script has detected that it is not being run from an elevated PowerShell console.`n
Please run the script from an elevated PowerShell console.`n"
    exit
}

# **WPR Check** ** Checks if WPR is installed in case OS < Win10 and 'slowlogon' switch is added**
if ($slowlogon) {

    [version]$OSVersion = (Get-CimInstance Win32_OperatingSystem).version
    if (!($OSVersion -gt [version]'10.0')) {
        try {
            Start-Process -FilePath wpr -WindowStyle Hidden -ErrorVariable WPRnotInstalled;
        }
        catch {
            if ($WPRnotInstalled) {
                Write-Host "`nWarning!" -ForegroundColor Yellow
                write-host "Windows Performance Recorder (WPR) needs to be installed before the '-slowlogon' switch can be used.`n" -ForegroundColor Yellow
                Write-host "You can download Windows Performance Recorder here: https://go.microsoft.com/fwlink/p/?LinkId=526740" -ForegroundColor Yellow
                Write-host "Exiting script.`n" -ForegroundColor Yellow
                exit;
            }
        }
    }
}

if ($containerId -ne "") {
    Write-Verbose "Collecting Container Auth Scripts"
    # Confirm that docker is in our path
    $DockerExists = (Get-Command "docker.exe" -ErrorAction SilentlyContinue) -ne $null
    if ($DockerExists) {
        Write-Verbose "Docker.exe found"
        $RunningContainers = $(docker ps -q)
        if ($containerId -in $RunningContainers) {
            Write-Verbose "$containerId found"

            $_CONTAINER_DIR = "$_BASE_C_DIR`-$containerId"
            if ((Test-Path $_CONTAINER_DIR\started.txt)) {
                Write-Host "
===== Microsoft CSS Authentication Scripts started tracing =====

We have detected that tracing has already been started.
Please run stop-auth.ps1 to stop the tracing.`n"
                exit
            }
            New-Item $_CONTAINER_DIR -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            Remove-Item $_CONTAINER_DIR\* -Recurse -ErrorAction SilentlyContinue | Out-Null

            # Confirm the running container base image
            if (Check-ContainerIsNano -ContainerId $containerId) {

                Write-Verbose "Container Image is NanoServer"
                Out-File -FilePath $_CONTAINER_DIR\container-base.txt -InputObject "Nano"

                # We need to use the wprp for the auth data collection
                if (!(Test-Path "$_CONTAINER_DIR\auth.wprp") -and !(Test-Path "$_CONTAINER_DIR\RunningProviders.txt")) {
                    Generate-WPRP -ContainerId $containerId
                }

                # Checking if the container has the tracing scripts
                if (Check-ContainsScripts -ContainerId $containerId -IsNano) {
                    Write-Host "Starting container tracing - please wait..."
                    Start-NanoTrace -ContainerId $containerId
                }
                else {
                    Write-Host "Container: $containerId missing tracing script!" -ForegroundColor Yellow
                    Write-Host "Please copy the auth.wprp into the C:\authscripts directory in the container then run start-auth.ps1 -containerId $containerId again
Example:
`tdocker stop $containerId
`tdocker cp auth.wprp $containerId`:\AuthScripts
`tdocker start $containerId
`t.\start-auth.ps1 -containerId $containerId" -ForegroundColor Yellow
                    return
                }

            }
            else {
                Write-Verbose "Container Image is Standard"
                Out-File -FilePath $_CONTAINER_DIR\container-base.txt -InputObject "Standard"

                if (Check-ContainsScripts -ContainerId $containerId) {
                    Write-Host "Starting container tracing - please wait..."
                    Invoke-Container -ContainerId $ContainerId -Record -Command ".\start-auth.ps1 -accepteula"
                }
                else {
                    Write-Host "Please copy start-auth.ps1 and stop-auth.ps1 into the C:\authscripts directory in the container and run start-auth.ps1 -containerId $containerId again
Example:
`tdocker stop $containerId
`tdocker cp start-auth.ps1 $containerId`:\AuthScripts
`tdocker cp stop-auth.ps1 $containerId`:\AuthScripts
`tdocker start $containerId
`t.\start-auth.ps1 -containerId $containerId" -ForegroundColor Yellow
                    return
                }
            }
        }
        else {
            Write-Host "Failed to find $containerId"
            return
        }
    }
    else {
        Write-Host "Unable to find docker.exe in system path."
        return
    }

    Check-GMSA -ContainerId $containerId

    # Start Container Logging
    if ((Get-HotFix | Where-Object { $_.HotFixID -gt "KB5000854" -and $_.Description -eq "Update" } | Measure-object).Count -ne 0) {
        pktmon start --capture -f $_CONTAINER_DIR\Pktmon.etl -s 4096 2>&1 | Out-Null
    }
    else {
        netsh trace start capture=yes persistent=yes report=disabled maxsize=4096 scenario=NetConnection traceFile=$_CONTAINER_DIR\netmon.etl | Out-Null
    }

    Add-Content -Path $_CONTAINER_DIR\script-info.txt -Value ("Data collection started on: " + (Get-Date -Format "yyyy/MM/dd HH:mm:ss"))
    Add-Content -Path $_CONTAINER_DIR\started.txt -Value "Started"

    Write-Host "`n
===== Microsoft CSS Authentication Scripts started tracing =====`n
The tracing has now started.
Once you have created the issue or reproduced the scenario, please run .\stop-auth.ps1 -containerId $containerId from this same directory to stop the tracing.`n
Once the tracing and data collection has completed, the script will save the data in a subdirectory from where this script is launched called `"$_CONTAINER_DIR`".
The `"$_CONTAINER_DIR`" directory and subdirectories will contain data collected by the Microsoft CSS Authentication scripts.
This folder and its contents are not automatically sent to Microsoft.
You can send this folder and its contents to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have."
    return
}

# *** Check if script is running ***
If ((Test-Path $_BASE_LOG_DIR\started.txt) -eq "True") {
    Write-Host "
===== Microsoft CSS Authentication Scripts started tracing =====

We have detected that tracing has already been started.
Please run stop-auth.ps1 to stop the tracing.`n"
    exit
}

if ("" -ne $watchProcess) {
    # Try by name
    $_WatchProcess = Get-Process $watchProcess -ErrorAction "SilentlyContinue"
    if ($null -eq $_WatchProcess) {
        # Try as process id
        try {
            $_WatchProcess = Get-Process -Id $watchProcess -ErrorAction "SilentlyContinue"
        }
        catch {
            # NOP
        }
    }
    if ($null -eq $_WatchProcess) {
        Write-Error "Failed to find Process $watchProcess"
        return
    }
    if ($_WatchProcess.Count -gt 1) {
        Write-Error "Multiple instances of $watchProcess found. Please use Process Id instead"
        return
    }
}

$_PRETRACE_LOG_DIR = $_LOG_DIR + "\PreTraceLogs"

If ((Test-Path $_PRETRACE_LOG_DIR) -eq "True") { Remove-Item -Path $_PRETRACE_LOG_DIR -Force -Recurse }
If ((Test-Path $_LOG_DIR) -eq "True") { Remove-Item -Path $_LOG_DIR -Force -Recurse }

New-Item -name $_LOG_DIR -ItemType Directory | Out-Null
New-Item -name $_PRETRACE_LOG_DIR -ItemType Directory | Out-Null

$ProductType = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType
Add-Content -Path $_LOG_DIR\script-info.txt -Value "Microsoft CSS Authentication Script version $_Authscriptver"

Add-Content -Path $_LOG_DIR\started.txt -Value "Started"

# **slowlogon** ** Generate customer WPRP**
if ($slowlogon) {
    function Generate-slowlogonWPRP {

        $sbsl_wprp_file = @"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0"  Author="Auth Scripts Team">
  <Profiles>
    <SystemCollector Id="SBSL_System_Collector" Name="SBSL System Collector">
      <BufferSize Value="1024" />
      <Buffers Value="3276" />
    </SystemCollector>
    <EventCollector Id="SBSL_Event_Collector" Name="SBSL Event Collector">
      <BufferSize Value="1024" />
      <Buffers Value="655" />
    </EventCollector>
    <SystemProvider Id="SBSL_Collector_Provider">
      <Keywords>
        <Keyword Value="CpuConfig" />
        <Keyword Value="CSwitch" />
        <Keyword Value="DiskIO" />
        <Keyword Value="DPC" />
        <Keyword Value="Handle" />
        <Keyword Value="HardFaults" />
        <Keyword Value="Interrupt" />
        <Keyword Value="Loader" />
        <Keyword Value="MemoryInfo" />
        <Keyword Value="MemoryInfoWS" />
        <Keyword Value="ProcessCounter" />
        <Keyword Value="Power" />
        <Keyword Value="ProcessThread" />
        <Keyword Value="ReadyThread" />
        <Keyword Value="SampledProfile" />
        <Keyword Value="ThreadPriority" />
		<Keyword Value="VirtualAllocation" />
		<Keyword Value="WDFDPC" />
        <Keyword Value="WDFInterrupt" />
      </Keywords>
      <Stacks>
        <Stack Value="CSwitch" />
        <Stack Value="HandleCreate" />
        <Stack Value="HandleClose" />
        <Stack Value="HandleDuplicate" />
        <Stack Value="SampledProfile" />
		<Stack Value="ThreadCreate" />
        <Stack Value="ReadyThread" />
      </Stacks>
    </SystemProvider>
    <EventProvider Id="Microsoft-Windows-Winlogon" Name="dbe9b383-7cf3-4331-91cc-a3cb16a3b538"/>
	<EventProvider Id="Microsoft-Windows-GroupPolicy" Name="aea1b4fa-97d1-45f2-a64c-4d69fffd92c9"/>
	<EventProvider Id="Microsoft-Windows-Wininit" Name="206f6dea-d3c5-4d10-bc72-989f03c8b84b111111"/>
	<EventProvider Id="Microsoft-Windows-User_Profiles_Service" Name="89b1e9f0-5aff-44a6-9b44-0a07a7ce5845"/>
	<EventProvider Id="Microsoft-Windows-User_Profiles_General" Name="db00dfb6-29f9-4a9c-9b3b-1f4f9e7d9770"/>
	<EventProvider Id="Microsoft-Windows-Folder_Redirection" Name="7d7b0c39-93f6-4100-bd96-4dda859652c5"/>
	<EventProvider Id="Microsoft-Windows-Security-Netlogon" Name="e5ba83f6-07d0-46b1-8bc7-7e669a1d31dca"/>
	<EventProvider Id="Microsoft-Windows-Shell-Core" Name="30336ed4-e327-447c-9de0-51b652c86108"/>
    <Profile Id="SBSL.Verbose.Memory" Name="SBSL" Description="RunningProfile:SBSL.Verbose.Memory" LoggingMode="Memory" DetailLevel="Verbose"> <!-- Default profile. Used when the '-slowlogon' switch is used  -->
      <ProblemCategories>
        <ProblemCategory Value="First level triage" />
      </ProblemCategories>
      <Collectors>
        <SystemCollectorId Value="SBSL_System_Collector">
          <SystemProviderId Value="SBSL_Collector_Provider" />
        </SystemCollectorId>
        <EventCollectorId Value="SBSL_Event_Collector">
          <EventProviders>
            <EventProviderId Value="Microsoft-Windows-Winlogon"/>
			<EventProviderId Value="Microsoft-Windows-GroupPolicy"/>
			<EventProviderId Value="Microsoft-Windows-Wininit"/>
			<EventProviderId Value="Microsoft-Windows-User_Profiles_Service"/>
			<EventProviderId Value="Microsoft-Windows-User_Profiles_General"/>
			<EventProviderId Value="Microsoft-Windows-Folder_Redirection"/>
			<EventProviderId Value="Microsoft-Windows-Shell-Core"/>
			<EventProviderId Value="Microsoft-Windows-Security-Netlogon"/>
          </EventProviders>
        </EventCollectorId>
      </Collectors>
      <TraceMergeProperties>
        <TraceMergeProperty Id="BaseVerboseTraceMergeProperties" Name="BaseTraceMergeProperties">
          <DeletePreMergedTraceFiles Value="true" />
          <FileCompression Value="false" />
          <InjectOnly Value="false" />
          <CustomEvents>
            <CustomEvent Value="ImageId" />
            <CustomEvent Value="BuildInfo" />
            <CustomEvent Value="VolumeMapping" />
            <CustomEvent Value="EventMetadata" />
            <CustomEvent Value="PerfTrackMetadata" />
            <CustomEvent Value="WinSAT" />
            <CustomEvent Value="NetworkInterface" />
          </CustomEvents>
        </TraceMergeProperty>
      </TraceMergeProperties>
    </Profile>
        <Profile Id="SBSL.Light.Memory" Name="SBSL" Description="RunningProfile:SBSL.Light.Memory" Base="SBSL.Verbose.Memory" LoggingMode="Memory" DetailLevel="Light" /> <!-- Light memory profile. Not currently in use. Reserved for later usage -->
		<Profile Id="SBSL.Verbose.File" Name="SBSL" Description="RunningProfile:SBSL.Verbose.File" Base="SBSL.Verbose.Memory" LoggingMode="File" DetailLevel="Verbose" /> <!-- Default -File mode profile. Used when the '-slowlogon' switch is added -->
		<Profile Id="SBSL.Light.File" Name="SBSL" Description="RunningProfile:SBSL.Light.File" Base="SBSL.Verbose.Memory" LoggingMode="File" DetailLevel="Light" /> <!-- Light file profile. Not currently in use. Reserved for later usage -->
  </Profiles>
</WindowsPerformanceRecorder>

"@
        Out-file -FilePath "$_LOG_DIR\sbsl.wprp" -InputObject $sbsl_wprp_file -Encoding ascii
    }
}

# **slowlogon** ** Generate Slow Logon WPRP file in case the 'slowlogon' switch is added**
if ($slowlogon) { Generate-slowlogonWPRP }

# *** QUERY RUNNING PROVIDERS ***
Add-Content -Path $_PRETRACE_LOG_DIR\running-etl-sessions.txt -value (logman query * -ets)

# Enable Eventvwr logging
wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" $_PRETRACE_LOG_DIR\Capi2_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe clear-log "Microsoft-Windows-CAPI2/Operational" 2>&1 | Out-Null
wevtutil.exe sl "Microsoft-Windows-CAPI2/Operational" /ms:102400000 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
wevtutil.exe clear-log "Microsoft-Windows-Kerberos/Operational" 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-WebAuth/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-WebAuthN/Operational" $_PRETRACE_LOG_DIR\WebAuthn_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-CertPoleEng/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
wevtutil.exe clear-log "Microsoft-Windows-CertPoleEng/Operational" 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:false | Out-Null
wevtutil.exe export-log "Microsoft-Windows-IdCtrls/Operational" $_PRETRACE_LOG_DIR\Idctrls_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-User Control Panel/Operational" $_PRETRACE_LOG_DIR\UserControlPanel_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUser-Client" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Biometrics/Operational" $_PRETRACE_LOG_DIR\WinBio_oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-LiveId/Operational" $_PRETRACE_LOG_DIR\LiveId_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-AAD/Operational" $_PRETRACE_LOG_DIR\Aad_oper.evtx /ow:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-AAD/Operational"  /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Admin" $_PRETRACE_LOG_DIR\UsrDeviceReg_Adm.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-HelloForBusiness/Operational" $_PRETRACE_LOG_DIR\Hfb_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Crypto-DPAPI/Operational" $_PRETRACE_LOG_DIR\DPAPI_Oper.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null


# *** ENABLE LOGGING VIA REGISTRY ***

# NEGOEXT
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f 2>&1 | Out-Null

# PKU2U
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f 2>&1 | Out-Null

# LSA
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /t REG_DWORD /d 0xC43EFF /f 2>&1 | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /t REG_DWORD /d 1 /f 2>&1 | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /t REG_DWORD /d 0xF /f 2>&1 | Out-Null

# LSP Logging
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgInfoLevel /t REG_DWORD /d 0x41C20800 /f 2>&1 | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgTraceOptions /t REG_DWORD /d 0x1 /f 2>&1 | Out-Null

# Kerberos Logging to SYSTEM event log in case this is a client
if ($ProductType -eq "WinNT") {
    reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters /v LogLevel /t REG_DWORD /d 1 /f 2>&1 | Out-Null
}

# *** START ETL PROVIDER GROUPS ***

# Start Logman NGC
$NGCSingleTraceName = "NGC"
logman start $NGCSingleTraceName -o $_LOG_DIR\NGC.etl -ets

ForEach ($NGCProvider in $NGC) {
    # Update Logman NGC
    $NGCParams = $NGCProvider.Split('!')
    $NGCSingleTraceGUID = $NGCParams[0]
    $NGCSingleTraceFlags = $NGCParams[1]

    logman update trace $NGCSingleTraceName -p `"$NGCSingleTraceGUID`" $NGCSingleTraceFlags 0xff -ets | Out-Null
}

# Start Logman Biometric
$BiometricSingleTraceName = "Biometric"
logman create trace $BiometricSingleTraceName -o $_LOG_DIR\Biometric.etl -ets

ForEach ($BiometricProvider in $Biometric) {
    # Update Logman Biometric
    $BiometricParams = $BiometricProvider.Split('!')
    $BiometricSingleTraceGUID = $BiometricParams[0]
    $BiometricSingleTraceFlags = $BiometricParams[1]

    logman update trace $BiometricSingleTraceName -p `"$BiometricSingleTraceGUID`" $BiometricSingleTraceFlags 0xff -ft 1:00 -rt -ets | Out-Null
}

# Start Logman LSA
$LSASingleTraceName = "LSA"
logman create trace $LSASingleTraceName -o $_LOG_DIR\LSA.etl -ets

ForEach ($LSAProvider in $LSA) {
    # Update Logman LSA
    $LSAParams = $LSAProvider.Split('!')
    $LSASingleTraceGUID = $LSAParams[0]
    $LSASingleTraceFlags = $LSAParams[1]

    logman update trace $LSASingleTraceName -p `"$LSASingleTraceGUID`" $LSASingleTraceFlags 0xff -ets | Out-Null
}

# Start Logman Ntlm_CredSSP
$Ntlm_CredSSPSingleTraceName = "Ntlm_CredSSP"
logman create trace $Ntlm_CredSSPSingleTraceName -o $_LOG_DIR\Ntlm_CredSSP.etl -ets

ForEach ($Ntlm_CredSSPProvider in $Ntlm_CredSSP) {
    # Update Logman Ntlm_CredSSP
    $Ntlm_CredSSPParams = $Ntlm_CredSSPProvider.Split('!')
    $Ntlm_CredSSPSingleTraceGUID = $Ntlm_CredSSPParams[0]
    $Ntlm_CredSSPSingleTraceFlags = $Ntlm_CredSSPParams[1]

    logman update trace $Ntlm_CredSSPSingleTraceName -p `"$Ntlm_CredSSPSingleTraceGUID`" $Ntlm_CredSSPSingleTraceFlags 0xff -ets | Out-Null
}

# Start Logman Kerberos
$KerberosSingleTraceName = "Kerberos"
logman start $KerberosSingleTraceName -o $_LOG_DIR\Kerberos.etl -ets

ForEach ($KerberosProvider in $Kerberos) {
    # Update Logman Kerberos
    $KerberosParams = $KerberosProvider.Split('!')
    $KerberosSingleTraceGUID = $KerberosParams[0]
    $KerberosSingleTraceFlags = $KerberosParams[1]

    logman update trace $KerberosSingleTraceName -p `"$KerberosSingleTraceGUID`" $KerberosSingleTraceFlags 0xff -ets | Out-Null
}

# Start Logman KDC
if ($ProductType -eq "LanmanNT") {
    $KDCSingleTraceName = "KDC"
    logman start $KDCSingleTraceName -o $_LOG_DIR\KDC.etl -ets

    ForEach ($KDCProvider in $KDC) {
        # Update Logman KDC
        $KDCParams = $KDCProvider.Split('!')
        $KDCSingleTraceGUID = $KDCParams[0]
        $KDCSingleTraceFlags = $KDCParams[1]

        logman update trace $KDCSingleTraceName -p `"$KDCSingleTraceGUID`" $KDCSingleTraceFlags 0xff -ets | Out-Null
    }
}

# Start Logman SSL
$SSLSingleTraceName = "SSL"
logman start $SSLSingleTraceName -o $_LOG_DIR\SSL.etl -ets

ForEach ($SSLProvider in $SSL) {
    # Update Logman SSL
    $SSLParams = $SSLProvider.Split('!')
    $SSLSingleTraceGUID = $SSLParams[0]
    $SSLSingleTraceFlags = $SSLParams[1]

    logman update trace $SSLSingleTraceName -p `"$SSLSingleTraceGUID`" $SSLSingleTraceFlags 0xff -ets | Out-Null
}

# Start Logman WebAuth
$WebAuthSingleTraceName = "WebAuth"
logman start $WebAuthSingleTraceName -o $_LOG_DIR\WebAuth.etl -ets

ForEach ($WebAuthProvider in $WebAuth) {
    # Update Logman WebAuth
    $WebAuthParams = $WebAuthProvider.Split('!')
    $WebAuthSingleTraceGUID = $WebAuthParams[0]
    $WebAuthSingleTraceFlags = $WebAuthParams[1]

    logman update trace $WebAuthSingleTraceName -p `"$WebAuthSingleTraceGUID`" $WebAuthSingleTraceFlags 0xff -ets | Out-Null
}

# Start Logman Smartcard
$SmartcardSingleTraceName = "Smartcard"
logman start $SmartcardSingleTraceName -o $_LOG_DIR\Smartcard.etl -ets

ForEach ($SmartcardProvider in $Smartcard) {
    # Update Logman Smartcard
    $SmartcardParams = $SmartcardProvider.Split('!')
    $SmartcardSingleTraceGUID = $SmartcardParams[0]
    $SmartcardSingleTraceFlags = $SmartcardParams[1]

    logman update trace $SmartcardSingleTraceName -p `"$SmartcardSingleTraceGUID`" $SmartcardSingleTraceFlags 0xff -ets | Out-Null
}

# Start Logman CredprovAuthui
$CredprovAuthuiSingleTraceName = "CredprovAuthui"
logman start $CredprovAuthuiSingleTraceName -o $_LOG_DIR\CredprovAuthui.etl -ets

ForEach ($CredprovAuthuiProvider in $CredprovAuthui) {
    # Update Logman CredprovAuthui
    $CredprovAuthuiParams = $CredprovAuthuiProvider.Split('!')
    $CredprovAuthuiSingleTraceGUID = $CredprovAuthuiParams[0]
    $CredprovAuthuiSingleTraceFlags = $CredprovAuthuiParams[1]

    logman update trace $CredprovAuthuiSingleTraceName -p `"$CredprovAuthuiSingleTraceGUID`" $CredprovAuthuiSingleTraceFlags 0xff -ets | Out-Null
}

# Nonet check
if ($nonet.IsPresent -ne "False") {
    # Start Net Trace
    switch -regex ($osVersionString) {
        # Win7 has different args syntax.
        '^6\.1' { netsh trace start persistent=yes traceFile=$_LOG_DIR\Netmon.etl capture=yes report=no maxsize=1024 | Out-Null }

        default {
            if (($ProductType -eq "WinNT") -and ($v)) {
                netsh trace start scenario=internetclient persistent=yes traceFile=$_LOG_DIR\Netmon.etl capture=yes report=disabled maxsize=1024 | Out-Null
            }
            else {
                netsh trace start persistent=yes traceFile=$_LOG_DIR\Netmon.etl capture=yes report=disabled maxsize=1024 | Out-Null
            }
        }
    }
}

# Start Logman CryptNcryptDpapi
if ($ProductType -eq "WinNT") {
    $CryptNcryptDpapiSingleTraceName = "CryptNcryptDpapi"
    logman start $CryptNcryptDpapiSingleTraceName -o $_LOG_DIR\CryptNcryptDpapi.etl -ets

    ForEach ($CryptNcryptDpapiProvider in $CryptNcryptDpapi) {
        # Update Logman CryptNcryptDpapi
        $CryptNcryptDpapiParams = $CryptNcryptDpapiProvider.Split('!')
        $CryptNcryptDpapiSingleTraceGUID = $CryptNcryptDpapiParams[0]
        $CryptNcryptDpapiSingleTraceFlags = $CryptNcryptDpapiParams[1]

        logman update trace $CryptNcryptDpapiSingleTraceName -p `"$CryptNcryptDpapiSingleTraceGUID`" $CryptNcryptDpapiSingleTraceFlags 0xff -ets | Out-Null
    }
}

# Start Logman SAM
$SAMSingleTraceName = "SAM"
logman start $SAMSingleTraceName -o $_LOG_DIR\SAM.etl -ets

ForEach ($SAMProvider in $SAM) {
    # Update Logman SAM
    $SAMParams = $SAMProvider.Split('!')
    $SAMSingleTraceGUID = $SAMParams[0]
    $SAMSingleTraceFlags = $SAMParams[1]

    logman update trace $SAMSingleTraceName -p `"$SAMSingleTraceGUID`" $SAMSingleTraceFlags 0xff -ets | Out-Null
}



wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:false 2>&1 | Out-Null
wevtutil.exe export-log "Microsoft-Windows-Containers-CCG/Admin" $_PRETRACE_LOG_DIR\Containers-CCG_Admin.evtx /overwrite:true 2>&1 | Out-Null
wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null


# **AppX** **Start Appx logman on clients, or in servers (except Domain Controllers) in case the '-v' switch is added**
if (($ProductType -eq "WinNT") -or (($v) -and ($ProductType -ne "LanmanNT"))) {

    $AppxSingleTraceName = "AppX"
    logman create trace $AppxSingleTraceName -o $_LOG_DIR\AppX.etl -ets

    ForEach ($AppXProvider in $AppX) {
        # Update Logman Kerberos
        $AppXParams = $AppXProvider.Split('!')
        $AppXSingleTraceGUID = $AppXParams[0]
        $AppXSingleTraceFlags = $AppXParams[1]

        logman update trace $AppXSingleTraceName -p `"$AppXSingleTraceGUID`" $AppXSingleTraceFlags 0xff -ets | Out-Null
    }
}


# Start Kernel logger
if ($ProductType -eq "WinNT") {
    $KernelSingleTraceName = "NT Kernel Logger"
    $KernelParams = $Kernel.Split('!')
    $KernelSingleTraceGUID = $KernelParams[0]
    $KernelSingleTraceFlags = $KernelParams[1]

    logman create trace $KernelSingleTraceName -ow -o $_LOG_DIR\kernel.etl -p `"$KernelSingleTraceGUID`" $KernelSingleTraceFlags 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets | Out-Null
}


# **Netlogon logging**
nltest /dbflag:0x2EFFFFFF 2>&1 | Out-Null

# **Enabling Group Policy Logging**
New-Item -Path "$($env:windir)\debug\usermode" -ItemType Directory 2>&1 | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /f 2>&1 | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /t REG_DWORD /d 0x30002 /f 2>&1 | Out-Null


# ** Turn on debug and verbose Cert Enroll  logging **

write-host "Enabling Certificate Enrolment debug logging...`n"
write-host "Verbose Certificate Enrolment debug output may be written to this window"
write-host "It is also written to a log file which will be collected when the stop-auth.ps1 script is run.`n"

Start-Sleep -s 5

certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null

certutil -setreg ngc\Debug 1 2>&1 | Out-Null
certutil -setreg Enroll\LogLevel 5 2>&1 | Out-Null

Switch -Regex ($osVersionString) {
    '^6\.1\.7600' { 'Windows Server 2008 R2, Skipping dsregcmd...' }
    '^6\.1\.7601' { 'Windows Server 2008 R2 SP1, Skipping dsregcmd...' }
    '^6\.2\.9200' { 'Windows Server 2012, Skipping dsregcmd...' }
    '^6\.3\.9600' { 'Windows Server 2012 R2, Skipping dsregcmd...' }
    default {
        Add-Content -Path $_PRETRACE_LOG_DIR\Dsregcmddebug.txt -Value (dsregcmd /status /debug /all 2>&1) | Out-Null
        Add-Content -Path $_PRETRACE_LOG_DIR\DsRegCmdStatus.txt -Value (dsregcmd /status 2>&1) | Out-Null
    }
}

Add-Content -Path $_PRETRACE_LOG_DIR\Tasklist.txt -Value (tasklist /svc 2>&1) | Out-Null
Add-Content -Path $_PRETRACE_LOG_DIR\Services-config.txt -Value (sc.exe queryex state=all 2>&1) | Out-Null
Add-Content -Path $_PRETRACE_LOG_DIR\Services-started.txt -Value (net start 2>&1) | Out-Null

Add-Content -Path $_PRETRACE_LOG_DIR\netstat.txt -Value (netstat -ano 2>&1) | Out-Null
Add-Content -Path $_PRETRACE_LOG_DIR\Tickets.txt -Value(klist) | Out-Null
Add-Content -Path $_PRETRACE_LOG_DIR\Tickets-localsystem.txt -Value (klist -li 0x3e7) | Out-Null
Add-Content -Path $_PRETRACE_LOG_DIR\Klist-Cloud-Debug.txt -Value (klist Cloud_debug) | Out-Null
Add-Content -Path $_PRETRACE_LOG_DIR\Displaydns.txt -Value (ipconfig /displaydns 2>&1) | Out-Null


# ** Run WPR in case the 'slowlogon' switch is added. (Default File mode = sbsl.wprp!sbsl.verbose -filemode)
if ($slowlogon) {
    wpr -start $_LOG_DIR\sbsl.wprp!sbsl.verbose -filemode
}


# *** QUERY RUNNING PROVIDERS ***
Add-Content -Path $_LOG_DIR\running-etl-sessions.txt -value (logman query * -ets)

ipconfig /flushdns 2>&1 | Out-Null


if ($v.IsPresent -eq "True") {
    Add-Content -Path $_LOG_DIR\script-info.txt -Value "Arguments passed: v"
}

if ($nonet.IsPresent -eq "True") {
    Add-Content -Path $_LOG_DIR\script-info.txt -Value "Arguments passed: nonet"
}

if ($slowlogon.IsPresent -eq "True") {
    Add-Content -Path $_LOG_DIR\script-info.txt -Value "Arguments passed: slowlogon"
}

Add-Content -Path $_LOG_DIR\script-info.txt -Value ("Data collection started on: " + (Get-Date -Format "yyyy/MM/dd HH:mm:ss"))

Write-Host "`n
===== Microsoft CSS Authentication Scripts started tracing =====`n
The tracing has now started."
Write-Host "`nIMPORTANT: The auth scripts make adjustments to the Windows registry to enable certain logging. Please be sure to run stop-auth.ps1 to clean up these adjustments.`n" -ForegroundColor "Yellow"
if ($null -ne $_WatchProcess) {
    if ($_WatchProcess.Name -eq "lsass") { Write-Host "WARNING: When lsass terminates it will cause the machine to restart 60 seconds later.`n" -ForegroundColor "Yellow" }
    Write-Host "Waiting for Process $($_WatchProcess.Name) ($($_WatchProcess.Id)) to terminate"
    Write-Host "Process CTRL+C to cancel"
    Wait-Process -Id $_WatchProcess.Id
    Write-Host "$($_WatchProcess.Name) terminated with Exit Code: $($_WatchProcess.ExitCode)"
    Write-Host "Stopping authscripts"
    Start-Process "powershell" -WorkingDirectory $(Get-Location).Path -ArgumentList  ".\stop-auth.ps1" -NoNewWindow -Wait
}
else {
    Write-Host "Once you have created the issue or reproduced the scenario, please run stop-auth.ps1 from this same directory to stop the tracing.
Once the tracing and data collection has completed, the script will save the data in a subdirectory from where this script is launched called `"Authlogs`".
The `"Authlogs`" directory and subdirectories will contain data collected by the Microsoft CSS Authentication scripts.
This folder and its contents are not automatically sent to Microsoft.
You can send this folder and its contents to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.`n"
}

# SIG # Begin signature block
# MIInzgYJKoZIhvcNAQcCoIInvzCCJ7sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBjyuhK0fKfhUCF
# agPTIUBkfvY+VpftaCUNxYls4ZB36aCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIO2k
# IWjlCGQUMzqP9v2UEJxbAPNu3d6eavPvsJVHw7BkMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAcB/wMbjZwaCBLOukqI9VH9zHJ5c8svCoKm6H
# cpBqAl33226cHofRb8hnu6tavrY9iCRfs21hMqCbyfMPtB2UMFWmCyF4qLcd1h0T
# QwI3KAEFT+12EOiRJzXSkzlEggxFlALYzW8nOI1dLl/yZa3ZT7KR6+Xx2JM+eK1H
# CTwNxgYN6W+WzkYfaXgWjaIap8gXoT8Zb/ckqV0SS2hgnk6rvBQ5uTJmwMdrS40j
# dSMPUcewaOEI2X1DwbRwpjpHTjKdx2M6yBrQEcHYubFUiGCbBADzhKec11IuhblX
# R6aJTnfPYrvDzNuCb9A0K5Oqfzg+AQfmlFPXqXYp3Uaw094l1qGCFykwghclBgor
# BgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCAMPIgR1awSNXghczuAIjFrNVlvN/qPJA5C
# HbPD/uKY0gIGY/dZM6ieGBMyMDIzMDMwMzExMDU1NS4yMDdaMASAAgH0oIHYpIHV
# MIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjJBRDQtNEI5Mi1GQTAxMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAGxypBD
# 7gvwA6sAAQAAAbEwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjIwOTIwMjAyMTU5WhcNMjMxMjE0MjAyMTU5WjCB0jELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjoyQUQ0LTRCOTItRkEwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIai
# qz7V7BvH7IOMPEeDM2UwCpM8LxAUPeJ7Uvu9q0RiDBdBgshC/SDre3/YJBqGpn27
# a7XWOMviiBUfMNff51NxKFoSX62Gpq36YLRZk2hN1wigrCO656z5pVTjJp3Q8jdY
# AJX3ruJea3ccfTgxAgT3Uv/sP4w0+yZAYa2JZalV3MBgIFi3VwKFA4ClQcr+V4Sp
# Gzqz8faqabmYypuJ35Zn8G/201pAN2jDEOu7QaDC0rGyDdwSTVmXcHM46EFV6N2F
# 69nwfj2DZh74gnA1DB7NFcZn+4v1kqQWn7AzBJ+lmOxvKrURlV/u19Mw1YP+zVQy
# zKn5/4r/vuYSRj/thZr+FmZAUtTAacLzouBENuaSBuOY1k330eMp8nndSNUsUjj/
# nn7gcdFqzdQNudJb+XxmRwi9LwjA0/8PlOsKTZ8Xw6EEWPVLfNojSuWpZMTaMzz/
# wzSPp5J02kpYmkdl50lwyGRLO5X7iWINKmoXySdQmRdiGMTkvRStXKxIoEm/EJxC
# aI+k4S3+BWKWC07EV5T3UG7wbFb4LfvgbbaKM58HytAyjDnO9fEi0vrp8JFTtGhd
# twhEEkraMtGVt+CvnG0ZlH4mvpPRPuJbqE509e6CqmHwzTuUZPFMFWvJn4fPv0d3
# 2Ws9jv2YYmE/0WR1fULs+TxxpWgn1z0PAOsxSZRPAgMBAAGjggFJMIIBRTAdBgNV
# HQ4EFgQU9Jtnke8NrYSK9fFnoVE0pr0OOZMwHwYDVR0jBBgwFoAUn6cVXQBeYl2D
# 9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1l
# LVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQAD
# ggIBANjnN5JqpeVShIrQIaAQnNVOv1cDEmCkD6oQufX9NGOX28Jw/gdkGtMJyagA
# 0lVbumwQla5LPhBm5LjIUW/5aYhzSlZ7lxeDykw57wp2AqoMAJm7bXcXtJt/HyaR
# lN35hAhBV+DmGnBIRcE5C2bSFFY3asD50KUSCPmKl/0NFadPeoNqbj5ZUna8VAfM
# SDsdxeyxjs8r/9Vpqy8lgIVBqRrXtFt6n1+GFpJ+2AjPspfPO7Y+Y/ozv5dTEYum
# 5eDLDdD1thQmHkW8s0BBDbIOT3d+dWdPETkf50fM/nALkMEdvYo2gyiJrOSG0a9Z
# 2S/6mbJBUrgrkgPp2HjLkycR4Nhwl67ehAhWxJGKD2gRk88T2KKXLiRHAoYTZVpH
# bgkYLspBLJs9C77ZkuxXuvIOGaId7EJCBOVRMJygtx8FXpoSu3jWEdau0WBMXxhV
# AzEHTu7UKW3Dw+KGgW7RRlhrt589SK8lrPSvPM6PPnqEFf6PUsTVO0bOkzKnC3TO
# gui4JhlWliigtEtg1SlPMxcdMuc9uYdWSe1/2YWmr9ZrV1RuvpSSKvJLSYDlOf6a
# JrpnX7YKLMRoyKdzTkcvXw1JZfikJeGJjfRs2cT2JIbiNEGK4i5srQbVCvgCvdYV
# EVZXVW1Iz/LJLK9XbIkMMjmECJEsa07oadKcO4ed9vY6YYBGMIIHcTCCBVmgAwIB
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
# aGFsZXMgVFNTIEVTTjoyQUQ0LTRCOTItRkEwMTElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA7WSxvqQDbA7vyy69
# Tn0wP5BGxyuggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOeruoMwIhgPMjAyMzAzMDMwODE0NTlaGA8yMDIzMDMw
# NDA4MTQ1OVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA56u6gwIBADAHAgEAAgIU
# gzAHAgEAAgIRPjAKAgUA560MAwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# AIHiiLepCZw3/ajvTxSkuQ9dq8J05MyH0wIRszBtR1Pxq0SnXkl4OVH8dY/MwMaH
# xk1FhH/vl4wBLJ7eQVQ64ok5KjsMkHaBzPLpAUxiqBKyy3J+8mo+rsOHUCQ5A3k0
# ZqhB0DVjQiGe98Efi2vg2QGDGYc/N7z91Q/f3do+YXlvMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGxypBD7gvwA6sAAQAA
# AbEwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQgLg8yQKyXewRws8Y6yxMyddadOEbAtWSjIRqyIFlA
# 3NMwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCD7Q2LFFvfqeDoy9gpu35t
# 6dYerrDO0cMTlOIomzTPbDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABscqQQ+4L8AOrAAEAAAGxMCIEIDw4/O6nV0vNVngShLcR8sQ8
# ZJRlz/6RVdTxz2Y9iL1KMA0GCSqGSIb3DQEBCwUABIICABIIyFP8rMQWrmgSAF0U
# MM7tIKOYwZPUOg7/6SvcwYk4UmE89X43/jHXWMxgZz7tImri4MaQnmVRrwDHqXll
# oWDMo6ffvGaHP0Q+uG+FpWE67FYT5bSTO2ovItYfSk1FQZJ3pxJVCOrU64Cpdpbp
# Kuea3BZdr8WQx73wfMHg9yVhyBUZ5IxA7rk++lFghZKdXSD129iOg+v38+Mg1GOP
# qFQTDwTW7hLiw97dD2871K2bgKwIQKtu8h0ETFGaSiA96umxoE+rCqoTTEzRtUwA
# PF6Em+sSqohK2K2IPTq7QldIcsTGkrKFAGAqPTerzEvry56ZanBly40tjnhwCtNw
# kYG7Ebv7UhL7jm7P9gK44L8DUFSwUCj1iO9ihLm7hA7dwoKzW7J1Ig93rpqZicBt
# HwiVxUYioyzRUJXya4vEVVrqYEAkgNFParNuEs34+qpB186xAAcuAi1U1mfkJXJU
# KGoaj5Opb3wZhUUy2UbC9w10+Bgu5i7Z4Gidk/hQXARJvnBPEINXmkBk8emN1131
# K1MdsffUmeGZmf/YaPSy5vU59BUk9mzwvauEWiHDsZa5DWGUIl2IpYfkXG4jSFAN
# AU7AN0ajt4dcLcYyDMTq4ZkSKvAFGZqKVnfIUFCufCU2nJOJcvxhi/r3Rx8czUIm
# YEOATkUl1Z3rU4Tg/9hXfGIJ
# SIG # End signature block
