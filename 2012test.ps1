#Initializing Script Variables
"*******************************************************************************"
"*                                                                             *"
"*                Windows Server 2012 R2 STIG Check Tool v0.1                  *"
"*                Covers Rules Not Included in SCAP Benchmarks                 *"
"*                                                                             *"
"*                          For STIG Version 2 Release 9                       *"
"*                                   10/5/2017                                 *"
"*                                                                             *"
"*******************************************************************************"
"* Point of Contact:                                                           *"
"*    Aaron Phillips                                                           *"
"*    Phone: (256) 509-6410                                                    *"
"*    E-Mail: aaron.r.phillips14.ctr@mail.mil                                  *"
"*******************************************************************************"

"Operating system              Version number
----------------------------  --------------
Windows 10                      10.0 Interprise = 6.3
Windows Server 2016             10.0
Windows 8.1                     6.3
Windows Server 2012 R2          6.3
Windows 8                       6.2
Windows Server 2012             6.2
Windows 7                       6.1
Windows Server 2008 R2          6.1
Windows Server 2008             6.0
Windows Vista                   6.0
Windows Server 2003 R2          5.2
Windows Server 2003             5.2
Windows XP 64-Bit Edition       5.2
Windows XP                      5.1
Windows 2000                    5.0
Windows ME                      4.9
Windows 98                      4.10"
param (
    [string]$ServerNameToCheck = ""
)
$m = Read-Host -Prompt "1 to fix : 0 to check"


If($m -eq 0)
{

#region SCRIPT SET UP
#-------------------------------------------------------------------------------------
$STIGName = "Windows Server 2012 R2"

#If no target was provided, target the local machine
$isLocalScan = $false
if($ServerNameToCheck -eq "")
{
    $ServerNameToCheck = $env:computername
}

#If the user provided no target or the user provided the name of the local machine, flag this as a local scan
if($ServerNameToCheck -eq $env:computername)
{
	$isLocalScan = $true
}

#File Timestamp
$ts = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"

#Display Timestamp
$startTime = Get-Date
$dts = ($startTime.ToLongDateString() + " " + $startTime.ToLongTimeString())

#Output files
$outFileName = "$STIGName Partial STIG Results - $ServerNameToCheck - $ts.xml"
$outFileFindingDetail = "$STIGName Partial STIG Results - $ServerNameToCheck - $ts - Finding Details.txt"

#Logging Function
function SendToLog
{
    param([string]$message)
	ac $outFileFindingDetail ($script:logFileIndent + $message)
}

function SendToLogAndOutput
{
    param([string]$message)
	Write-Host $message
	ac $outFileFindingDetail ($script:logFileIndent + $message)
}

#Variable for indenting messages in the log file
#Indents make the log file easier to read.
$logFileIndent = ""

#Begin Logging
SendToLogAndOutput ("Beginning $STIGName Partial STIG Check on $ServerNameToCheck")
SendToLogAndOutput ("  Date/Time: $dts")

$connectionStatus = Test-Connection $ServerNameToCheck -Quiet
if($connectionStatus -ne $True)
{
    SendToLogAndOutput ("Unable to connect to server $ServerNameToCheck.  Aborting STIG checks")
    exit
}

#Registry Object
$regHKLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$ServerNameToCheck)

#External Dependencies
$psExecPath = "E:\ServerScanning\Automated Check Tools\Windows Server 2012 R2\psexec.exe"

#Script variable for storing the rule that we're currently working on
 $ruleId = $null 
 
#Import Required Types
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

#-------------------------------------------------------------------------------------
#endregion

#region FUNCTIONS
#-------------------------------------------------------------------------------------
function WriteResultFileHeader
{
    # Gather Computer Information
    [array]$NICs = (GWMI -class Win32_NetworkAdapterConfiguration -cn $ServerNameToCheck) | Where {$_.IPAddress}
    $ComputerName = $NICs[0].DNSHostName
    $IPV4 = $NICs[0].IPAddress -join ',' 
    $MacAddr = $NICs[0].MACAddress
    
    $CompInfo = GWMI -class Win32_ComputerSystem -cn $ServerNameToCheck
    $DN = $CompInfo.Domain
    
    # Write File Header
    ac $outFileName "<cdf:Benchmark resolved=""1"" id=""Windows_2012_MS_STIG"" xsi:schemaLocation=""http://checklists.nist.gov/xccdf/1.1 http://nvd.nist.gov/schema/xccdf-1.1.4.xsd http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.1.xsd"" xmlns:cdf=""http://checklists.nist.gov/xccdf/1.1"" xmlns:cpe=""http://cpe.mitre.org/dictionary/2.0"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#"" xmlns:dc=""http://purl.org/dc/elements/1.1/"" xmlns:xhtml=""http://www.w3.org/1999/xhtml"">`n"
	ac $outFileName " <cdf:TestResult>`n"
	ac $outFileName "  <cdf:profile idref=""MAC-2_Sensitive""></cdf:profile>`n"
	ac $outFileName ("  <cdf:target>" + $ComputerName + "</cdf:target>`n")
	ac $outFileName "  <cdf:target-facts>`n"
	ac $outFileName ("   <cdf:fact name=""urn:scap:fact:asset:identifier:host_name"">" + ($ComputerName -as [string]) + "</cdf:fact>`n")
	ac $outFileName ("   <cdf:fact name=""urn:scap:fact:asset:identifier:fqdn"">" + $ComputerName.ToLower() + "." + $DN + "</cdf:fact>`n")
	ac $outFileName ("   <cdf:fact name=""urn:scap:fact:asset:identifier:ipv4"">" + $IPV4 + "</cdf:fact>`n")
	ac $outFileName ("   <cdf:fact name=""urn:scap:fact:asset:identifier:mac"">" + $MacAddr + "</cdf:fact>`n")
	ac $outFileName "  </cdf:target-facts>`n"
	ac $outFileName "`n"
}

function WriteResultFileFooter
{
    # Write File Footer
	ac $outFileName " </cdf:TestResult>`n"
    ac $outFileName "</cdf:Benchmark>"
}

function RecordFindingStatus
{
    param([string]$ruleId, [string]$status)
	$sText = ""
	
	if($status -eq "pass")
    {
		$sText = "Not a Finding"
		ac $outFileName ("  <cdf:rule-result idref=""" + $ruleId + """><cdf:result>pass</cdf:result></cdf:rule-result>`n")
    }
	elseif($status -eq "fail")
    {
		$sText = "Open"
		ac $outFileName ("  <cdf:rule-result idref=""" + $ruleId + """><cdf:result>fail</cdf:result></cdf:rule-result>`n")
    }
	elseif($status -eq "notapplicable")
    {
		$sText = "Not Applicable"
		ac $outFileName ("  <cdf:rule-result idref=""" + $ruleId + """><cdf:result>notapplicable</cdf:result></cdf:rule-result>`n")
    }
	elseif($status -eq "manual")
	{
		$sText = "Manual Review Required"
	}
	else
    {
		$sText = "Invalid Status"
    }

	SendToLogAndOutput ("$ruleId : $sText")
}

function GetRegistryKeyValue
{
    param([string]$regKeyPath,[string]$regValue)
    $actualValue = $null
    Try
    { 
        $rKey = $regHKLM.OpenSubKey($regKeyPath)
		if($rKey -ne $null)
		{
			$actualValue = $rKey.GetValue($regValue)
		}
		else
		{
			$actualValue  = $null
		}
        SendToLog ("Opened Registry Path: " + $regKeyPath + ", Key Name: " + $regValue + ",  Found Value: " + $actualValue)
    }
    Catch
    {
        SendToLog "An error occurred retrieving a registry key!"
        SendToLog ("Registry Path: " + $regKeyPath + ", Key Name: " + $regValue + ",  Found Value: " + $actualValue)
        SendToLog $error[0]
        $actualValue = $null
    }
    
    return $actualValue
}

function CheckRegistryKeyValue
{
    param([string]$regKeyPath,[string]$regValue, $expectedValue, [string]$ruleId)
    $actualValue = ""
	BeginCheck $ruleId
    Try
    { 
		
        $rKey = $regHKLM.OpenSubKey($regKeyPath)
        $actualValue = $rKey.GetValue($regValue)
        
        
        if($actualValue -eq $expectedValue)
        {
            RecordFindingStatus $ruleId "pass"
        }
        else
        {
			SendToLog ("Opened Registry Path: " + $regKeyPath + ", Key Name: " + $regValue + ",  Found Value: " + $actualValue + ", Expected Value: " + $expectedValue)
            RecordFindingStatus $ruleId "fail"
        }
    }
    Catch
    {
        SendToLog "An error occurred checking a registry key!"
        SendToLog ("Registry Path: " + $regKeyPath + ", Key Name: " + $regValue + ",  Found Value: " + $actualValue + ", Expected Value: " + $expectedValue)
        SendToLog $error[0]
    }
	EndCheck
}

function CheckRegistryKeyValueGreaterThan
{
    param([string]$regKeyPath,[string]$regValue, $boundaryValue, [string]$ruleId)
    $actualValue = ""
    Try
    { 
        $rKey = $regHKLM.OpenSubKey($regKeyPath)
        $actualValue = $rKey.GetValue($regValue)
        SendToLog ("Opened Registry Path: " + $regKeyPath + ", Key Name: " + $regValue + ",  Found Value: " + $actualValue + ", Boundary Value: " + $boundaryValue)
        
        if($actualValue -gt $boundaryValue)
        {
            RecordFindingStatus $ruleId "pass"
        }
        else
        {
            RecordFindingStatus $ruleId "fail"
        }
    }
    Catch
    {
        SendToLog "An error occurred checking a registry key!"
        SendToLog ("Registry Path: " + $regKeyPath + ", Key Name: " + $regValue + ",  Found Value: " + $actualValue + ", Boundary Value: " + $boundaryValue)
        SendToLog $error[0]
    }
}

function CheckProhibitedWindowsServiceStatus
{
    param([string]$serviceDisplayName, [string]$ruleId)
    
    $ServiceState = (Get-Service -ComputerName $ServerNameToCheck | ?{$_.DisplayName -like $serviceDisplayName}).Status

    if($ServiceState -eq "Running")
    {
        RecordFindingStatus $ruleId  "fail"
    }
    else
    {
        RecordFindingStatus $ruleId  "pass"
    }
}

function GetRegistryValueUserCheck
{
  param([Microsoft.Win32.RegistryKey]$baseRegistryKey, [string]$path, [string]$value)
  
  $k = $baseRegistryKey.OpenSubKey($path)
  $v = $null
  if($k -ne $null)
  {
    $v = $k.GetValue($value)
    $k.Close()
  }
  
  return $v
}

function CreateUserHiveResultObject
{
	param([Microsoft.Win32.RegistryKey]$baseRegistryKey, [string]$registryPath, [string]$registryKey, $expectedValue, [scriptblock]$condition)
	
	$object = New-Object –TypeName PSObject
	$object | Add-Member –MemberType NoteProperty –Name RegistryPath –Value $registryPath
	$object | Add-Member –MemberType NoteProperty –Name RegistryKey –Value $registryKey
	$object | Add-Member –MemberType NoteProperty –Name ExpectedValue –Value $expectedValue
	$object | Add-Member –MemberType NoteProperty –Name FoundValue –Value $null
	$object | Add-Member –MemberType NoteProperty –Name RuleResult –Value $null
	
	$object.FoundValue = (GetRegistryValueUserCheck $baseRegistryKey $registryPath $registryKey)
	
	$object | Add-Member -MemberType ScriptMethod -Name "Evaluate" -Value $condition
	$object.RuleResult = $object.Evaluate()
	
	#If for some reason the scriptblock did not return a boolean value, default to false (failed rule).
	if(-Not ($object.RuleResult -is [bool]))
	{
		$object.RuleResult = $false
	}
	
	return $object
}

function PerformUserHiveChecks
{
    param([Microsoft.Win32.RegistryKey]$baseRegistryKey, $ListOfFindings)
	
	$sbEquals = {$this.FoundValue -eq $this.ExpectedValue}
    
    $f = @{}
	$f.Add("SV-53145r1_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Policies\Microsoft\Assistance\Client\1.0" "NoExplicitFeedback" 1 $sbEquals))
	$f.Add("SV-53144r1_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Policies\Microsoft\Assistance\Client\1.0" "NoImplicitFeedback" 1 $sbEquals))
    $f.Add("SV-53140r2_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoInPlaceSharing" 1 $sbEquals))
	$f.Add("SV-53006r1_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "ScanWithAntiVirus" 3 $sbEquals))
	$f.Add("SV-53004r1_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "HideZoneInfoOnProperties" 1 $sbEquals))
	$f.Add("SV-53002r1_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" 2 $sbEquals))
	$f.Add("SV-52921r1_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Policies\Microsoft\WindowsMediaPlayer" "PreventCodecDownload" 1 $sbEquals))
	
	$f.Add("SV-51758r2_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveActive" 1 $sbEquals))
	#$f.Add("SV-51759r1_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Policies\Microsoft\Windows\Control Panel\Desktop" "SCRNSAVE.EXE" "scrnsave.scr" $sbEquals))
	$f.Add("SV-51760r1_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaverIsSecure" 1 $sbEquals))
	
	#$f.Add("SV-51761r1_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Microsoft\Windows\CurrentVersion\Policies\System" "NoDispScrSavPage" 1 $sbEquals))
	$f.Add("SV-51762r1_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification" 1 $sbEquals))
	$f.Add("SV-51763r1_rule", (CreateUserHiveResultObject $baseRegistryKey "Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoToastApplicationNotificationOnLockScreen" 1 $sbEquals))
   
    $e = $f.GetEnumerator()
    while($e.MoveNext())
    {
      if(-not $e.Value.RuleResult)
      {
        SendToLog($e.Key + ": FAIL")
		SendToLog("    " + $e.Value.RegistryPath + "\" + $e.Value.RegistryKey + "  Expected Value:  " + $e.Value.ExpectedValue + "  Found Value:  " + $e.Value.FoundValue)
      }
      $ListOfFindings[$e.Key] = $ListOfFindings[$e.Key] -and $e.Value.RuleResult
    }
    
    return $ListOfFindings
}

function BeginCheck
{
	param([string]$stigRuleId)
	$script:ruleId = $stigRuleId
	SendToLog ("Beginning check of rule $stigRuleId...")
	$script:logFileIndent = "    "
}

function EndCheck
{
	$script:ruleId = $null
	$script:logFileIndent = ""
	SendToLog ("")
}

function ParseRemoteFilePath
{
	param([string]$path)
	if($path -match "^([A-Za-z]):\\")
	{
		$driveLetter = $matches[1]
		$rtPath = $path -replace "^([A-Za-z]):\\", "\\$ServerNameToCheck\$driveLetter`$\"
	}
	else 
	{
		$rtPath = $path -replace "%systemroot%", $windowsPath
	}
	return $rtPath
}
#-------------------------------------------------------------------------------------
#endregion FUNCTIONS

#region Site Specific Configuration Items
net user
"read the following account names from the above net user call."
$builtInAdministratorName = Read-Host prompt("what is the built in administrator name")
$backupAdministratorName = Read-Host prompt("what is the built in backup administrator name")
$builtInGuestName = Read-Host prompt("what is the built in guest name")
$authorizedServerAdministratorDomainGroups = @("", "")
#endregion

#-------------------------------------------------------------------------------------
# BEGIN SCRIPT EXECUTION
#-------------------------------------------------------------------------------------

# Clear output files
sc $outFileName ""
sc $outFileFindingDetail ""

#region Gather Target System Information and Check Applicability
$sysInfo = GWMI -class Win32_OperatingSystem -Computername $ServerNameToCheck
$sysDrive = "\\" + $ServerNameToCheck + "\" + ($sysInfo.SystemDrive -replace ":", "$")

if($sysInfo.BuildNumber -lt 9600 -or $sysInfo.BuildNumber -ge 9699)
{
	SendToLogAndOutput ("The specified computer is not running Microsoft Windows Server 2012 R2.  Aborting STIG checks!")
	SendToLogAndOutput ("  Expected build number between 9600 and 9699.  Found " + $sysInfo.BuildNumber)
    exit
}

$sysPath = "\\" + $ServerNameToCheck + "\" + $sysInfo.SystemDirectory -replace ":", "$"
$windowsPath = "\\" + $ServerNameToCheck + "\" + $sysInfo.WindowsDirectory -replace ":", "$"
$progData = (GetRegistryKeyValue "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" "ProgramData") -replace "%SystemDrive%", $sysInfo.SystemDrive
$programDataPath = "\\" + $ServerNameToCheck + "\" + $progData
$progFiles = GetRegistryKeyValue "SOFTWARE\Microsoft\Windows\CurrentVersion" "ProgramFilesDir"
$programFilesPath = "\\" + $ServerNameToCheck + "\" + ($progFiles -replace ":", "$")
$programFilesPathx86 = ($programFilesPath + " (x86)")

#If this is a local scan, do not use admin share UNC paths.  Instead, use local paths.
#This allows a local admin account to run the scan.
if($isLocalScan)
{ 
	$sysDrive = $sysInfo.SystemDrive
	$sysPath = $sysInfo.SystemDirectory
	$windowsPath = $sysInfo.WindowsDirectory
	$programDataPath = $progData
	$programFilesPath = $progFiles
	$programFilesPathx86 = ($programFilesPath + " (x86)")
}

SendToLog ("System Drive Path: " + $sysDrive)
SendToLog ("Target Windows Path: " + $windowsPath)
SendToLog ("Target Windows System Path: " + $sysPath)
SendToLog ("Target Program Files Path: " + $programFilesPath)
SendToLog ("Target Program Files (x86) Path: " + $programFilesPathx86)
SendToLog ("Target Program Data Path: " + $programDataPath)

#endregion

#Write XML header to results file
WriteResultFileHeader

#-------------------------------------------------------------------------------------
# BEGIN RULE CHECKS
#-------------------------------------------------------------------------------------

#region User Registry Hive Checks
#---------------------------------------------------------------------------------------------------------------------------------
# Perform check on each user hive for required setings

SendToLog ("Beginning check of user registry hives...") #We do this manually here instead of calling BeginCheck because this encompasses multiple rules
$logFileIndent = "    "

$FindingList = @{}  # A true value indicates compliant, a false value is non-compliant
$FindingList.Add("SV-53145r1_rule", $true)
$FindingList.Add("SV-53144r1_rule", $true)
$FindingList.Add("SV-53140r2_rule", $true)
$FindingList.Add("SV-53006r1_rule", $true)
$FindingList.Add("SV-53004r1_rule", $true)
$FindingList.Add("SV-53002r1_rule", $true)
$FindingList.Add("SV-52921r1_rule", $true)
$FindingList.Add("SV-51758r2_rule", $true)
#$FindingList.Add("SV-51759r1_rule", $true)
$FindingList.Add("SV-51760r1_rule", $true)
#$FindingList.Add("SV-51761r1_rule", $true)
$FindingList.Add("SV-51762r1_rule", $true)
$FindingList.Add("SV-51763r1_rule", $true)

$rKey = $regHKLM.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\")
$userProfileList = $rKey.GetSubKeyNames()

$tempStore = $env:SystemDrive + "\AuditTemp"
$null = md $tempStore

foreach($userProfile in $userProfileList)
{
	if($userProfile -ne "S-1-5-18" -and $userProfile -ne "S-1-5-19" -and $userProfile -ne "S-1-5-20")
	{
		$UserProfileKey = $rKey.OpenSubKey($userProfile)
		$UserProfilePath = $UserProfileKey.GetValue("ProfileImagePath")
		$localProfilePath = $UserProfilePath

		$remoteProfilePath = $localProfilePath -replace "%systemroot%", $windowsPath
		if(-Not $isLocalScan)
		{
			$remoteProfilePath = ("\\" + $ServerNameToCheck + "\" + $remoteProfilePath -replace ":", "$")
		}

		$remoteRegHivePath = ($remoteProfilePath  + "\NTUSER.DAT")
  
		SendToLog ("Checking registry settings for user with SID: " + $userProfile )
		$logFileIndent = "        "
		
		$localUserTempFolder = ($tempStore + "\" + $userProfile)
		$null = md $localUserTempFolder

		try
		{
			copy ($remoteProfilePath + "\NTUSER.DAT") $localUserTempFolder
		}
		catch
		{
			
		}
  
		# If the hive was copied sucessfully...
		if(Test-Path ($localUserTempFolder + "\NTUSER.DAT"))
		{
			#Write-Host "Loading Registry Hive Locally..."
			SendToLog ("Connecting to the user's registry hive (offline copy)...")
			$null = (reg load 'HKLM\TempUserAudit' ($localUserTempFolder + "\NTUSER.DAT"))
			$regHKLMA = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry32')
			$baseUserHive = $regHKLMA.OpenSubKey("TempUserAudit")

			# Perform Checks
			$FindingList = PerformUserHiveChecks $baseUserHive $FindingList
			$baseUserHive.Close()
    
			#Unload the registry hive copy and delete it
			while((Test-Path hklm:\TempUserAudit) -or (Test-Path($localUserTempFolder + "\NTUSER.DAT")))
			{
				[gc]::collect()
				Start-Sleep 1
				$null = (reg unload 'HKLM\TempUserAudit')
				del ($localUserTempFolder + "\NTUSER.DAT") -Force
			}
		}
  
		#If not, assume it's loaded already and try to access it via the registry object
		else
		{
			$regUsers = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $ServerNameToCheck)
			$baseUserHive = $regUsers.OpenSubKey($userProfile)
		
			if($baseUserHive -ne $null)
			{
				# Perform Checks
				SendToLog ("Connecting to the user's registry hive (online)...")
				$FindingList = PerformUserHiveChecks $baseUserHive $FindingList
			}
			else
			{
				SendToLog("An error ocurred while attempting to load the user's registry hive.")
			}
		}
		$logFileIndent = "    "
	}
	
}

rd $tempStore -Recurse -Force

SendToLog ("")
SendToLog ("Results:")
#Record Findings
$logFileIndent = "        "
$enumVar = $FindingList.GetEnumerator()
while($enumVar.MoveNext())
{
    if($enumVar.Value)
    {
      RecordFindingStatus $enumVar.Key  "pass"
    }
    else
    {
      RecordFindingStatus $enumVar.Key  "fail"
    }
}
$logFileIndent = ""
SendToLog ("")
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Simple Machine Level Registry Checks
#---------------------------------------------------------------------------------------------------------------------------------
CheckRegistryKeyValue "SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2 "SV-51750r2_rule"
CheckRegistryKeyValue "SOFTWARE\Policies\Microsoft\WindowsStore" "RemoveWindowsStore" 1 "SV-51751r2_rule"
CheckRegistryKeyValue "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "RedirectOnlyDefaultClientPrinter" 1 "SV-52163r2_rule"
CheckRegistryKeyValue "SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" 1 "SV-56343r2_rule"
CheckRegistryKeyValue "SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI" 1 "SV-56346r2_rule"
CheckRegistryKeyValue "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional" 1 "SV-56353r2_rule"
CheckRegistryKeyValue "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" 1 "SV-56355r2_rule"
#---------------------------------------------------------------------------------------------------------------------------------
#endregion

#region Rule SV-52156 & SV-52157
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52156r2_rule"
$memberCount = 0

Try
{
	$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $ServerNameToCheck)
	$backupOperatorsGroup = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($principalContext, "Backup Operators")
    $memberCount = $backupOperatorsGroup.Members.Count
    
    Foreach($boMember in $backupOperatorsGroup.Members)
    {
		SendToLog("Found undocumented user account in the Backup Operators security group: " + $boMember.Context.Name + "\" + $boMember.Name)
    }
}
Catch
{
    SendToLog("An error ocurred while running the rule check! Skipping $ruleId.")
}

if($memberCount -eq 0)
{
    RecordFindingStatus $ruleId  "notapplicable"
}
elseif($memberCount -ne $null)
{
    RecordFindingStatus $ruleId  "fail"
}

EndCheck

BeginCheck "SV-52157r2_rule"
if($memberCount -eq 0)
{
    RecordFindingStatus $ruleId  "notapplicable"
}
elseif($memberCount -eq $null)
{
    SendToLog("An error ocurred while running the rule check! Skipping $ruleId.")
}
else
{
	SendToLog("Members were found in the Backup Operators group.  A manual review of rule SV-52157 is required.")
	RecordFindingStatus $ruleId  "manual"
}
EndCheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-52854
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52854r4_rule"
$dormantAccountCount = 0

Try
{
    $adsi = [ADSI]("WinNT://" + $ServerNameToCheck)
	$localUserAccounts = @($adsi.Children | where {$_.SchemaClassName -eq 'user'})
        
    Foreach($usr in $localUserAccounts)
    {
		$dt = [datetime]::MinValue
		if($usr.PsBase.Properties.LastLogin.Value -ne $null)
		{
			$dt = [datetime]($usr.PsBase.Properties.LastLogin.Value)
		}
		
		if($usr.name -ne $builtInAdministratorName -and $usr.name -ne $backupAdministratorName -and $usr.name -ne $builtInGuestName -and (Get-Date).AddDays(-35) -le $dt)
		{
			SendToLog("$ruleId - Dormant user account found. " + $usr.name + ", Last Login: $dt")
			$dormantAccountCount = $dormantAccountCount + 1
		}
    }
}
Catch
{
    $dormantAccountCount = $Null
}

if($dormantAccountCount -eq 0)
{
    RecordFindingStatus $ruleId  "pass"
}
elseif($dormantAccountCount -ne $null)
{
    RecordFindingStatus $ruleId  "fail"
}
EndCheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-51569
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-51569r1_rule"
$eventLogAclFinding = $false

Try
{
	$systemEventLogFile = ParseRemoteFilePath(GetRegistryKeyValue "SYSTEM\CurrentControlSet\services\eventlog\system\" "File")
	$a = Get-Acl $systemEventLogFile
	foreach($e in $a.Access)
	{
		$idRef = $e.IdentityReference.Value
		if($idRef -ne "BuiltIn\Administrators" -and $idRef -ne "NT SERVICE\eventlog" -and $idRef -ne "NT AUTHORITY\SYSTEM")
		{
			$eventLogAclFinding = $true
			SendToLog("$ruleId - Event log file found with unpermitted ACL entry. File Path: $logFile, Identity: $idRef, Permission Value: $a.Access.FileSystemRights")
		}
	}
}
Catch
{
    SendToLog("An error ocurred while running the rule check! Skipping $ruleId.")
}

if($eventLogAclFinding -eq $false)
{
    RecordFindingStatus $ruleId  "pass"
}
elseif($dormantAccountCount -ne $null)
{
    RecordFindingStatus $ruleId  "fail"
}
EndCheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-87391
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-87391r1_rule"
$is2012R2 = $false

Try
{
	$useLogonCredentialForWDigest = GetRegistryKeyValue "SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" "UseLogonCredential"
	$is2012R2 = ($sysInfo.BuildNumber -ge 9600 -and $sysInfo.BuildNumber -lt 9699)
}
Catch
{
    SendToLog("An error ocurred while running the rule check! Skipping $ruleId.")
}

if($useLogonCredentialForWDigest -eq 0 -and $is2012R2)
{
    RecordFindingStatus $ruleId  "pass"
}
elseif($useLogonCredentialForWDigest -eq 0 -and (-not $is2012R2))
{
    SendToLog ("Warning: Server OS is not 2012 R2.  Manual review of $ruleId is required.")
	RecordFindingStatus $ruleId  "manual"
}
else
{
	RecordFindingStatus $ruleId  "fail"
}
EndCheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-51571
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-51571r1_rule"
Try
{
	$applicationEventLogFile = ParseRemoteFilePath(GetRegistryKeyValue "SYSTEM\CurrentControlSet\services\eventlog\application\" "File")
	$a = Get-Acl $systemEventLogFile
	foreach($e in $a.Access)
	{
		$idRef = $e.IdentityReference.Value
		if($idRef -ne "BuiltIn\Administrators" -and $idRef -ne "NT SERVICE\eventlog" -and $idRef -ne "NT AUTHORITY\SYSTEM")
		{
			$eventLogAclFinding = $true
			SendToLog("$ruleId - Event log file found with unpermitted ACL entry. File Path: $logFile, Identity: $idRef, Permission Value: $a.Access.FileSystemRights")
		}
	}
}
Catch
{
    SendToLog("An error ocurred while running the rule check! Skipping $ruleId.")
}

if($eventLogAclFinding -eq $false)
{
    RecordFindingStatus $ruleId  "pass"
}
elseif($dormantAccountCount -ne $null)
{
    RecordFindingStatus $ruleId  "fail"
}
EndCheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-51572
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-51572r1_rule"
Try
{
	$securityEventLogFile = ParseRemoteFilePath(GetRegistryKeyValue "SYSTEM\CurrentControlSet\services\eventlog\security\" "File")
	
	foreach($logFile in $eventLogFileList)
	{
		$a = Get-Acl $logFile
		foreach($e in $a.Access)
		{
			$idRef = $e.IdentityReference.Value
			if($idRef -ne "BuiltIn\Administrators" -and $idRef -ne "NT SERVICE\eventlog" -and $idRef -ne "NT AUTHORITY\SYSTEM")
			{
				$eventLogAclFinding = $true
				SendToLog("$ruleId - Event log file found with unpermitted ACL entry. File Path: $logFile, Identity: $idRef, Permission Value: $a.Access.FileSystemRights")
			}
		}
	}
}
Catch
{
    $eventLogAclFinding = $Null
}

if($eventLogAclFinding -eq $false)
{
    RecordFindingStatus $ruleId  "pass"
}
elseif($dormantAccountCount -ne $null)
{
    RecordFindingStatus $ruleId  "fail"
}
#---------------------------------------------------------------------------------------------------------------------------------
#endregion

#region Rule SV-52212 & SV-52106
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52212r2_rule"

$isRunningFtp = $true

try
{
	[System.Net.Sockets.TcpClient]$client = New-Object System.Net.Sockets.TcpClient($ServerNameToCheck, 21)
	$client.Close()
	$isRunningFtp = $true
}
catch
{
	$isRunningFtp = $false
}

if($isRunningFtp)
{
  RecordFindingStatus $ruleId  "manual"
}
else
{
	RecordFindingStatus $ruleId  "pass"
}

EndCheck

BeginCheck "SV-52106r2_rule"
if($isRunningFtp)
{
    RecordFindingStatus $ruleId  "manual"
}
else
{
	RecordFindingStatus $ruleId  "pass"
}
EndCheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion

#region Rule SV-52919
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52919r2_rule"

$ntpTypeValue = GetRegistryKeyValue "SYSTEM\CurrentControlSet\Services\W32time\Parameters" "Type"
$ntpServerValue = GetRegistryKeyValue "SYSTEM\CurrentControlSet\Services\W32time\Parameters" "NtpServer"

$ntpPolicyTypeValue = GetRegistryKeyValue "SoFTWARE\Policies\Microsoft\W32time\Parameters" "Type"
$ntpPolicyServerValue = GetRegistryKeyValue "SoFTWARE\Policies\Microsoft\W32time\Parameters" "Type"

if($ntpPolicyTypeValue -ne $null)
{
  $ntpTypeValue = $ntpPolicyTypeValue
}
if($ntpPolicyServerValue -ne $null)
{
  $ntpServerValue = $ntpPolicyServerValue 
}

if($ntpTypeValue -eq "NT5DS" -or $ntpTypeValue -eq "NoSync")
{
  RecordFindingStatus $ruleId  "pass"
}
elseif(($ntpTypeValue -eq "NTP" -or $ntpTypeValue -eq "Allsync") -and $ntpServerValue -notlike "*navy.mil")
{
	SendToLog("An unauthorized NTP server is configured on the target system.  Found Server: $ntpServerValue)")
	RecordFindingStatus $ruleId  "fail"
}
else
{
	SendToLog ("Warning: Unable to determine compliance status of rule $ruleId.  Manual review is required.")
	RecordFindingStatus $ruleId  "manual"
}
EndCheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-52103 & SV-52133
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52103r4_rule"

#This only checks for the existence of McAfee.
$mcafeeVersion = [version] "0.0.0.0"
if(Test-Path ($programFilesPathx86 + "\McAfee\VirusScan Enterprise\shstat.exe"))
{
	$mcafeeVersion = [Version](((gci ($programFilesPathx86 + "\McAfee\VirusScan Enterprise\shstat.exe")).VersionInfo).FileVersion)
}

if($mcafeeVersion -ge ([Version] "8.8.0.1528"))
{
	RecordFindingStatus $ruleId  "pass"
}
else
{
	SendToLog("McAfee Antivirus version 8.8.0.1528 or higher could not be located on the target system.  Expected file " + ($programFilesPathx86 + "\McAfee\VirusScan Enterprise\shstat.exe") + " with version 8.8.0.1528 or higher.")
	RecordFindingStatus $ruleId  "fail"
}
Endcheck

BeginCheck "SV-52133r3_rule"
$upToDate = $false
$virusDefDate = GetRegistryKeyValue "SOFTWARE\Wow6432Node\McAfee\AVEngine" "AVDatDate"
if($virusDefDate -ne $null)
{
	$upToDate = ((Get-Date).AddDays(-7)) -lt ([datetime]$virusDefDate)
}

if($upToDate)
{
	RecordFindingStatus $ruleId  "pass"
}
else
{
	SendToLog("Anti-virus definitions do not exist on the target system or have not been updated in the past seven days.")
	SendToLog("    Found Value: $virusDefDate")
	RecordFindingStatus $ruleId  "fail"
}
Endcheck

#---------------------------------------------------------------------------------------------------------------------------------
#endregion

#region Rule SV-52105
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52105r3_rule"
$mcafeeHIPSPresent = ((Test-Path ($programFilesPathx86 + "\McAfee\Host Intrusion Prevention\x64\FireSvc.exe")) -or (Test-Path ($programFilesPath + "\McAfee\Host Intrusion Prevention\FireSvc.exe")))
$mcafeeHIPSRunning = (Get-Service "enterceptAgent" -ComputerName $ServerNameToCheck -ErrorAction SilentlyContinue).Status -eq "Running"

if($mcafeeHIPSPresent -and $mcafeeHIPSRunning)
{
  RecordFindingStatus $ruleId  "pass"
}
else
{
	if(-Not $mcafeeHIPSPresent)
	{
		SendToLog("McAfee HIPS could not be located on the target system.  Expected file: $programFilesPathx86\McAfee\Host Intrusion Prevention\x64\FireSvc.exe")
	}
	elseif(-Not $mcafeeHIPSRunning)
	{
		SendToLog("McAfee HIPS is installed on the target system but was not running.")
	}
	
	RecordFindingStatus $ruleId  "fail"
}
Endcheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-52881
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52881r3_rule"
$fileShares = gwmi Win32_Share -ComputerName $ServerNameToCheck
$systemShares = ("ADMIN$", "IPC$", "print$")
$customFileSharePresent = $false

#Search for administrator or user created file shares
foreach($shr in $fileShares)
{
	if($systemShares -notcontains $shr.Name -and $shr.Type -ne 2147483648 -and $shr.Type -ne 3221225472)
	{
		$customFileSharePresent = $true
		SendToLog("Found administrator/user created file share.  Name: $($shr.Name)")
	}
}

if(-not $customFileSharePresent)
{
  RecordFindingStatus $ruleId  "pass"
}
else
{
	SendToLog("Administrator/user created file shares were found on the server.  A manual review of rule SV-52881 is required.")	
	RecordFindingStatus $ruleId  "manual"
}
Endcheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-53123
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-53123r4_rule"

$regAclKey = $regHKLM.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon")
$regAclData = ($regAclKey.GetAccessControl()).Sddl

# Remove Allowed permission strings
$regAclData = $regAclData -replace "O:BAG:BAD:AI", "" # Ownership 1
$regAclData = $regAclData -replace "O:SYG:SYD:AI", "" # Ownership 2


$regAclData = $regAclData -replace "\(A;ID;KA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\)", "" # Trusted Installer 1 - Full Control
$regAclData = $regAclData -replace "\(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\)", "" # Trusted Installer 2 - Full Control


$regAclData = $regAclData -replace "\(A;ID;KA;;;BA\)", "" # Built-In Administrators 1 - Full Control
$regAclData = $regAclData -replace "\(A;CIIOID;GA;;;BA\)", "" # Built-In Administrators 2 - Full Control

$regAclData = $regAclData -replace "\(A;ID;KA;;;SY\)", "" # System - Full Control 1
$regAclData = $regAclData -replace "\(A;CIIOID;GA;;;SY\)", "" # System - Full Control 2

$regAclData = $regAclData -replace "\(A;ID;KR;;;BU\)", "" # Built In Users - Read 1
$regAclData = $regAclData -replace "\(A;CIIOID;GR;;;BU\)", "" # Built In Users - Read 2

$regAclData = $regAclData -replace "\(A;ID;KR;;;S-1-15-2-1\)", "" # All App Packages - Read 1
$regAclData = $regAclData -replace "\(A;CIIOID;GR;;;S-1-15-2-1\)", "" # All App Packages - Read 2
$regAclData = $regAclData -replace "\(A;ID;KR;;;AC\)", "" # All App Packages - Read 3
$regAclData = $regAclData -replace "\(A;CIIOID;GR;;;AC\)", "" # All App Packages - Read 4

#if there's any additional permissions, mark as a finding
if($regAclData.Length -eq 0)
{
    RecordFindingStatus $ruleId  "pass"
}
else
{
	SendToLog ("Additional (potentially insecure) ACL entries were found on HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon.  Suspect ACL Data: " + $regAclData)
    RecordFindingStatus $ruleId  "fail"
}
Endcheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-52939, SV-52940, SV-52942, SV-52839, SV-51580, SV-72063, & SV-72065
#---------------------------------------------------------------------------------------------------------------------------------
SendToLog ("Beginning check of rules SV-52939, SV-52940, SV-52942, SV-52839, SV-51580, SV-72063, & SV-72065...")
$logFileIndent = "    "
	
$localUsers = (gwmi Win32_UserAccount -ComputerName $ServerNameToCheck -Filter "LocalAccount='$true'")
$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $ServerNameToCheck)

$foundUserwithPwdNotRequired = $false
$foundUserwithNonExpiringPwd = $false
$foundUserwithStalePwd = $false
$foundCustomLocalAccounts = $false
$foundCustomLocalAccountsThatDoNotExpire = $false

#Check for any custom local accounts (If none exist, certain STIG rules are not applicable)
$customAccounts = @($localUsers | ? {$_.Name -ne $builtInAdministratorName -and $_.Name -ne $backupAdministratorName -and $_.Name -ne $builtInGuestName})
$foundCustomLocalAccounts = ($customAccounts.Count -gt 0)

#Check for correct settings on local accounts
foreach($usr in $localUsers)
{
	$userObj = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($principalContext, $usr.Name)  
	if(($usr.Name -ne $builtInAdministratorName) -and ($usr.Name -ne $backupAdministratorName) -and ($usr.Name -ne $builtInGuestName) -and ($userObj.LastPasswordSet -le ((Get-Date).AddDays(-365))))
	{
		$foundUserwithStalePwd = $true
		SendToLog("SV-51580r2_rule - Local user found with stale password: " + $usr.Name + ".  Last Changed: " + $userObj.LastPasswordSet)
	}

	if($usr.PasswordRequired -ne $true)
	{
		$foundUserwithPwdNotRequired = $true
		SendToLog("SV-52940r1_rule - Local user found with password not required: " + $usr.Name)
	}

	if($usr.PasswordExpires -ne $true)
	{
		if(($usr.Name -ne $builtInAdministratorName) -and ($usr.Name -ne $backupAdministratorName))
		{
			$foundUserwithNonExpiringPwd = $true
			SendToLog("SV-52939r3_rule - Local user found with password that does not expire: " + $usr.Name)
		}
	}
	
	#Check for local user accounts (standard admins and guest are exempt) that do not expire or have expiration dates more than 72 hours from now
	if(($usr.Name -ne $builtInAdministratorName) -and ($usr.Name -ne $backupAdministratorName) -and ($usr.Name -ne $builtInGuestName))
	{
		if($userObj.AccountExpirationDate -ne $null)
		{
			if($userObj.AccountExpirationDate -gt (Get-Date).AddHours(72))
			{
				$foundCustomLocalAccountsThatDoNotExpire = $true
				SendToLog("SV-72063 & SV-72066 - Local user account found with expiration date more than 72 hours from now: " + $usr.Name)
			}
		}
		else
		{
			$foundCustomLocalAccountsThatDoNotExpire = $true
			SendToLog("SV-72063 & SV-72066 - Local user account found with no expiration date: " + $usr.Name)
		}
	}
}

#Check for stale passwords on built-in administrator and backup administrator account
$adminPasswordsChangedWithinTheLastYear = $true
$adminList = $localUsers | ? {$_.Name -eq $backupAdministratorName -or $_.Name -eq $builtInAdministratorName}
foreach($adm in $adminList)
{
  $userObj = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($principalContext, $adm.Name)
  if($userObj.LastPasswordSet -le ((Get-Date).AddDays(-365)))
  {
    $adminPasswordsChangedWithinTheLastYear = $false
    SendToLog("SV-52942r2_rule - Default or backup administrator found with stale password: " + $adm.Name + ".  Last Changed: " + $userObj.LastPasswordSet)
  }
}


$ruleId = "SV-52839r1_rule"
if($foundCustomLocalAccounts)
{
	SendToLog("Custom local user accounts were found on the target system.  A manual review of rule SV-52839 is required.")
	RecordFindingStatus $ruleId  "manual"
}
else 
{
	RecordFindingStatus $ruleId  "notapplicable"
}

$ruleId = "SV-52939r3_rule"
if($foundUserwithNonExpiringPwd)
{
  RecordFindingStatus $ruleId  "fail"
}
else
{
  RecordFindingStatus $ruleId  "pass"
}

$ruleId = "SV-72063r2_rule"
if($foundCustomLocalAccountsThatDoNotExpire)
{
	SendToLog("Custom local user accounts that do not expire within 72 hours were found on the target system.  A manual review of rule SV-72063 is required.")
	RecordFindingStatus $ruleId  "manual"
}
else
{
  RecordFindingStatus $ruleId  "pass"
}

$ruleId = "SV-72065r3_rule"
if($foundCustomLocalAccountsThatDoNotExpire)
{
	SendToLog("Custom local user accounts that do not expire within 72 hours were found on the target system.  A manual review of rule SV-72065 is required.")
	RecordFindingStatus $ruleId  "manual"
}
else
{
	RecordFindingStatus $ruleId  "pass"
}

$ruleId = "SV-52940r1_rule"
if($foundUserwithPwdNotRequired)
{
  RecordFindingStatus $ruleId  "fail"
}
else
{
  RecordFindingStatus $ruleId  "pass"
}

$ruleId = "SV-51580r2_rule"
if($foundUserwithStalePwd)
{
  RecordFindingStatus $ruleId  "fail"
}
else
{
  RecordFindingStatus $ruleId  "pass"
}

$ruleId = "SV-52942r2_rule"
if($adminPasswordsChangedWithinTheLastYear)
{
  RecordFindingStatus $ruleId  "pass"
}
else
{
  RecordFindingStatus $ruleId  "fail"
}

$logFileIndent = ""
SendToLog ("")
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-52956
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52956r3_rule"

$regAclKey1 = $regHKLM.OpenSubKey("SOFTWARE\Microsoft\Active Setup\Installed Components")
$regAclKey2 = $regHKLM.OpenSubKey("SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components")

$regAclData1 = ($regAclKey1.GetAccessControl()).Sddl
$regAclData2 = ($regAclKey2.GetAccessControl()).Sddl

$regAclData1 = $regAclData1 -replace "O:BAG:BAD:AI", "" # Ownership 1
$regAclData1 = $regAclData1 -replace "O:SYG:SYD:AI", "" # Ownership 2

$regAclData1 = $regAclData1 -replace "\(A;CIID;KA;;;BA\)", "" #Built-In Administrators
$regAclData1 = $regAclData1 -replace "\(A;ID;KA;;;BA\)", "" #Built-In Administrators
$regAclData1 = $regAclData1 -replace "\(A;CIIOID;GA;;;BA\)", "" #Built-In Administrators
$regAclData1 = $regAclData1 -replace "\(A;CIIOID;KA;;;CO\)", "" # Creator/Owner
$regAclData1 = $regAclData1 -replace "\(A;CIIOID;GA;;;CO\)", "" # Creator/Owner
$regAclData1 = $regAclData1 -replace "\(A;CIID;KA;;;SY\)", "" # System
$regAclData1 = $regAclData1 -replace "\(A;ID;KA;;;SY\)", "" # System
$regAclData1 = $regAclData1 -replace "\(A;CIIOID;GA;;;SY\)", "" # System
$regAclData1 = $regAclData1 -replace "\(A;CIID;KR;;;BU\)", "" # Built-In Users
$regAclData1 = $regAclData1 -replace "\(A;ID;KR;;;BU\)", "" # Built-In Users
$regAclData1 = $regAclData1 -replace "\(A;CIIOID;GR;;;BU\)", "" # Built-In Users
$regAclData1 = $regAclData1 -replace "\(A;CIID;KR;;;S-1-15-2-1\)", "" # All App Packages (Read 1)
$regAclData1 = $regAclData1 -replace "\(A;ID;KR;;;S-1-15-2-1\)", "" # All App Packages (Read 2)
$regAclData1 = $regAclData1 -replace "\(A;CIIOID;GR;;;S-1-15-2-1\)", "" # All App Packages (Read 3)
$regAclData1 = $regAclData1 -replace "\(A;CIID;KR;;;AC\)", "" # All App Packages (Read 4)
$regAclData1 = $regAclData1 -replace "\(A;ID;KR;;;AC\)", "" # All App Packages (Read 5)
$regAclData1 = $regAclData1 -replace "\(A;CIIOID;GR;;;AC\)", "" # All App Packages (Read 6)


$regAclData2 = $regAclData2 -replace "O:BAG:BAD:AI", "" # Ownership 1
$regAclData2 = $regAclData2 -replace "O:SYG:SYD:AI", "" # Ownership 2
$regAclData2 = $regAclData2 -replace "\(A;CIID;KA;;;BA\)", "" #Built-In Administrators
$regAclData2 = $regAclData2 -replace "\(A;ID;KA;;;BA\)", "" #Built-In Administrators
$regAclData2 = $regAclData2 -replace "\(A;CIIOID;GA;;;BA\)", "" #Built-In Administrators
$regAclData2 = $regAclData2 -replace "\(A;CIIOID;KA;;;CO\)", "" # Creator/Owner
$regAclData2 = $regAclData2 -replace "\(A;CIIOID;GA;;;CO\)", "" # Creator/Owner
$regAclData2 = $regAclData2 -replace "\(A;CIID;KA;;;SY\)", "" # System
$regAclData2 = $regAclData2 -replace "\(A;ID;KA;;;SY\)", "" # System
$regAclData2 = $regAclData2 -replace "\(A;CIIOID;GA;;;SY\)", "" # System
$regAclData2 = $regAclData2 -replace "\(A;CIID;KR;;;BU\)", "" # Built-In Users
$regAclData2 = $regAclData2 -replace "\(A;ID;KR;;;BU\)", "" # Built-In Users
$regAclData2 = $regAclData2 -replace "\(A;CIIOID;GR;;;BU\)", "" # Built-In Users
$regAclData2 = $regAclData2 -replace "\(A;CIID;KR;;;S-1-15-2-1\)", "" # All App Packages (Read)
$regAclData2 = $regAclData2 -replace "\(A;ID;KR;;;AC\)", "" # All App Packages (Read)
$regAclData2 = $regAclData2 -replace "\(A;CIID;KR;;;AC\)", "" # All App Packages (Read)


if($regAclData1.Length -ne 0)
{
	SendToLog ("Additional (potentially insecure) ACL entries were found on HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components.  Suspect ACL Data: " + $regAclData1)
}

if($regAclData2.Length -ne 0)
{
	SendToLog ("Additional (potentially insecure) ACL entries were found on HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components.  Suspect ACL Data: " + $regAclData2)
}

if($regAclData1.Length -eq 0 -and $regAclData2.Length -eq 0)
{
    RecordFindingStatus $ruleId  "pass"
}
else
{
    RecordFindingStatus $ruleId  "fail"
}
EndCheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-51584
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-51584r1_rule"
$crlCheckAgentPresent = Test-Path ($programFilesPath + "\Tumbleweed\Desktop Validator\DVService.exe")
$crlCheckAgentRunning = (Get-Service "Tumbleweed Desktop Validator" -ComputerName $ServerNameToCheck -ErrorAction SilentlyContinue).Status -eq "Running" 

if(-Not $crlCheckAgentPresent)
{
	SendToLog("The CRL checking service is not installed.  Expected file:  $programFilesPath\Tumbleweed\Desktop Validator\DVService.exe")
}

if(-Not $crlCheckAgentRunning)
{
	SendToLog("The CRL checking service (Tumbleweed Desktop Validator) is installed but was not running.")
}

if($crlCheckAgentPresent -and $crlCheckAgentRunning)
{
  RecordFindingStatus $ruleId  "pass"
}
else
{
  RecordFindingStatus $ruleId  "fail"
}
Endcheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion

#region Rule SV-52882
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52882r1_rule"
SendToLogAndOutput("Obtaining security policy from target system...")

$allowAnonSidNameTrans = $false
if(Test-Path $psExecPath)
{
	Write-Host ("--------------------------------------------------------------------------")
	$secPolicyData = & $psExecPath -S \\$ServerNameToCheck secedit /export /cfg ($sysInfo.WindowsDirectory + "\temp\secexport.cfg")
	Write-Host ("--------------------------------------------------------------------------")
	
	$secDataRemotePath = $windowsPath + "\Temp\secexport.cfg"
	if($secPolicyData -contains "The task has completed successfully.")
	{
		if(Test-Path $secDataRemotePath)
		{
			$secData = gc $secDataRemotePath
			$rawTextValue = ($secData | Select-String "LSAAnonymousNameLookup").ToString().Split('=')[1].Trim()
			$allowAnonSidNameTrans = ($rawTextValue -eq "0")
			
			del $secDataRemotePath
		}
	}
	else
	{
		if(Test-Path $secDataRemotePath) {del $secDataRemotePath}
		SendToLog("Unable to successfully retrieve security policy data from $ServerNameToCheck.")
		SendToLog("As a result, the check for rule SV-52882 was skipped.")
		SendToLog("Command Output: $secPolicyData")
	}
}
else
{
	$allowAnonSidNameTrans = $null
	SendToLog("PSExec.exe was not found in the expected location.  Path: $psExecPath")
	SendToLog("As a result, the check for rule SV-52882 was skipped.")
}

if($allowAnonSidNameTrans -eq $null)
{
	RecordFindingStatus $ruleId  "manual"
}
elseif($allowAnonSidNameTrans)
{
  RecordFindingStatus $ruleId  "pass"
}
else
{
  RecordFindingStatus $ruleId  "fail"
}
Endcheck

#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-52858
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52858r1_rule"
SendToLogAndOutput("Obtaining boot configuration from target system...")

$hasSingleBootEntry = $false
if(Test-Path $psExecPath)
{
	Write-Host ("--------------------------------------------------------------------------")
	$bootCfg = & $psExecPath -S \\$ServerNameToCheck bcdedit /v
	Write-Host ("--------------------------------------------------------------------------")
	
	if($bootCfg -contains "Windows Boot Loader")
	{
		$bootEntryCount = ($bootCfg | ? {$_ -like "description*" -and (-not ($_ -like "*Windows Boot Manager"))}).Count
		$hasSingleBootEntry = ($bootEntryCount -eq 1)
	}
	else
	{
		SendToLog("Unable to successfully retrieve boot configuration from $ServerNameToCheck.")
		SendToLog("As a result, the check for rule SV-52858 was skipped.")
		SendToLog("Command Output: $bootCfg")
	}
}
else
{
	$hasSingleBootEntry = $null
	SendToLog("PSExec.exe was not found in the expected location.  Path: $psExecPath")
	SendToLog("As a result, the check for rule SV-52858 was skipped.")
}

if($hasSingleBootEntry)
{
	RecordFindingStatus $ruleId  "pass"
}
else
{
	RecordFindingStatus $ruleId  "manual"
}
Endcheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-51601, SV-51604, SV-52159, & SV-52161
#---------------------------------------------------------------------------------------------------------------------------------
SendToLog("Beginning validation of Audit Policy settings (SV-51601, SV-51604, SV-52159, & SV-52161)...")
$logFileIndent = "    "
SendToLogAndOutput("Obtaining Audit Policy from target system...")

$resultData = @{}
$resultData.Add("SV-51601r2_rule", $false)
$resultData.Add("SV-51604r2_rule", $false)
$resultData.Add("SV-52159r3_rule", $false)
$resultData.Add("SV-52161r3_rule", $false)

if(Test-Path $psExecPath)
{
	Write-Host ("--------------------------------------------------------------------------")
	$auditingPolicyData = & $psExecPath -S \\$ServerNameToCheck auditpol.exe /get /category:*
	$fileAuditPolicyData = & $psExecPath -S \\$ServerNameToCheck auditpol.exe /resourceSACL /type:File /view
	$registryAuditPolicyData = & $psExecPath -S \\$ServerNameToCheck auditpol.exe /resourceSACL /type:Key /view
	Write-Host ("--------------------------------------------------------------------------")
	Write-Host ("")
	if($auditingPolicyData.Count -gt 50)
	{
		$idx = 0
		while($idx -lt $auditingPolicyData.Count)
		{
			$str = $auditingPolicyData[$idx]
			
			if($str -eq "Object Access")
			{
				$idx = $idx + 1
				$str = $auditingPolicyData[$idx]
				while($str -match "^  " -or $str -match "^$")
				{
					if($str -match "^  Removable Storage[ ]+([A-Za-z ]+)")
					{
						if($matches[1] -like "*Success*")
						{
							$resultData["SV-51601r2_rule"] = $true
						}
						if($matches[1] -like "*Failure*")
						{
							$resultData["SV-51604r2_rule"] = $true
						}
					}
					elseif($str -match "^  Central Policy Staging[ ]+([A-Za-z ]+)")
					{
						if($matches[1] -like "*Success*")
						{
							$resultData["SV-52161r3_rule"] = $true
						}
						if($matches[1] -like "*Failure*")
						{
							$resultData["SV-52159r3_rule"] = $true
						}
					}
					$str = $auditingPolicyData[$idx]
					$idx = $idx + 1
				}
			}
			$idx = $idx + 1
		}
	}
	else
	{
		$removableStorageAuditingIsCorrect = $null
		SendToLog("The audit policy data retrieved from $ServerNameToCheck did not appear to be valid.")
		SendToLog("As a result, checks for rules SV-51601, SV-51604, SV-52159, & SV-52161 were skipped.")
	}
}
else
{
	$removableStorageAuditingIsCorrect = $null
	SendToLog("PSExec.exe was not found in the expected location.  Path: $psExecPath")
	SendToLog("As a result, checks for rules SV-51601, SV-51604, SV-52159, & SV-52161 were skipped.")
}

$e = $resultData.GetEnumerator()
while($e.MoveNext())
{
	if($e.Value)
	{
		RecordFindingStatus $e.Key  "pass"
    }
	else
	{
		if($e.Key -eq "SV-51601r2_rule"){SendToLog("Removable Storage Success auditing is not enabled.")}
		elseif($e.Key -eq "SV-51604r2_rule"){SendToLog("Removable Storage Failure auditing is not enabled.")}
		elseif($e.Key -eq "SV-52159r3_rule"){SendToLog("Central Policy Staging Failure auditing is not enabled.")}
		elseif($e.Key -eq "SV-52161r3_rule"){SendToLog("Central Policy Staging Success auditing is not enabled.")}
		RecordFindingStatus $e.Key  "fail"
	}
}


Endcheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-52213
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52213r1_rule"
$serverIsCompliant = $true
$printSpoolerRunning = (Get-Service Spooler -ComputerName $ServerNameToCheck -ErrorAction SilentlyContinue).Status -eq "Running"

if($printSpoolerRunning)
{
	SendToLogAndOutput("Obtaining list of shared printers from the target system...")
	$sharedPrinterList = (gwmi Win32_Printer -ComputerName $ServerNameToCheck | ? {$_.Shared -eq $true})
	
	$pace = @{}
	$pace.Add(983052, "ManagePrinter")
	$pace.Add(983088, "ManageDocuments")
	$pace.Add(131080, "Print")
	$pace.Add(524288, "TakeOwnership")
	$pace.Add(131072, "ReadPermissions")
	$pace.Add(262144, "ChangePermissions")
	
	$flags = @(983052, 983088, 131080, 524288, 131072, 262144)
	$restrictedFlags = @(983052, 983088, 524288, 262144)
	
	foreach($printer in $sharedPrinterList)
	{
		$dacl = $printer.GetSecurityDescriptor().Descriptor.DACL
		$permissionList = New-Object System.Collections.ArrayList
		
		foreach($entry in $dacl)
		{
			$userName = "$($entry.Trustee.Domain)\$($entry.Trustee.Name)"
			if($entry.Trustee.Name -eq $null)
			{
				$userName = $entry.Trustee.SIDString
			}
			
			if($userName -ne "BUILTIN\Administrators" -and $userName -ne "BUILTIN\Print Operators" -and $userName -ne "\CREATOR OWNER" -and $userName -notlike "*.dsa" -and $userName -notlike "*.oa")
			{
				foreach ($flag in $flags)
				{
					if ($flag -band $entry.AccessMask)
					{
						$bValue = [int]($flag -band $entry.AccessMask)
						if($restrictedFlags -contains $bValue)
						{
							$null = $permissionList.Add(@($printer.Name, $userName, $pace[$bValue])) #Using $null prevents the script from spitting numbers into the output
							$serverIsCompliant = $false
						}
					}
				}
			}
        }
		
		if($permissionList.Count -gt 0)
		{
			$serverIsCompliant = $false
			
			$userList =  $permissionList | % {$_[1]} | Sort-Object | Get-Unique
			foreach($u in $userList)
			{
				"Found printer $($printer.Name) with excessive permissions for $u`:"
				$userPermList = $permissionList | ? {$_[1] -eq $u} | Sort-Object | Get-Unique
				foreach($p in $permissionList | Select-Object -Unique)
				{
					"    - $($p[2])"
				}
			}
		}
	}
}

if($serverIsCompliant)
{
  RecordFindingStatus $ruleId  "pass"
}
else
{
  RecordFindingStatus $ruleId  "fail"
}

Endcheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region SV-51511 & SV-51575
#---------------------------------------------------------------------------------------------------------------------------------
SendToLog("Beginning check for rules SV-51511 & SV-51575...")
$logFileIndent = "    "
$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $ServerNameToCheck)
$adminsGroup = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($principalContext, "Administrators")
$manualReview = $false

foreach($adm in $adminsGroup.Members)
{
	if((-Not($adm.Name -eq $builtInAdministratorName -and $adm.ContextType -eq "Machine"))`
		-and (-Not($adm.Name -eq $backupAdministratorName -and $adm.ContextType -eq "Machine"))`
		-and (-Not($authorizedServerAdministratorDomainGroups -contains $adm.Name -and $adm.ContextType -eq "Domain")))
	{
		SendToLog("Unrecognized account/group in local administrators group: $($adm.Name)")
		$manualReview = $true
	}
}

if($manualReview)
{
	SendToLog("The target system has unrecognized accounts or groups in the local administrators group.  Rules SV-51511 & SV-51575 will require manual review.")
	RecordFindingStatus "SV-51511r3_rule" "manual"
	RecordFindingStatus "SV-51575r2_rule" "manual"
}
else
{
	RecordFindingStatus "SV-51511r3_rule" "pass"
	RecordFindingStatus "SV-51575r2_rule" "pass"
}
$logFileIndent = ""
SendToLog("")
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-52135
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52135r3_rule"

$everyoneIncludesAnonymous = GetRegistryKeyValue "System\CurrentControlSet\Control\Lsa\" "everyoneincludesanonymous"

$progFilesAclData = (([System.IO.DirectoryInfo]$programFilesPath).GetAccessControl()).Sddl
$progFilesx86AclData = (([System.IO.DirectoryInfo]$programFilesPathx86).GetAccessControl()).Sddl

# Remove Allowed permission strings
$trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

$progFilesAclData = $progFilesAclData -replace ("O:" + $trustedInstallerSID + "G:" + $trustedInstallerSID + "D:PAI"), "" # Ownership
$progFilesAclData = $progFilesAclData -replace "\(A;OICIIO;GA;;;CO\)", "" # Creator Owner 1
$progFilesAclData = $progFilesAclData -replace "\(A;OICIIO;GA;;;SY\)", "" # System 1
$progFilesAclData = $progFilesAclData -replace "\(A;;0x1301bf;;;SY\)", "" # System 2
$progFilesAclData = $progFilesAclData -replace "\(A;OICIIO;GA;;;BA\)", "" # Built-In Administrators 1
$progFilesAclData = $progFilesAclData -replace "\(A;;0x1301bf;;;BA\)", "" # Built-In Administrators 2
$progFilesAclData = $progFilesAclData -replace "\(A;OICIIO;GXGR;;;BU\)", "" # Built-In Users 1
$progFilesAclData = $progFilesAclData -replace "\(A;;0x1200a9;;;BU\)", "" # Built-In Users 2
$progFilesAclData = $progFilesAclData -replace ("\(A;CIIO;GA;;;" + $trustedInstallerSID + "\)"), "" # Trusted Installer 1
$progFilesAclData = $progFilesAclData -replace ("\(A;;FA;;;" + $trustedInstallerSID + "\)"), "" # Trusted Installer 2
$progFilesAclData = $progFilesAclData -replace "\(A;;0x1200a9;;;S-1-15-2-1\)", "" # All Application Packages 1
$progFilesAclData = $progFilesAclData -replace "\(A;OICIIO;GXGR;;;S-1-15-2-1\)", "" # All Application Packages 2
$progFilesAclData = $progFilesAclData -replace "\(A;;0x1200a9;;;AC\)", "" # All Application Packages 3
$progFilesAclData = $progFilesAclData -replace "\(A;OICIIO;GXGR;;;AC\)", "" # All Application Packages 4

$progFilesx86AclData = $progFilesx86AclData -replace ("O:" + $trustedInstallerSID + "G:" + $trustedInstallerSID + "D:PAI"), "" # Ownership
$progFilesx86AclData = $progFilesx86AclData -replace "\(A;OICIIO;GA;;;CO\)", "" # Creator Owner 1
$progFilesx86AclData = $progFilesx86AclData -replace "\(A;OICIIO;GA;;;SY\)", "" # System 1
$progFilesx86AclData = $progFilesx86AclData -replace "\(A;;0x1301bf;;;SY\)", "" # System 2
$progFilesx86AclData = $progFilesx86AclData -replace "\(A;OICIIO;GA;;;BA\)", "" # Built-In Administrators 1
$progFilesx86AclData = $progFilesx86AclData -replace "\(A;;0x1301bf;;;BA\)", "" # Built-In Administrators 2
$progFilesx86AclData = $progFilesx86AclData -replace "\(A;OICIIO;GXGR;;;BU\)", "" # Built-In Users 1
$progFilesx86AclData = $progFilesx86AclData -replace "\(A;;0x1200a9;;;BU\)", "" # Built-In Users 2
$progFilesx86AclData = $progFilesx86AclData -replace ("\(A;CIIO;GA;;;" + $trustedInstallerSID + "\)"), "" # Trusted Installer 1
$progFilesx86AclData = $progFilesx86AclData -replace ("\(A;;FA;;;" + $trustedInstallerSID + "\)"), "" # Trusted Installer 2
$progFilesx86AclData = $progFilesx86AclData -replace "\(A;;0x1200a9;;;S-1-15-2-1\)", "" # All Application Packages 1
$progFilesx86AclData = $progFilesx86AclData -replace "\(A;OICIIO;GXGR;;;S-1-15-2-1\)", "" # All Application Packages 2
$progFilesx86AclData = $progFilesx86AclData -replace "\(A;;0x1200a9;;;AC\)", "" # All Application Packages 3
$progFilesx86AclData = $progFilesx86AclData -replace "\(A;OICIIO;GXGR;;;AC\)", "" # All Application Packages 4

#if there's any additional permissions, mark as a finding
if($progFilesAclData.Length -eq 0 -and $progFilesx86AclData.Length -eq 0 -and $everyoneIncludesAnonymous -eq 0)
{
    RecordFindingStatus $ruleId  "pass"
}
else
{
	if($progFilesAclData.Length -gt 0)
	{
		SendToLog ("Additional (potentially insecure) ACL entries were found on $programFilesPath.  Suspect ACL Data: " + $progFilesAclData)
	}
	
	if($progFilesx86AclData.Length -gt 0)
	{
		SendToLog ("Additional (potentially insecure) ACL entries were found on $programFilesPath.  Suspect ACL Data: " + $progFilesx86AclData)
	}
	if($everyoneIncludesAnonymous -ne 0)
	{
		SendToLog ("The local security policy ""Network access: Let everyone permissions apply to anonymous users"" is not set correctly.  Found:  $everyoneIncludesAnonymous  Expected: 0")
	}
	
    RecordFindingStatus $ruleId  "fail"
}
Endcheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-52136
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52136r3_rule"

$everyoneIncludesAnonymous = GetRegistryKeyValue "System\CurrentControlSet\Control\Lsa\" "everyoneincludesanonymous"

$systemDriveAclData = (([System.IO.DirectoryInfo]($sysDrive + "\\")).GetAccessControl()).Sddl

# Remove Allowed permission strings
$trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

$systemDriveAclData = $systemDriveAclData -replace ("O:" + $trustedInstallerSID + "G:" + $trustedInstallerSID + "D:PAI"), "" # Ownership
$systemDriveAclData = $systemDriveAclData -replace "\(A;OICIIO;GA;;;CO\)", "" # Creator Owner 1
$systemDriveAclData = $systemDriveAclData -replace "\(A;OICI;FA;;;SY\)", "" # System 1
$systemDriveAclData = $systemDriveAclData -replace "\(A;OICI;FA;;;BA\)", "" # Built-In Administrators 1

$systemDriveAclData = $systemDriveAclData -replace "\(A;CI;LC;;;BU\)", "" # Built-In Users 1
$systemDriveAclData = $systemDriveAclData -replace "\(A;CIIO;DC;;;BU\)", "" # Built-In Users 2
$systemDriveAclData = $systemDriveAclData -replace "\(A;OICI;0x1200a9;;;BU\)", "" # Built-In Users 2

#if there's any additional permissions, mark as a finding
if($systemDriveAclData.Length -eq 0 -and $everyoneIncludesAnonymous -eq 0)
{
    RecordFindingStatus $ruleId  "pass"
}
else
{
	if($systemDriveAclData.Length -gt 0)
	{
		SendToLog ("Additional (potentially insecure) ACL entries were found on $sysDrive\   Suspect ACL Data: " + $systemDriveAclData)
	}
	
	if($everyoneIncludesAnonymous -ne 0)
	{
		SendToLog ("The local security policy ""Network access: Let everyone permissions apply to anonymous users"" is not set correctly.  Found:  $everyoneIncludesAnonymous  Expected: 0")
	}
	
    RecordFindingStatus $ruleId  "fail"
}
Endcheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-52137
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-52137r3_rule"

$everyoneIncludesAnonymous = GetRegistryKeyValue "System\CurrentControlSet\Control\Lsa\" "everyoneincludesanonymous"

$windowsPathAclData = (([System.IO.DirectoryInfo]($windowsPath)).GetAccessControl()).Sddl

# Remove Allowed permission strings
$trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

$windowsPathAclData = $windowsPathAclData -replace ("O:" + $trustedInstallerSID + "G:" + $trustedInstallerSID + "D:PAI"), "" # Ownership
$windowsPathAclData = $windowsPathAclData -replace "\(A;OICIIO;GA;;;CO\)", "" # Creator Owner 1
$windowsPathAclData = $windowsPathAclData -replace "\(A;OICIIO;GA;;;SY\)", "" # System 1
$windowsPathAclData = $windowsPathAclData -replace "\(A;;0x1301bf;;;SY\)", "" # System 2
$windowsPathAclData = $windowsPathAclData -replace "\(A;OICIIO;GA;;;BA\)", "" # Built-In Administrators 1
$windowsPathAclData = $windowsPathAclData -replace "\(A;;0x1301bf;;;BA\)", "" # Built-In Administrators 2
$windowsPathAclData = $windowsPathAclData -replace "\(A;OICIIO;GXGR;;;BU\)", "" # Built-In Users 1
$windowsPathAclData = $windowsPathAclData -replace "\(A;;0x1200a9;;;BU\)", "" # Built-In Users 2
$windowsPathAclData = $windowsPathAclData -replace ("\(A;CIIO;GA;;;" + $trustedInstallerSID + "\)"), "" # Trusted Installer 1
$windowsPathAclData = $windowsPathAclData -replace ("\(A;;FA;;;" + $trustedInstallerSID + "\)"), "" # Trusted Installer 2
$windowsPathAclData = $windowsPathAclData -replace "\(A;;0x1200a9;;;S-1-15-2-1\)", "" # All Application Packages 1
$windowsPathAclData = $windowsPathAclData -replace "\(A;OICIIO;GXGR;;;S-1-15-2-1\)", "" # All Application Packages 2
$windowsPathAclData = $windowsPathAclData -replace "\(A;;0x1200a9;;;AC\)", "" # All Application Packages 3
$windowsPathAclData = $windowsPathAclData -replace "\(A;OICIIO;GXGR;;;AC\)", "" # All Application Packages 4

#if there's any additional permissions, mark as a finding
if($windowsPathAclData.Length -eq 0 -and $everyoneIncludesAnonymous -eq 0)
{
    RecordFindingStatus $ruleId  "pass"
}
else
{
	if($windowsPathAclData.Length -gt 0)
	{
		SendToLog ("Additional (potentially insecure) ACL entries were found on $sysDrive\   Suspect ACL Data: " + $windowsPathAclData)
	}
	
	if($everyoneIncludesAnonymous -ne 0)
	{
		SendToLog ("The local security policy ""Network access: Let everyone permissions apply to anonymous users"" is not set correctly.  Found:  $everyoneIncludesAnonymous  Expected: 0")
	}
	
    RecordFindingStatus $ruleId  "fail"
}
Endcheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Rule SV-55085
#---------------------------------------------------------------------------------------------------------------------------------
BeginCheck "SV-55085r1_rule"
$isMcAfeeFWActive = GetRegistryKeyValue "Software\Wow6432Node\McAfee\HIP\Config\Settings\" "FW_Enabled"
$isWindowsFirewallActive = $false

if(Test-Path $psExecPath)
{
	Write-Host ("--------------------------------------------------------------------------")
	$currentFirewallProfileData = & $psExecPath -S \\$ServerNameToCheck netsh.exe advfirewall monitor show currentprofile
	Write-Host ("--------------------------------------------------------------------------")
	Write-Host ("")
	
	if($currentFirewallProfileData[1] -like "Domain Profile:*")
	{
		$a = GetRegistryKeyValue "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\" "EnableFirewall"
		$b = GetRegistryKeyValue "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\" "EnableFirewall"
		if($a -or $b)
		{
			$isWindowsFirewallActive = $true
		}
	}
	elseif($currentFirewallProfileData[1] -like "Public Profile:*")
	{
		$a = GetRegistryKeyValue "SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\" "EnableFirewall"
		$b = GetRegistryKeyValue "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\" "EnableFirewall"
		if($a -or $b)
		{
			$isWindowsFirewallActive = $true
		}
	}
	elseif($currentFirewallProfileData[1] -like "Private Profile:*")
	{
		$a = GetRegistryKeyValue "SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\" "EnableFirewall"
		$b = GetRegistryKeyValue "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\" "EnableFirewall"
		if($a -or $b)
		{
			$isWindowsFirewallActive = $true
		}
	}
	else
	{
		SendToLog("An unexpected result was returned from the remote netsh command.")
		SendToLog("As a result, the status of the Windows Firewall could not be determined.")
		SendToLog("")
		SendToLog("Raw Output Dump:")
		foreach($line in $currentFirewallProfileData)
		{
			SendToLog("    " + $line)
		}
	}	
}
else
{
	$isWindowsFirewallActive = $null
	SendToLog("PSExec.exe was not found in the expected location.  Path: $psExecPath")
	SendToLog("As a result, the status of the Windows Firewall could not be determined.")
}

if($isMcAfeeFWActive -or $isWindowsFirewallActive)
{
	RecordFindingStatus $ruleId "pass"
}
else
{
	SendToLog("An active, host based firewall solution could not be located on the target system.  Rule SV-55085 will require manual review.")
	
	
	RecordFindingStatus $ruleId "manual"
}
EndCheck
#---------------------------------------------------------------------------------------------------------------------------------
#endregion
#region Automatic Pass/Fail Rules
#---------------------------------------------------------------------------------------------------------------------------------
# List of rules that are known failures.
# As automated checks become necessary and/or available for these findings, they will be removed from this list.

$logFileIndent = "    "
$ruleId = "SV-72047r4_rule"
SendToLog ("Rule SV-72047r3 fails automatically due to known lack of AppLocker policy.")
RecordFindingStatus $ruleId  "fail"
$logFileIndent = ""
SendToLog("")
#---------------------------------------------------------------------------------------------------------------------------------
#endregion

#-------------------------------------------------------------------------------------
# END RULE CHECKS
#-------------------------------------------------------------------------------------

WriteResultFileFooter
}



If($m -eq 1)
{

$manualmode = Read-Host prompt("enter 1 to run manual fix registry, 2 for GPO policy fix")
if($manualmode -eq "1")
{
If($win -eq "True")
{
If($ver -eq "Windows Server 2012 R2")
{
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /f /v "AutoDownload" /t REG_DWORD /d 2 
}
ElseIf($ver -eq "Windows Server 2012")
{
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\WindowsUpdate" /f /v "AutoDownload" /t REG_DWORD /d 2
}
}
Else
{
"Skipped SV-51750r2_rule WN12-CC-000109 becuase winstore directory does not exist."
}

If($win -eq "True")
{
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /f /v "RemoveWindowsStore" /t REG_DWORD /d 1
}
Else
{
"Skipped SV-51750r2_rule WN12-CC-000109 becuase winstore directory does not exist."
}



"Does the system have windows media player installed."
$L = Read-Host -Prompt "y/n"
if($L -eq 'y')
{
reg add "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer" /f /v "DisableAutoupdate" /t REG_DWORD /d  1
}
else
{
"This check is NA"
}


#SV-51182r3_rule	
reg add "HKLM\System\CurrentControlSet\Services\W32Time\Config" /f /v "EventLogFlags" /t REG_DWORD /d 2
#SV-51596r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "InactivityTimeoutSecs" /t REG_DWORD /d 0x00000384
#SV-51605r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /f /v "EnableIPAutoConfigurationLimits" /t REG_DWORD /d 1
#SV-51606r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing" /f /v "UseWindowsUpdate" /t REG_DWORD /d 2
#SV-51607r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /f /v "DriverServerSelection" /t REG_DWORD /d 1
#SV-51608r1_rule	
reg add "HKLM\System\CurrentControlSet\Policies\EarlyLaunch" /f /v "DriverLoadPolicy" /t REG_DWORD /d 1
#SV-51609r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /f /v "NoUseStoreOpenWith" /t REG_DWORD /d 1
#SV-51610r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Control Panel\International" /f /v "BlockUserInputMethodsForSignIn" /t REG_DWORD /d 1
#SV-51611r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /f /v "EnumerateLocalUsers" /t REG_DWORD /d 0
#SV-51612r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /f /v "DisableLockScreenAppNotifications" /t REG_DWORD /d 1
#SV-51737r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /f /v "DisablePcaUI" /t REG_DWORD /d 0
#SV-51738r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Appx" /f /v "AllowAllTrustedApps" /t REG_DWORD /d 1
#SV-51739r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Biometrics" /f /v "Enabled" /t REG_DWORD /d 0
#SV-51740r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\CredUIs" /f /v "DisablePasswordReveal" /t REG_DWORD /d 1
#SV-51747r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /f /v "EnableSmartScreen" /t REG_DWORD /d 0
#SV-51748r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /f /v "DisableLocation" /t REG_DWORD /d 1
#SV-51749r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds" /f /v "AllowBasicAuthInClear" /t REG_DWORD /d 0
#SV-51752r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" /f /v "AllowBasic" /t REG_DWORD /d 0
#SV-51753r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" /f /v "AllowUnencryptedTraffic" /t REG_DWORD /d 0
#SV-51754r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" /f /v "AllowDigest" /t REG_DWORD /d 0
#SV-51755r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" /f /v "AllowBasic" /t REG_DWORD /d 0
#SV-51756r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" /f /v "AllowUnencryptedTraffic" /t REG_DWORD /d 0
#SV-51757r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" /f /v "DisableRunAs" /t REG_DWORD /d 1
#SV-51758r2_rule	
reg add "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /f /v "ScreenSaveActive" /t REG_SZ /d 1
#SV-51760r1_rule	
reg add "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /f /v "ScreenSaverIsSecure" /t REG_SZ /d 1
#SV-51762r1_rule	
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /f /v "NoCloudApplicationNotification" /t REG_DWORD /d 1
#SV-51763r1_rule	
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /f /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d 1
#SV-52107r2_rule	
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /f /v "AutoAdminLogon" /t REG_SZ /d 0
#SV-52163r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "RedirectOnlyDefaultClientPrinter" /t REG_DWORD /d 1
#SV-52214r2_rule	
reg add "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /f /v "AddPrinterDrivers" /t REG_DWORD /d 1
#SV-52216r2_rule	
reg add "HKLMftware\Policies\Microsoft\Windows NT\Terminal Services" /f /v "fSingleSessionPerUser" /t REG_DWORD /d 1
#SV-52219r2_rule	
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Subsystems" /f /v "Optional" /t REG_MULTI_SZ /d 
#SV-52223r2_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "EnableUIADesktopToggle" /t REG_DWORD /d 0
#SV-52224r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "fDisableCcm" /t REG_DWORD /d 1
#SV-52226r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "fDisableLPT" /t REG_DWORD /d 1
#SV-52229r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "fDisablePNPRedir" /t REG_DWORD /d 1
#SV-52230r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "fEnableSmartCard" /t REG_DWORD /d 1
#SV-52840r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "ShutdownWithoutLogon" /t REG_DWORD /d 0
#SV-52845r3_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "LegalNoticeText" /t REG_SZ /d "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS.-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants.  Such communications and work product are private and confidential.  See User Agreement for details."
#SV-52846r2_rule
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /f /v "CachedLogonsCount" /t REG_SZ /d 4
#SV-52847r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /f /v "RestrictAnonymous" /t REG_DWORD /d 1
#SV-52860r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /f /v "EnableForcedLogoff" /t REG_DWORD /d 1
#SV-52861r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /f /v "EnablePlainTextPassword" /t REG_DWORD /d 0
#SV-52865r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /f /v "LmCompatibilityLevel" /t REG_DWORD /d 5
#SV-52866r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "DisableCAD" /t REG_DWORD /d 0
#SV-52867r2_rule	
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /f /v "SCRemoveOption" /t REG_SZ /d 2
#SV-52870r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /f /v "EnableSecuritySignature" /t REG_DWORD /d 1
#SV-52871r3_rule	
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /f /v "SealSecureChannel" /t REG_DWORD /d 1
#SV-52872r3_rule	
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /f /v "SignSecureChannel" /t REG_DWORD /d 1
#SV-52873r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /f /v "DisablePasswordChange" /t REG_DWORD /d 0
#SV-52874r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /f /v "EnableSecuritySignature" /t REG_DWORD /d 1
#SV-52875r1_rule	
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /f /v "AllocateDASD" /t REG_SZ /d 0
#SV-52876r1_rule	
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /f /v "PasswordExpiryWarning" /t REG_DWORD /d 14
#SV-52877r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /f /v "ProtectionMode" /t REG_DWORD /d 1
#SV-52878r3_rule	
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /f /v "autodisconnect" /t REG_DWORD /d 0x0000000f
#SV-52879r2_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\policies\Explorer" /f /v "NoDriveTypeAutoRun" /t REG_DWORD /d 0x000000ff
#SV-52883r2_rule	
reg add "HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPathsr" /f /v "Machine" /t REG_MULTI_SZ /d "System\CurrentControlSet\Control\ProductOptions" \0 "System\CurrentControlSet\Control\Server Applications" \0 "Software\Microsoft\Windows NT\CurrentVersion"  
#SV-52884r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /f /v "NullSessionShares" /t REG_MULTI_SZ /d 
#SV-52885r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "fAllowToGetHelp" /t REG_DWORD /d 0
#SV-52886r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /f /v "LimitBlankPasswordUse" /t REG_DWORD /d 1
#SV-52887r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /f /v "MaximumPasswordAge" /t REG_DWORD /d 30
#SV-52888r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /f /v "RequireStrongKey" /t REG_DWORD /d 1
#SV-52889r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /f /v "DisableDomainCreds" /t REG_DWORD /d 1
#SV-52890r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /f /v "EveryoneIncludesAnonymous" /t REG_DWORD /d 0
#SV-52891r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /f /v "ForceGuest" /t REG_DWORD /d 0
#SV-52892r2_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /f /v "NoLMHash" /t REG_DWORD /d 1
#SV-52894r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\LDAP" /f /v "LDAPClientIntegrity" /t REG_DWORD /d 1
#SV-52895r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /f /v "NTLMMinClientSec" /t REG_DWORD /d 0x20080000
#SV-52896r2_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" /f /v "Enabled" /t REG_DWORD /d 1
#SV-52897r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Kernel" /f /v "ObCaseInsensitive" /t REG_DWORD /d 1
#SV-52898r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "fPromptForPassword" /t REG_DWORD /d 1
#SV-52899r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "MinEncryptionLevel" /t REG_DWORD /d 3
#SV-52900r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "PerSessionTempDir" /t REG_DWORD /d 1
#SV-52901r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "DeleteTempDirsOnExit" /t REG_DWORD /d 1
#SV-52906r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\system" /f /v "DisableBkGndGroupPolicy" /t REG_DWORD /d 0
#SV-52917r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "fAllowUnsolicited" /t REG_DWORD /d 0
#SV-52920r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /f /v "SafeDllSearchMode" /t REG_DWORD /d 1
#SV-52921r1_rule	
reg add "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer" /f /v "PreventCodecDownload" /t REG_DWORD /d 1
#SV-52922r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /f /v "NTLMMinServerSec" /t REG_DWORD /d 0x20080000
#SV-52923r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\Eventlog\Security" /f /v "WarningLevel" /t REG_DWORD /d 90
#SV-52924r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\Eventlog\Security" /f /v "DisableIPSourceRouting" /t REG_DWORD /d 2
#SV-52925r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\Eventlog\Security" /f /v "EnableICMPRedirect" /t REG_DWORD /d 0
#SV-52926r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /f /v "PerformRouterDiscovery" /t REG_DWORD /d 0
#SV-52927r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /f /v "KeepAliveTime" /t REG_DWORD /d 300000
#SV-52928r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\Netbt\Parameters" /f /v "NoNameReleaseOnDemand" /t REG_DWORD /d 1
#SV-52929r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /f /v "TcpMaxDataRetransmissions" /t REG_DWORD /d 3
#SV-52930r1_rule	
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /f /v "ScreenSaverGracePeriod" /t REG_SZ /d 5
#SV-52931r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /f /v "NoGPOListChanges" /t REG_DWORD /d 0
#SV-52931r2_rule	
reg add "HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" /f /v "Machine" /t REG_MULTI_SZ /d "Software\Microsoft\OLAP Server" \0 "Software\Microsoft\Windows NT\CurrentVersion\Perflib" \0 "Software\Microsoft\Windows NT\CurrentVersion\Print" \0 "Software\Microsoft\Windows NT\CurrentVersion\Windows" \0 "System\CurrentControlSet\Control\ContentIndex" \0 "System\CurrentControlSet\Control\Print\Printers" \0 "System\CurrentControlSet\Control\Terminal Server" \0 "System\CurrentControlSet\Control\Terminal Server\UserConfig" \0 "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration" \0 "System\CurrentControlSet\Services\Eventlog" \0 "System\CurrentControlSet\Services\Sysmonlog" \0
#SV-52932r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "fEncryptRPCTraffic" /t REG_DWORD /d 1
#SV-52934r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /f /v "RequireSignOrSeal" /t REG_DWORD /d 1
#SV-52935r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /f /v "RequireSecuritySignature" /t REG_DWORD /d 1
#SV-52936r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /f /v "RequireSecuritySignature" /t REG_DWORD /d 1
#SV-52937r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /f /v "RestrictNullSessAccess" /t REG_DWORD /d 1
#SV-52941r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "DontDisplayLastUserName" /t REG_DWORD /d 1
#SV-52943r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /f /v "FullPrivilegeAuditing" /t REG_BINARY /d 0
#SV-52944r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /f /v "SCENoApplyLegacyAuditPolicy" /t REG_DWORD /d 1
#SV-52945r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\IPSEC" /f /v "NoDefaultExempt" /t REG_DWORD /d 3
#SV-52946r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "FilterAdministratorToken" /t REG_DWORD /d 1
#SV-52947r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 3
#SV-52948r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "ConsentPromptBehaviorUser" /t REG_DWORD /d 0
#SV-52949r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "EnableInstallerDetection" /t REG_DWORD /d 1
#SV-52950r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "EnableSecureUIAPaths" /t REG_DWORD /d 1
#SV-52951r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "EnableLUA" /t REG_DWORD /d 1
#SV-52952r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "PromptOnSecureDesktop" /t REG_DWORD /d 1
#SV-52953r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "EnableVirtualization" /t REG_DWORD /d 1
#SV-52954r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer" /f /v "AlwaysInstallElevated" /t REG_DWORD /d 0
#SV-52955r2_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" /f /v "EnumerateAdministrators" /t REG_DWORD /d 0x00000000
#SV-52958r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "DisablePasswordSaving" /t REG_DWORD /d 1
#SV-52959r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "fDisableCdm" /t REG_DWORD /d 1
#SV-52962r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" /f /v "DisableSendRequestAdditionalSoftwareToWER" /t REG_DWORD /d 1

"Does the system write events to an audit server."
$L = Read-Host -Prompt "y/n"
if($L -eq 'y')
{
#SV-52963r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\System" /f /v "MaxSize" /t REG_DWORD /d  0x00008000
#SV-52964r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\Setup" /f /v "MaxSize" /t REG_DWORD /d  0x00008000
#SV-52965r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" /f /v "MaxSize" /t REG_DWORD /d  0x00030000
#SV-52966r2_rule	
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" /f /v "MaxSize" /t REG_DWORD /d  0x00008000
}
else
{
"This check is NA"
}

#SV-52967r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /f /v "Teredo_State" /t REG_SZ /d "Disabled"
#SV-52968r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /f /v "ISATAP_State" /t REG_SZ /d "Disabled"
#SV-52969r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface" /f /v "IPHTTPS_ClientState" /t REG_DWORD /d 3
#SV-52970r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /f /v "6to4_State" /t REG_SZ /d "Disabled"
#SV-52997r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /f /v "DisableHTTPPrinting" /t REG_DWORD /d 1
#SV-52998r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /f /v "DisableWebPnPDownload" /t REG_DWORD /d 1
#SV-53000r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /f /v "DontSearchWindowsUpdate" /t REG_DWORD /d 1
#SV-53002r1_rule	
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /f /v "SaveZoneInformation" /t REG_DWORD /d 2
#SV-53004r1_rule	
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /f /v "HideZoneInfoOnProperties" /t REG_DWORD /d 1
#SV-53006r1_rule	
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /f /v "ScanWithAntiVirus" /t REG_DWORD /d 3
#SV-53012r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Peernet" /f /v "Disabled" /t REG_DWORD /d 1
#SV-53014r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Network Connections" /f /v "NC_AllowNetBridge_NLA" /t REG_DWORD /d 0
#SV-53017r1_rule	
reg add "HKLM\Software\Policies\Microsoft\EventViewer" /f /v "MicrosoftEventVwrDisableLinks" /t REG_DWORD /d 1
#SV-53021r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f /v "NoInternetOpenWith" /t REG_DWORD /d 1
#SV-53040r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds" /f /v "DisableEnclosureDownload" /t REG_DWORD /d 1
#SV-53045r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f /v "PreXPSP2ShellProtocolBehavior" /t REG_DWORD /d 0
#SV-53056r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer" /f /v "SafeForScripting" /t REG_DWORD /d 0
#SV-53061r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer" /f /v "EnableUserControl" /t REG_DWORD /d 0
#SV-53065r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Installer" /f /v "DisableLUAPatching" /t REG_DWORD /d 1
#SV-53069r1_rule	
reg add "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer" /f /v "GroupPrivacyAcceptance" /t REG_DWORD /d 

#SV-53072r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD" /f /v "AllowLLTDIOOndomain" /t REG_DWORD /d 0
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD" /f /v "AllowLLTDIOOnPublicNet" /t REG_DWORD /d 0
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD" /f /v "EnableLLTDIO" /t REG_DWORD /d 0
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD" /f /v "ProhibitLLTDIOOnPrivateNet" /t REG_DWORD /d 0

#SV-53081r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD" /f /v "AllowRspndrOndomain" /t REG_DWORD /d 0
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD" /f /v "AllowRspndrOnPublicNet" /t REG_DWORD /d 0
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD" /f /v "EnableRspndr" /t REG_DWORD /d 0
reg add "HKLM\Software\Policies\Microsoft\Windows\LLTD" /f /v "ProhibitRspndrOnPrivateNet" /t REG_DWORD /d 0

#SV-53085r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars" /f /v "DisableFlashConfigRegistrar" /t REG_DWORD /d 0
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars" /f /v "DisableInBand802DOT11Registrar" /t REG_DWORD /d 0
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars" /f /v "DisableUPnPRegistrar" /t REG_DWORD /d 0
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars" /f /v "DisableWPDRegistrar" /t REG_DWORD /d 0
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars" /f /v "EnableRegistrars" /t REG_DWORD /d 0

#SV-53089r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\UI" /f /v "DisableWcnUi" /t REG_DWORD /d 1
#SV-53094r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" /f /v "AllowRemoteRPC" /t REG_DWORD /d 0
#SV-53099r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" /f /v "DisableSystemRestore" /t REG_DWORD /d 0
#SV-53105r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" /f /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d 1
#SV-53115r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /f /v "DontPromptForWindowsUpdate" /t REG_DWORD /d 1
#SV-53116r1_rule
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /f /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1
#SV-53121r2_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "LegalNoticeCaption" /t REG_SZ /d "DoD Notice and Consent Banner"
#SV-53122r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /f /v "RestrictAnonymousSAM" /t REG_DWORD /d 1
#SV-53124r2_rule	
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f /v "NoAutorun" /t REG_DWORD /d 1
#SV-53125r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /f /v "NoDataExecutionPrevention" /t REG_DWORD /d 0
#SV-53126r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /f /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1
#SV-53127r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /f /v "DisableInventory" /t REG_DWORD /d 1
#SV-53128r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /f /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0
#SV-53129r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /f /v "AuditBaseObjects" /t REG_DWORD /d 0
#SV-53130r1_rule	
reg add "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer" /f /v "DisableAutoupdate" /t REG_DWORD /d  1
#SV-53131r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /f /v "DCSettingIndex" /t REG_DWORD /d  1
#SV-53132r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /f /v "ACSettingIndex" /t REG_DWORD /d  1
#SV-53133r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /f /v "LoggingEnabled" /t REG_DWORD /d 1

#SV-53134r2_rule	
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet" /f /v "SpyNetReporting" /t REG_DWORD /d 1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet" /f /v "SpyNetReporting" /t REG_DWORD /d 2

#SV-53137r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /f /v "NoHeapTerminationOnCorruption" /t REG_DWORD /d 0
#SV-53139r1_rule	
reg add "HKLM\Software\Policies\Microsoft\WMDRM" /f /v "DisableOnline" /t REG_DWORD /d 1
#SV-53140r2_rule	
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f /v "NoInPlaceSharing" /t REG_DWORD /d 1
#SV-53142r1_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "ValidateAdminCodeSignatures" /t REG_DWORD /d 0
#SV-53143r1_rule	
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /f /v "CEIPEnable" /t REG_DWORD /d 0
#SV-53144r1_rule	
reg add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /f /v "NoImplicitFeedback" /t REG_DWORD /d 1
#SV-53145r1_rule	
reg add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /f /v "NoExplicitFeedback" /t REG_DWORD /d 1
#SV-53175r1_rule	
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /f /v "SmbServerNameHardeningLevel" /t REG_DWORD /d 0
#SV-53176r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\LSA" /f /v "UseMachineId" /t REG_DWORD /d 1
#SV-53177r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\LSA\MSV1_0" /f /v "allownullsessionfallback" /t REG_DWORD /d 0
#SV-53178r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\LSA\pku2u" /f /v "AllowOnlineID" /t REG_DWORD /d 0
#SV-53179r2_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /f /v "SupportedEncryptionTypes" /t REG_DWORD /d 0
#SV-53180r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /f /v "DisableIPSourceRouting" /t REG_DWORD /d 2
#SV-53181r2_rule
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /f /v "TcpMaxDataRetransmissions" /t REG_DWORD /d 3
#SV-53182r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Network Connections" /f /v "NC_StdDomainUserSetLocation" /t REG_DWORD /d 1
#SV-53183r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /f /v "Force_Tunneling" /t REG_SZ /d "Enabled"
#SV-53184r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /f /v "DoNotInstallCompatibleDriverFromWindowsUpdate" /t REG_DWORD /d 1
#SV-53185r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Device Metadata" /f /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1
#SV-53186r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /f /v "SearchOrderConfig" /t REG_DWORD /d 0
#SV-53187r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /f /v "DisableQueryRemoteServer" /t REG_DWORD /d 0
#SV-53188r1_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /f /v "EnableQueryRemoteServer" /t REG_DWORD /d 0
#SV-56343r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /f /v "NoLockScreenSlideshow" /t REG_DWORD /d 1
#SV-56344r3_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /f /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d 0x00000001
#SV-56346r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /f /v "DontDisplayNetworkSelectionUI" /t REG_DWORD /d 1
#SV-56353r2_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies" /f /v "MSAOptional" /t REG_DWORD /d 1
#SV-56355r2_rule	
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d 1
#SV-72049r2_rule	
reg add "HKLM\Software\Policies\Microsoft\Cryptography" /f /v "ForceKeyProtection" /t REG_DWORD /d 2
#SV-87391r1_rule	
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\Wdigest" /f /v "UseLogonCredential" /t REG_DWORD /d 0x00000000
#SV-88193r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /f /v "SMB1" /t REG_DWORD /d 0x00000000

#SV-88205r2_rule	
reg add "HKLM\System\CurrentControlSet\Services\mrxsmb10" /f /v "Start" /t REG_DWORD /d 0x00000004
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation" /f /v "DependOnService" /t REG_MULTI_SZ /d "Bowser" \0 "MRxSmb20" \0 "NSI"
} 


elseif($manualmode -eq "2")
{
import-module grouppolicy

[string]$PathToCompressedGPOs = Read-Host prompt("enter the file path to the GPO objects downloaded or that came whit this package.")
[string]$DestinationToCompressedGPOs = Read-Host prompt("enter the path to place the extracted GPO objects")
New-Item -ItemType Directory -Force -Path $PathToCompressedGPOs
$t = Test-Path -LiteralPath $DestinationToCompressedGPOs
if($t = True)
{
Expand-Archive -LiteralPath $PathToCompressedGPOs -DestinationPath $DestinationToCompressedGPOs 
}
else
{
"path does not exist"
exit
}

#New-GPO -Name RMFGPO -comment "This a shell gpo to import the DISA GPO policies."

#New-GPO -Name RMFGPO -StarterGPOName "RMF GPO Policies"   

#import-gpo -BackupGpoName  -TargetName RMFGPO -path c:\backups

import-gpo -BackupGpoName Backup -TargetName RMFGPO1 -LiteralPath $DestinationToCompressedGPOs+"\DoD Windows Server 2012 R2 MS and DC v2r10\GPOs\{2CDA29CA-43B3-4750-8395-E505E96803C2}" -CreateIfNeeded

import-gpo -BackupGpoName Backup  -TargetName RMFGPO2 -LiteralPath $DestinationToCompressedGPOs+"\DoD Windows Server 2012 R2 MS and DC v2r10\GPOs\{A040821A-58DA-4ED9-B1B2-38880518EF7A}" -CreateIfNeeded

import-gpo -BackupGpoName Backup  -TargetName RMFGPO3 -LiteralPath $DestinationToCompressedGPOs+"\DoD Windows Server 2012 R2 MS and DC v2r10\GPOs\{B7556BB5-798B-4978-A46B-0833CE815328}" -CreateIfNeeded

import-gpo -BackupGpoName Backup  -TargetName RMFGPO4 -LiteralPath $DestinationToCompressedGPOs+"\DoD Windows Server 2012 R2 MS and DC v2r10\GPOs\{C9A0A68E-3552-4E6B-9EC2-74732B182D04}" -CreateIfNeeded

Invoke-GPUpdate

"you are ready to scan with checker and scap"



}













}




