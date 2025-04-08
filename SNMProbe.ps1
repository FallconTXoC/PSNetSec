[CmdletBinding()]
param (
    [Alias("i")]
    [Parameter(Mandatory=$true)]
    [string]$InputFile,

    [Alias("o")]
    [Parameter(Mandatory=$true)]
    [string]$OutputFile,

    [Alias("e")]
    [Parameter(Mandatory=$false)]
    [switch]$EncryptFile,

    [Alias("c")]
    [Parameter(Mandatory=$false)]
    [switch]$CustomKey,

    [Alias("h")]
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

function Show-Help {
    @"
NAME
    SNMProbe.ps1

SYNOPSIS
    A script that performs SNMP requests to a list of devices to gather basic information using multithreading and saves the results in a JSON file.
    Requires ThreadJob and Powershell-YAML modules. /!\ COMMUNITIES SHOULD BE DIFFERENT FOR EACH VENDOR /!\

SYNTAX
    .\SNMProbe.ps1 [-t <target>] [-i <input file>] [-o <output file>] [-e] [-c] [-h]

DESCRIPTION
    This script accepts the following arguments:
        - '-i' (aka input file) which accepts a string representing a csv file path to read ip addresses from. CSV file should be a result of GhostPulse or follow the same output file pattern.
        - '-o' (aka output file) which accepts a string representing a file path to write the results to. Results are in JSON format.
        - '-e' (aka encrypt) which encrypts the output file using AES encryption. If running on PowerShell 5, uses CBC encryption. If running on PowerShell 7, uses GCM encryption.
        - '-c' (aka custom key) which allows to provide a custom key for encryption up to 512 bits. (Only available on PowerShell 7)
        - '-h' (aka help) which displays this help message.

PARAMETERS
    -i <input file>
        The file path to read ip addresses from. CSV file should be a result of GhostPulse or follow the same output file pattern.
    -o <output file>
        The file path to write the results to. Results are in JSON format.
    -e
        Encrypts the output file using AES encryption. If running on PowerShell 5, uses CBC encryption. If running on PowerShell 7, uses GCM encryption.
    -c
        Allows to provide a custom key for encryption up to 512 bits. (Only available on PowerShell 7)
    -h
        Displays this help message.

EXAMPLES
        .\SNMProbe.ps1 -i "input.csv" -o "output.json"
        .\SNMProbe.ps1 -i "input.csv" -o "output.json" -e -c

"@
}

<#
    Logs messages to a file.
    @param [string] $origin  - Origin of the message
    @param [string] $message - Message to log
#>
function LogMessage {
	param(
		[Parameter()][string]$origin,
		[Parameter()][string]$message,
		[Parameter()][string]$type = "info"
	)
	
	$currDate = Get-Date -Format "yyyy-MM-dd"
	$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

	if($message.GetType() -eq [PSCustomObject]) {
		$message = $message.Message
	}

	switch($type) {
		"warning" {
			$message = "[Warning] $message"
			break
		}
		"error" {
			$message = "[Error] $message"
			Write-Host "An error occured, please check logs."
			break
		}
		default {
			$message = $message
		}
	}

	$errLog = "$PSScriptRoot\logs\SNMProbe_$currDate.log"
	if (-Not (Test-Path $errLog -PathType Leaf)) {
		New-Item -Path $errLog -ItemType File
	}

	$errLogContent = Get-Content $errLog
	$errLogContent += "[$timestamp] [$origin]: $message`n"
	$errLogContent | Out-File $errLog
}

<#
    Loads a module from a given path.
    @param [string] $module - Name of the module to load
    @param [string] $path   - Path to the module
    @param [bool]   $psd1   - Whether the module is a .psd1 or a .psm1
#>
function LoadModule {
	param(
		[Parameter()][string]$module,
		[Parameter()][string]$path,
		[Parameter()][bool]$psd1 = $true
	)

    $moduleFile = if($psd1) { "$path\$module.psd1" } else { "$path\$module.psm1" }

	try {
		if (Get-Module -Name $module -ErrorAction SilentlyContinue) {
			Remove-Module -Name $module # Allows to update the module in case of changes
		}
		
		Import-Module $moduleFile -ErrorAction Stop

		return $moduleFile
	} catch {
		throw "Error while loading module $module : $($_.Exception.Message)"
	}
}

<#
    Reads a YAML configuration file and returns its content.
    @param [string] $ConfigPath - Path to the YAML configuration file
    @return [object] - Content of the YAML configuration file
#>
function Get-YamlConfig {
    [CmdletBinding()]
    param (
        [string]$ConfigPath = "config.yml"
    )

    $yamlContent = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Yaml

    return $yamlContent
}


try {
    $UpdaterModule = LoadModule "SNMPLib" "$PSScriptRoot\libs"
    LoadModule "SecurityLib" "$PSScriptRoot\libs"

    try {
        Import-Module powershell-yaml
    } catch {
        Throw "Powershell-yaml is required but has not been detected."
    }

} catch {
	LogMessage "Module load" $_.Exception.Message "error"
	exit
}

# ---------------------- Initial Configuration ---------------------- #

$knownDevices_f = "$PSScriptRoot/config/known-devices.csv"
$snmpoids_f = "$PSScriptRoot/config/snmp-oids.yml"

if($InputFile) {
    $scoutResults_f = $InputFile
} else {
    throw "Input file not provided"
}

if($OutputFile) {
    $devicesSNMPData_f = $OutputFile
} else {
    throw "Output file not provided"
}

try {
    $knownDevices = Read-CSVFileToHashtable $knownDevices_f
	$scoutResults_raw = Read-CSVFileToHashtable $scoutResults_f
} catch {
    throw "Error while reading configuration files"
}

try {
    $scoutResults = @{}
    $scoutResults_raw.GetEnumerator() | Where-Object { $_.Value.STATUS -eq "Up" } | ForEach-Object {
        $scoutResults[$_.Key] = $_.Value
    }
} catch {
    throw "Error while reading Scout results"
}

try {
    $snmpoids = Get-YamlConfig -ConfigPath $snmpoids_f
} catch {
    throw "Error while reading OIDs"
}

$devicesSNMPData = @{}

# ---------------------- Runspaces (parallel computing) ---------------------- #

# Creating an initial session state and importing modules
$iss = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()

$modules = @($UpdaterModule)
foreach($module in $modules) {
	[void]$iss.ImportPSModule($module)
}

# Creating a runspace pool
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, [int]$env:NUMBER_OF_PROCESSORS, $iss, $host)
$RunspacePool.ApartmentState = "MTA"
$RunspacePool.Open()
$Runspaces = $results = @()

# Event handler to close runspaces when aborting script
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
	$RunspacePool.Close()
    $RunspacePool.Dispose()
}

# ------------------------- Scriptblocks definition ------------------------- #

$ProcessSNMP = {
	param (
		[Parameter()][string]$ip,
		[Parameter()][object]$knownDevices,
		[Parameter()][object]$snmpoids
	)

    $snmpData = Get-SNMPData $ip $knownDevices $snmpoids

    return [PSCustomObject]@{
        IP = $ip
        SNMPData = $snmpData
    }
}

# --------------------------------------------------------------------------- #

# Running runspaces
foreach ($ip in $scoutResults.GetEnumerator()) {
    $runspace = [PowerShell]::Create($iss)
	$null = $runspace.AddScript($ProcessSNMP)
	
	$null = $runspace.AddParameter('ip', $ip.Name)
	$null = $runspace.AddParameter('knownDevices', $knownDevices)
    $null = $runspace.AddParameter('snmpoids', $snmpoids)
	
	$runspace.RunspacePool = $RunspacePool
	
	$Runspaces += [PSCustomObject]@{
		Pipe = $runspace
		Status = $runspace.BeginInvoke()
	}
}

# Waiting for runspaces to complete
$completedRunspacesCount = 0
$totalRunspaces = $($Runspaces.Count)

while($completedRunspacesCount -lt $totalRunspaces) {
	Start-Sleep -Seconds 5

	Clear-Host

	$runspacesData = Get-Runspace | Where-Object {($_.id -ne 1) -and ($_.RunspaceIsRemote -eq $false) -and ($_.RunspaceAvailability -ne "Available")}

	foreach($runspaceData in $runspacesData) {
		Write-Host "Runspace $($runspaceData.Id) : $($runspaceData.RunspaceAvailability)"
	}

	$completedRunspaces = $Runspaces | Where-Object { $_.Status.IsCompleted -eq $true }
    $completedRunspacesCount = $(($Runspaces | Where-Object { $_.Status.IsCompleted -eq $true }).Count)

	Write-Host "Total runspaces : $totalRunspaces"
	Write-Host "Completed runspaces : $(($Runspaces | Where-Object { $_.Status.IsCompleted -eq $true }).Count)"

	foreach($runspace in $completedRunspaces) {
        try {
		    $results += $runspace.Pipe.EndInvoke($runspace.Status)
		    $runspace.Status = $null
        } catch {
            Write-Host "An error occured while fetching SNMP data :"
            Write-Host $_
            continue
        }
	}
}

# Closing and disposing the runspace pool
$RunspacePool.Close()
$RunspacePool.Dispose()

# Viewing results
foreach($result in $results) {
	$devicesSNMPData[$result.IP] = $result.SNMPData
}

$devicesSNMPData | ConvertTo-Json | Out-File -FilePath $devicesSNMPData_f

if($EncryptFile) {
    # If running on PowerShell 5, use CBC encryption
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        $key = New-AesKeyCBC

        Write-Host "Please copy the encryption key to a safe place:"
        Write-Host "$key"
        Read-Host -Prompt "Press any key to continue" | Out-Null
        
        Clear-Host

        $encryptedString = Protect-TextCBC $key $devicesSNMPData_f
        $fileData = "PS5`n" + $encryptedString
        $fileData | Out-File -FilePath $devicesSNMPData_f
    }
    # If running on PowerShell 7, use GCM encryption
    elseif ($PSVersionTable.PSVersion.Major -eq 7) {
        if($CustomKey) {
            while($true) {
                $key = Read-SecureBase64Key
    
                # Check key length
                $keyLength = $(Convert-SecureStringToBytes $SecureKey).Length
                if ($keyLength -notin @(16, 24, 32, 64)) {
                    Write-Host "Error: Key must be 128-bit (16 bytes), 192-bit (24 bytes), 256-bit (32 bytes), or 512-bit (64 bytes)."
                    continue
                } else {
                    break
                }
            }
        } else {
            $keys = New-AesKey -Length 32
            $key = $keys[0]
        
            Write-Host "Please copy the encryption key to a safe place:"
            Write-Host "$key"
            Read-Host -Prompt "Press any key to continue" | Out-Null
            
            Clear-Host
        
            $key = $keys[1]
        }
    
    
        $encryptedString = Protect-Text $key $devicesSNMPData_f
        $fileData = "PS7`n" + $encryptedString
        $fileData | Out-File -FilePath $devicesSNMPData_f    
    } else {
        Write-Host "Running on an unsupported version of PowerShell for encryption."
    }
}