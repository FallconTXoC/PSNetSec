[CmdletBinding()]
param (
    [Alias("t")]
    [Parameter(Mandatory=$false)]
    [string]$Target,

    [Alias("i")]
    [Parameter(Mandatory=$false)]
    [string]$InputFile,

    [Alias("csv")]
    [Parameter(Mandatory=$false)]
    [switch]$CSVInput,

    [Alias("csvcol")]
    [Parameter(Mandatory=$false)]
    [string]$CSVColumn,

    [Alias("o")]
    [Parameter(Mandatory=$false)]
    [string]$OutputFile,

    [Alias("up")]
    [Parameter(Mandatory=$false)]
    [switch]$UpOnly,

    [Alias("v")]
    [Parameter(Mandatory=$false)]
    [switch]$ExtraVerbose,

    [Alias("h")]
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

try {
    Import-Module -Name "$PSScriptRoot\libs\GhostPulseLib.psd1"
} catch {
    throw "Error while loading module GhostPulseLib"
}

if (-not (Get-Module -Name ThreadJob -ListAvailable)) {
    throw "ThreadJob module is required to run this script. Please install it before running the script."
}

function Show-Help {
    @"
NAME
    GhostPulse.ps1

SYNOPSIS
    A script that performs network ICMP scanning to detect devices. It will automatically switch to a "master" mode if an input file is provided and distribute the scanning among multiple threads. Requires ThreadJob package.

SYNTAX
    .\GhostPulse.ps1 [-t <target>] [-i <input file>] [-o <output file>] [-up] [-h]

DESCRIPTION
    This script accepts the following arguments:
        - '-t' (aka target) which accepts a string representing a network IP with its mask (e.g., '192.168.3.0/25'). | MANDATORY if -i is not provided
        - '-i' (aka input file) which accepts a string representing a file path to read network addresses from. Addresses should be separated by a semicolon (;). | MANDATORY if -t is not provided
        - '-csv' specifies that the input file is in CSV format. | OPTIONAL
        - '-csvcol' specifies the column name in the CSV file that contains the CIDRs. | MANDATORY if -csv is provided
        - '-o' (aka output file) which accepts a string representing a file path to write the results to. Results are in CSV format (IP, STATUS). | OPTIONAL
        - '-up' specifies that only devices that are up should be included in the output. | OPTIONAL
        - '-v' (aka verbose) which specifies that the script should run in verbose mode. | OPTIONAL
        - '-h' (aka help) which displays this help message.

PARAMETERS
    -t <target>
        The target network IP with its mask (e.g., '192.168.3.0/25'). This parameter is mandatory if input file is not provided.
    -i <input file>
        The file path to read network addresses from. Addresses should be separated by a semicolon (;). This parameter is mandatory if target is not provided.
    -csv
        Specifies that the input file is in CSV format. This parameter is optional.
    -csvcol <column name>
        Specifies the column name in the CSV file that contains the CIDRs. This parameter is mandatory if CSV is provided.
    -o <output file>
        The file path to write the results to. Results are in CSV format (IP, STATUS). This parameter is recommended if you provide an input file.
    -up
        Specifies that only devices that are up should be included in the output. This parameter is optional.
    -v
        Specifies that the script should run in verbose mode. This parameter is optional.
    -h
        Displays this help message.

EXAMPLES
        .\GhostPulse.ps1 -i "input.txt" -o "output.csv" -up
        .\GhostPulse.ps1 -t 192.168.3.0/25 -v

"@
}

<#
    .SYNOPSIS
        Main function of the script used when targets file is provided. It will run the network scanning process and save the results to a CSV file.
    .DESCRIPTION
        This function will read the input file or target, distribute the scanning among multiple threads, and gather the results to create the final output CSV file.
    .EXAMPLE
        Main
#>
function Main {
    if($Target) {
        Write-Host "Target: $Target" -ForegroundColor DarkBlue
    }
    elseif($InputFile) {
        Write-Host "Input File: $InputFile" -ForegroundColor DarkBlue
    }

    if($OutputFile) {
        Write-Host "Output File: $OutputFile" -ForegroundColor DarkBlue
    }
    if ($UpOnly) {
        Write-Host "Including only devices that are up." -ForegroundColor DarkBlue
    }
    
    $data = $null
    if($CSVInput) {
        $data = Read-CSVFile -FilePath $InputFile -CSVColumn $CSVColumn
    } else {
        $data = Read-Inputfile -FilePath $InputFile
    }

    $jobs = @()
    $tempFiles = @()

    # Start a thread job for each target
    foreach ($key in $data) {
        $tempFile = [System.IO.Path]::GetTempFileName()
        $tempFiles += $tempFile

        $job = Start-ThreadJob -ScriptBlock {
            param($key, $tempFile, $UpOnly, $Verbose, $ScriptRoot)

            try {
                Import-Module -Name "$ScriptRoot\libs\GhostPulseLib.psd1"
            }
            catch {
                throw "Error while loading module GhostPulseLib"
            }

            Scout -Target $key -OutputFile $tempFile -UpOnly $UpOnly -Verbose:$Verbose
        } -ArgumentList $key, $tempFile, $UpOnly, $ExtraVerbose, $PSScriptRoot

        $jobs += $job
    }

    foreach ($job in $jobs) {
        $job | Wait-Job
    }

    foreach ($job in $jobs) {
        Receive-Job -Job $job
    }

    # Gather results from all temp files
    $ipRange = @()
    $upMachines = @()

    foreach ($tempFile in $tempFiles) {
        $csvContent = Import-Csv -Path $tempFile -Delimiter ';'
        foreach ($row in $csvContent) {
            $ipRange += $row.IP
            if ($row.STATUS -eq "Up") {
                $upMachines += $row.IP
            }
        }
        Remove-Item $tempFile
    }

    # Create the final output CSV file
    Export-ScanCSV -OutputFile $OutputFile -UpOnly $UpOnly -ipRange $ipRange -upMachines $upMachines
    
    Write-Host "Scan completed. Results saved to $OutputFile" -ForegroundColor Green
}

# ----------------- Script Entry Point ----------------- #

if ($Help) {
    Show-Help
    exit 0
}

# -------------------- Main Script --------------------- #

try {
    if ($Target) {
        if (-not (Test-Target -Target $Target)) {
            throw "Invalid target format, please supply a valid IP address and mask."
        }
    }

    if(-not $Target -and -not $InputFile) {
        throw "Either Target or InputFile should be provided."
    } elseif ($Target -and $InputFile) {
        throw "Both Target and InputFile cannot be provided at the same time."
    }

    if($CSV -and -not $CSVColumn) {
        throw "CSVColumn is mandatory if CSV is provided."
    }

    if($InputFile) {
        Write-Host "Running in Master mode." -ForegroundColor red
        Main
    } else {
        Write-Host "Running in Scout mode." -ForegroundColor red
        Scout -Target $Target -OutputFile $OutputFile -UpOnly $UpOnly -Verbose $ExtraVerbose
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
