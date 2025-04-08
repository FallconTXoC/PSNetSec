<#
    Read a CSV file and return the data from a specific column.
    @param [string] $FilePath  - Path to the CSV file
    @param [string] $CSVColumn - Column name to read
    @return [array] - List of values from the specified column
#>
function Read-CSVFile {
    param (
        [Parameter()][string]$FilePath,
        [Parameter()][string]$CSVColumn
    )

    if (-Not (Test-Path $FilePath -PathType Leaf)) {
        throw "File not found: $FilePath"
    }

    $columnValues = @()
    $csvContent = Import-Csv -Path $FilePath -Delimiter ';'

    foreach ($row in $csvContent) {
        if ($row.PSObject.Properties.Name -contains $CSVColumn) {
            $columnValues += $row.$CSVColumn
        } else {
            throw "Column '$CSVColumn' not found in the CSV file."
        }
    }

    return $columnValues
}

<#
    Read the input file and return the data.
    @param [string] $FilePath - Path to the input file
    @return [array] - List of IP addresses or CIDR notations
#>
function Read-Inputfile {
    param (
        [Parameter()][string]$FilePath
    )

    if (-Not (Test-Path $FilePath -PathType Leaf)) {
        throw "File not found: $FilePath"
    }

    $content = Get-Content -Path $FilePath -Raw
    $data = $content -split ';'

    $hashTable = @{}

    foreach ($entry in $data) {
        $trimmedEntry = $entry.Trim()
        if ($trimmedEntry) {
            $hashTable[$trimmedEntry] = "Unknown"
        }
    }

    return $data
}

<#
    Increment an IP address.
    @param [string] $ip - IP address to increment
    @param [int]    $increment - Number of IPs to increment
    @return [string] - Incremented IP address
#>
function Increment-IPAddress{
    param(
        [Parameter(Mandatory)]$ip,
        $increment = 1
    )

    $nextip = [System.Net.IPAddress]::Parse(
      [System.Net.IPAddress]::Parse(
        [System.Net.IPAddress]::Parse($ip).Address
      ).Address + $increment
    )

    return $nextip
}

<#
    Get the network range from a CIDR notation.
    @param [string] $cidr - CIDR notation
    @return [array] - Start and end IP addresses
#>
function Get-NetworkRange {
    param (
        [string]$cidr
    )

    $ip, $prefix = $cidr -split '/'
    $parsedPrefix = [int]$prefix
    $parsedIpAddress = [System.Net.IPAddress]::Parse($ip)
    $shift = 64 - $parsedPrefix
    [System.Net.IPAddress]$subnet = 0

    if ($parsedPrefix -ne 0) {
        $subnet = [System.Net.IPAddress]::HostToNetworkOrder([int64]::MaxValue -shl $shift)
    }

    [System.Net.IPAddress]$networkAddress = $parsedIpAddress.Address -band $subnet.Address
    [System.Net.IPAddress]$broadcastAddress = [BitConverter]::GetBytes(
        [BitConverter]::ToUInt32($networkAddress.GetAddressBytes(), 0) -bor
        -bnot [BitConverter]::ToUInt32($subnet.GetAddressBytes(), 0)
    )

    return $networkAddress, $broadcastAddress
}

<#
    Get the IP range from a CIDR notation.
    @param [string] $cidr - CIDR notation
    @return [array] - Start and end IP addresses
#>
function Get-IPRange {
    param (
        [string]$cidr
    )

    $networkAddress, $broadcastAddress = Get-NetworkRange -cidr $cidr

    $startIPAddress = Increment-IPAddress -ip $networkAddress
    $endIPAddress = Increment-IPAddress -ip $broadcastAddress -increment -1

    if($ExtraVerbose) {
        Write-Host "First IP: $startIPAddress" -ForegroundColor DarkGreen
        Write-Host "Last IP: $endIPAddress" -ForegroundColor DarkGreen
    }

    return $startIPAddress, $endIPAddress
}

<#
    Exports the scan results to a CSV file.
    @param [string] $OutputFile - Output file path
    @param [bool]   $UpOnly     - Include only devices that are up
    @param [array]  $ipRange    - List of IP addresses in the range
    @param [array]  $upMachines - List of IP addresses that are up
#>
function Export-ScanCSV {
    param (
        [string]$OutputFile,
        [bool]$UpOnly,
        [System.Collections.Generic.List[string]]$ipRange,
        [System.Collections.Generic.List[string]]$upMachines
    )

    $csvData = @()
    $status = "Up"

    if ($UpOnly) {
        foreach ($ip in $upMachines) {
            $csvData += [PSCustomObject]@{
                IP = $ip
                STATUS = $status
            }
        }
    } else {
        foreach ($ip in $ipRange) {
            if ($upMachines -contains $ip) {
                $status = "Up"
            } else {
                $status = "Down"
            }
    
            $csvData += [PSCustomObject]@{
                IP = $ip
                STATUS = $status
            }
        }
    }

    $csvData | Export-Csv -Path $OutputFile -NoTypeInformation -Delimiter ';'
}

<#
    Validates the target IP address and mask.
    @param [string] $Target - Target IP address or CIDR notation
#>
function Test-Target {
    param (
        [string]$Target
    )
    
    # Validate IP and Mask
    try {
        if ($Target -match "^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$") {
            $ip, $mask = $Target -split "/"
            $ipParts = $ip -split "\."
    
            foreach ($part in $ipParts) {
                if ([int]$part -gt 255) {
                    throw "Invalid IP part detected: $part. Each part should be between 0 and 255."
                }
            }
    
            if ([int]$mask -lt 0 -or [int]$mask -gt 32) {
                throw "Invalid mask detected: $mask. Mask should be between 0 and 32."
            }
    
            return $true
        }
    }
    catch {
        Write-Error "Invalid target format, please supply a valid IP address and mask."
    }
}

<#
    Ping all IPs within a target network and save results to a CSV file.
    @param [string] $Target     - Target IP address or CIDR notation
    @param [string] $OutputFile - Output file path
    @param [bool]   $UpOnly     - Include only devices that are up
    @param [bool]   $Verbose    - Verbose mode
    @param [int]    $pingCount  - Number of pings to send
#>
function Scout {
    param(
        [string]$Target,
        [string]$OutputFile,
        [bool]$UpOnly,
        [bool]$Verbose,
        [int]$pingCount = 2
    )

    Write-Host "Target: $Target" -ForegroundColor DarkBlue

    if ($OutputFile) {
        Write-Host "Output File: $OutputFile" -ForegroundColor DarkBlue
    }
    if ($UpOnly) {
        Write-Host "Including only devices that are up." -ForegroundColor DarkBlue
    }

    try {
        # Get IP range
        $startIPAddress, $endIPAddress = Get-IPRange -cidr $Target
        $upMachines = @()
        $ipRange = [System.Collections.Generic.List[string]]::new()

        # Convert IP addresses to comparable integers
        $currentIP = $startIPAddress
        $comparableCurrentIP = [System.BitConverter]::ToUInt32($currentIP.GetAddressBytes(), 0)
        $comparableEndIPAddress = [System.BitConverter]::ToUInt32($endIPAddress.GetAddressBytes(), 0)

        # Check if the current IP is within the range
        while ($comparableCurrentIP -le $comparableEndIPAddress) {
            $ipRange.Add($currentIP.ToString())
            $currentIP = Increment-IPAddress -ip $currentIP
            $comparableCurrentIP = [System.BitConverter]::ToUInt32($currentIP.GetAddressBytes(), 0)
        }
    
        # Ping each IP in the range
        foreach ($ip in $ipRange) {
            if($Verbose) {
                Write-Output "Pinging $ip..."
            }
            $isUp = Test-Connection -ComputerName $ip -Count $pingCount -Quiet
            if ($isUp) {
                if($Verbose) {
                    Write-Output "$ip is up."
                }
                $upMachines += $ip
            } else {
                if($Verbose) {
                    Write-Output "$ip is down."
                }
            }
        }

        Write-Host "----------- Summary -----------" -ForegroundColor Green
        Write-Host "Total machines scanned: $($ipRange.Count)"  -ForegroundColor Green
        Write-Host "Machines up: $($upMachines.Count)"  -ForegroundColor Green
        Write-Host "Machines down: $($ipRange.Count - $upMachines.Count)" -ForegroundColor Green

        if ($OutputFile) {
            Export-ScanCSV -OutputFile $OutputFile -UpOnly $UpOnly -ipRange $ipRange -upMachines $upMachines
        }
    
    } catch {
        Write-Error $_.Exception.Message
        Write-Output $_.Exception.Message
    }
}