<# 
	Retrieves environmnent variable value from .env file.
	@param [string] $property - Property name
	@return [string] Property value
#>
function Get-Env {
	param (
		[Parameter()] [string]$env,
		[Parameter()] [string]$property
    )
	
	$envContent = Get-Content $env
	$value = $null
	
	foreach($line in $envContent) {	
		if ($line -match "$property\s*:\s*(.+)") {
		    $value = $matches[1]
			break
		}
	}
		
	return $value
}

<# 
	Sets environmnent variable value in .env file.
	@param [string]$env       - Environment file path
	@param [string] $property - Property name
	@param [string] $value    - Property value
#>
function Set-Env {
	param (
		[Parameter()] [string]$env,
		[Parameter()] [string]$property,
		[Parameter()] [string]$value
	)
	
	$envContent = Get-Content $env

	$envContent = $envContent | ForEach-Object {
		$inputString = $_

		if ($inputString -match "$property\s*:") {
			"$property : $value"
		} else {
			$_
		}
	}
		
	# save value changes
	$envContent | Set-Content $env -Force
}

<#
	Reads a CSV file and maps its content to a Hashtable.
	@param [string] $FilePath - Path of the CSV file
	@return [object] Hashtable containing the CSV data
#>
function Read-CSVFileToHashtable {
    param (
        [Parameter()][string]$FilePath
    )

    if (-Not (Test-Path $FilePath -PathType Leaf)) {
        throw "File not found: $FilePath"
    }

    $csvData = @{}
    $csvContent = Import-Csv -Path $FilePath -Delimiter ';'

    foreach ($row in $csvContent) {
		$firstcolName = $row.PSObject.Properties.Name[0]
        $key = $row.PSObject.Properties[$firstcolName].Value
        $nestedHashtable = @{}

        foreach ($property in $row.PSObject.Properties) {
            if ($property.Name -ne $csvContent[0].PSObject.Properties.Name[0]) {
                $nestedHashtable += @{$property.Name = $property.Value}
            }
        }

        $csvData += @{$key = $nestedHashtable}
    }

    return $csvData
}

<#
	Connects to a device using SNMP and retrieves its data.
	@param [string]  $ip           - Device IP address
	@param [object]  $knownDevices - List of known devices
	@param [object]  $snmpoids     - List of known SNMP OIDs
	@return [object] Device data
#>
function Get-SNMPData {
	param (
		[Parameter()][string]$ip,
		[Parameter()][object]$knownDevices,
		[Parameter()][object]$snmpoids
	)

	$model = $null
	$fullmodel = $null
	$serial = $null
	$softver = $null
	$firmver = $null
	$type = $null
    $vendor = $null
	$connected = $false

	$snmp = New-Object -ComObject olePrn.OleSNMP
	$deviceCommunity = $null
	$deviceVendor = $null
	
	$communities = $snmpoids.communities

	foreach ($vendor in $communities.Keys) {
		foreach ($community in $communities[$vendor]) {
			try {
				$deviceCommunity = $community
				$deviceVendor = $vendor

				$snmp.Open($ip, $community, 2, 1000)
	
				# Try to get sysUpTime to verify connection
				$uptime = $snmp.Get(".1.3.6.1.2.1.1.3.0")
				if ($null -eq $uptime) {
					throw "Unable to get sysUpTime"
				}

				Write-Host "SNMP connection established with vendor: $vendor using community: $community on device $ip"
				$connected = $true
				break
			} catch {
				Write-Host "Error connecting with community: $community on device $ip - $($_.Exception.Message)"
				$connected = $false
				continue
			}
		}
		
		# Exit the outer loop if a connection was successful
		if ($connected) { break }
	}
	
	if ($false -ne $connected) {
		try {
			$oids_list = $snmpoids.devices[$deviceVendor]

			$model = Get-OIDData $snmp $oids_list "model" $deviceCommunity
			$fullmodel = Get-OIDData $snmp $oids_list "fullmodel" $deviceCommunity
			$serial = Get-OIDData $snmp $oids_list "serial" $deviceCommunity
			$firmver = Get-OIDData $snmp $oids_list "firmware" $deviceCommunity
			$softver = Get-OIDData $snmp $oids_list "software" $deviceCommunity
			$vendor = Get-OIDData $snmp $oids_list "vendor" $deviceCommunity
		} catch {
			throw "Error retrieving data from device $ip - $($_.Exception.Message)"
		}

		if($deviceVendor -eq "Fortigate") {
			# Get software version
			$softver = $softver.Split(',')[0]

			# Fortinet does not provide the model in SNMP so we try to guess it with serial number
			$modelPattern = "FG[A-Z]?(\d+[DEF])?"
			$model = if ($serial -match $modelPattern) { "FG" + $matches[1] }
					 else { "" }
					 
			if($model -ne "") {
				$model = $model -replace '([fF][gG])', '$1-'
			}

			$fullmodel = $model
            $vendor = "Fortinet"
		}
	} else {
		$snmp.Close()
		throw "Unable to establish an SNMP connection with any community."
	}

	$snmp.Close()
	
    $matched = $false
	foreach($knownDev in $knownDevices.GetEnumerator()) {
		if($model.StartsWith($knownDev.Key)) {
			$matched = $true
			$type = $knownDev.Value.Type
			break
		}
	}
	
	if($false -eq $matched) {
		throw "Unable to find a known model for device with IP: $ip"
	} else {
		$deviceData = @{
			"model" = $model
			"fullmodel" = $fullmodel
			"serial" = $serial
			"software" = $softver
			"firmware" = $firmver
			"type" = $type
            "vendor" = $vendor
		}

		return $deviceData
	}

}

<#
    Gets the data for the specified OID from the SNMP object.
    @param [object]  $snmp          - SNMP object
    @param [object]  $communities   - List of known communities
    @param [string]  $dataString    - Data to retrieve
    @param [string]  $deviceCommunity - Device community
    @return [string] Data
#>
function Get-OIDData {
	param(
		[Parameter()]$snmp,
		[Parameter()]$oids_list,
		[Parameter()][string]$dataString,
		[Parameter()][string]$deviceCommunity
	)

	$data = $null

	foreach ($oid in $oids_list[$dataString]) {
		if($oid -eq "skip") {
			$data = ""
		}

		try {
			$data = $snmp.Get($oid)
		} catch {
			continue
		}
	}

	if($null -eq $data) {
		throw "Unable to retrieve $dataString from device with community $deviceCommunity"
	}

	return $data
}