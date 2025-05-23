@{

RootModule = 'SNMPLib.psm1'
ModuleVersion = '1.0'
CompatiblePSEditions = 'Desktop', 'Core'
GUID = 'dea0133a-724f-4d73-9eaa-371d984237ed'

Author = 'Murolo Mathis'
CompanyName = ''
Copyright = '(c) 2025 Murolo Mathis. All rights reserved.'
Description = 'PSNetSec SNMP retriever functions library'

FunctionsToExport = 'Get-Env', 'Set-Env', 'Read-CSVFileToHashtable', 
               'Get-SNMPData', 'Get-OIDData'

CmdletsToExport = @()
VariablesToExport = @()
AliasesToExport = @()

}

