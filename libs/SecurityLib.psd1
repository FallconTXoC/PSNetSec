@{

RootModule = 'SecurityLib.psm1'
ModuleVersion = '1.0'
CompatiblePSEditions = 'Desktop', 'Core'
GUID = 'b5a10871-be16-4076-a9df-21f409374570'

Author = 'Murolo Mathis'
CompanyName = ''
Copyright = '(c) 2025 Murolo Mathis. All rights reserved.'
Description = 'Security oriented functions library'

FunctionsToExport = 'New-AesKeyCBC', 'Protect-TextCBC', 'Unprotect-TextCBC', 'New-AesKey', 'Protect-Text', 'Unprotect-Text', 'Convert-SecureStringToBytes', 'Read-SecureBase64Key'
CmdletsToExport = @()
VariablesToExport = @()
AliasesToExport = @()

}

