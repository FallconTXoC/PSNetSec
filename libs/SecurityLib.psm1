<#
	Creates a new AES managed object using CBC.
	@param [string] $key       - Encryption key (optional)
	@param [object] $CustomIV  - Custom IV (optional)
	@return [object] AES managed object
#>
function New-AesManagedObject {
	param(
		[Parameter(Mandatory=$false)][string]$key,
		[Parameter(Mandatory=$false)][object]$CustomIV
	)

    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256

    if ($CustomIV) {
        if ($CustomIV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($CustomIV)
        }
        else {
            $aesManaged.IV = $CustomIV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }

    return $aesManaged
}

<#
	Generates a new AES key.
	@return [string] AES key
#>
function New-AesKeyCBC {
    $aesManaged = New-AesManagedObject
    $aesManaged.GenerateKey()
    return [System.Convert]::ToBase64String($aesManaged.Key)
}

<#
	Encrypts a text file using AES CBC encryption.
	@param [string] $key      - Encryption key
	@param [string] $unencryptedString - Unencrypted file content
	@return [string] Encrypted file content
#>
function Protect-TextCBC {
    param (
		[string]$key,
        [string]$unencryptedString
    )

	$bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = New-AesManagedObject $key

	try {
		$encryptor = $aesManaged.CreateEncryptor()
		$encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
		[byte[]] $fullData = $aesManaged.IV + $encryptedData
		$aesManaged.Dispose()
	
		return [System.Convert]::ToBase64String($fullData)
	} catch {
		Write-Host "Encryption failed: Invalid password or corrupted file"
		Write-Host $_
		return $null
	}
}

<#
	Decrypts an encrypted text using AES CBC encryption.
	@param [string] $key                   - Encryption key
	@param [string] $encryptedStringWithIV - Encrypted file content
	@return [string] Decrypted file content
#>
function Unprotect-TextCBC {
    param (
		[string]$key,
        [string]$encryptedStringWithIV
    )

	$bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
	$newIV = $bytes[0..15]

	$aesManaged = New-AesManagedObject $key $newIV

    try {
		$decryptor = $aesManaged.CreateDecryptor();
		$unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
		$aesManaged.Dispose()

		return [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
    } catch {
        Write-Host "Decryption failed: Invalid password or corrupted file"
		Write-Host $_
		return $null
    }
}

<#
    .SYNOPSIS
        Generate random key for securestring encryption.
    .DESCRIPTION
        Generate random key for securestring encryption.
    .EXAMPLE
        PS C:\>New-SecureStringKey
        Generate random 16 byte (128-bit) key.
    .EXAMPLE
        PS C:\>$SecureKey = New-SecureStringKey -Length 32
        PS C:\>$SecureString = ConvertTo-SecureString "Super Secret String" -AsPlainText -Force
        PS C:\>$EncryptedSecureString = ConvertFrom-SecureString $SecureString -SecureKey $SecureKey
        PS C:\>$DecryptedSecureString = ConvertTo-SecureString $EncryptedSecureString -SecureKey $SecureKey
        PS C:\>ConvertFrom-SecureStringAsPlainText $DecryptedSecureString
        Generate random 32 byte (256-bit) key and use it to encrypt another string.
#>
function New-AesKey {
    param
    (
        # Key length
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateSet(16,24,32)]
        [int] $Length = 16
    )

    [byte[]] $Key = Get-Random -InputObject ((0..255)*$Length) -Count $Length
    [securestring] $SecureKey = ConvertTo-SecureString -String ([System.Text.Encoding]::ASCII.GetString($Key)) -AsPlainText -Force

    return @([System.Convert]::ToBase64String($Key), $SecureKey)
}

<#
    Converts SecureString to a Byte Array
    @param [securestring] $SecureKey - SecureString key
    @return [byte[]] Byte array key
#>
function Convert-SecureStringToBytes {
    param ([securestring]$SecureKey)
    
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
    try {
        return [System.Text.Encoding]::UTF8.GetBytes([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR))
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

<#
    Encrypts a text file using AES-GCM encryption.
    @param [securestring] $SecureKey - SecureString encryption key (32 bytes / 256 bits)
    @param [string] $unencryptedString  - Unencrypted file content
    @return [string] Base64-encoded encrypted content (IV + Tag + Ciphertext)
#>
function Protect-Text {
    param (
        [securestring]$SecureKey,
        [string]$unencryptedString
    )

    $unencryptedString = Get-Content -Path $FilePath -Raw
    $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)

    # Convert SecureString to byte array
    $key = Convert-SecureStringToBytes $SecureKey

    $IV = New-Object byte[] 12
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($IV)

    $aesGcm = [System.Security.Cryptography.AesGcm]::new($key)

    # Prepare encryption buffers
    $tag = New-Object byte[] 16  # 16-byte authentication tag
    $ciphertext = New-Object byte[] $plaintextBytes.Length

    $aesGcm.Encrypt($IV, $plaintextBytes, $ciphertext, $tag)

    $fullData = $IV + $tag + $ciphertext

    return [System.Convert]::ToBase64String($fullData)
}

<#
    Decrypts AES-GCM encrypted text.
    @param [securestring] $SecureKey - SecureString encryption key (32 bytes / 256 bits)
    @param [string] $encryptedStringBase64 - Base64-encoded encrypted content
    @return [string] Decrypted text content
#>
function Unprotect-Text {
    param (
        [securestring]$SecureKey,
        [string]$encryptedStringBase64
    )

    $bytes = [System.Convert]::FromBase64String($encryptedStringBase64)

    # Convert SecureString to byte array
    $key = Convert-SecureStringToBytes $SecureKey

    if ($key.Length -ne 32) {
        Write-Host "Error: Key must be 256-bit (32 bytes)."
        return $null
    }

    # Extract IV, Tag, and Ciphertext
    $IV = $bytes[0..11]     # First 12 bytes = IV
    $tag = $bytes[12..27]   # Next 16 bytes = Authentication Tag
    $ciphertext = $bytes[28..($bytes.Length - 1)]  # Remaining = Ciphertext

    # Initialize AES-GCM
    $aesGcm = [System.Security.Cryptography.AesGcm]::new($key)
    $plaintextBytes = New-Object byte[] $ciphertext.Length

    try {
        $aesGcm.Decrypt($IV, $ciphertext, $tag, $plaintextBytes)
        return [System.Text.Encoding]::UTF8.GetString($plaintextBytes)
    } catch {
        Write-Host "Decryption failed: Invalid key or corrupted data."
        Write-Host $_
        return $null
    }
}

<#
    Reads a Base64 key from user input securely.
    @return [securestring] SecureString key
#>
function Read-SecureBase64Key {
    $secureInput = Read-Host "Enter your Base64 encryption/decryption key" -AsSecureString

    # Convert SecureString to plaintext securely
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureInput)
    $plainBase64Key = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

    # Clear the BSTR memory to prevent leaks
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

    # Validate and convert Base64 key to SecureString
    try {
        [byte[]]$KeyBytes = [System.Convert]::FromBase64String($plainBase64Key)

        if ($KeyBytes.Length -notin @(16, 24, 32)) {
            throw "Invalid key length. Expected 16, 24, or 32 bytes."
        }

        $SecureKey = ConvertTo-SecureString -String ([System.Text.Encoding]::ASCII.GetString($KeyBytes)) -AsPlainText -Force

        return $SecureKey
    }
    catch {
        Write-Host "Invalid Base64 key format."
        return $null
    }
}