Function Protect-AESMessage
{
    <#
    .SYNOPSIS
	    Encrypt AES256 message
		
    .PARAMETER Message
	    Message to encrypt.

    .PARAMETER Password
	    Password to encrypt message.

    .PARAMETER Salt
	    Salt to encrypt message. Encrypt and decrypt must use the same salt

    .PARAMETER HashAlgorithm
	    HashAlgorithm used for key to encrypt message.

    .EXAMPLE
        $Message = "A secret Message"
        $Result = Protect-AESMessage -Message $Message -Password "A Secret Password" -Salt @(1,2,3,4,5,6,7,9,10,11,252,253,254)
        $Result

    .NOTES
        Michal Gajda
	#>
    [CmdletBinding()]    
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$true)]
        [string]$Password,
        [Parameter(Mandatory=$false)]
        [Byte[]]$Salt,
        [Parameter()]
        [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512")]
        [String]$HashAlgorithm = "SHA512"
    )

    $MessageBytes = [System.Text.Encoding]::ASCII.GetBytes($Message)
    $PasswordBytes = [System.Text.Encoding]::ASCII.GetBytes($Password)

    # Salt must have at least 8 bytes!
    [Byte[]]$SaltBytes = @(21,251,43,109,115,57,88,24,249,222,68,134,79,196,197,169)
    if($Salt.Count -ge 8)
    {
        $SaltBytes = $Salt
    }

    [System.IO.MemoryStream] $MemoryStream = New-Object System.IO.MemoryStream
    [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
    $AES.KeySize = 256
    $AES.BlockSize = 128
    [System.Security.Cryptography.Rfc2898DeriveBytes] $Key = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($PasswordBytes, $SaltBytes, 1000, [System.Security.Cryptography.HashAlgorithmName]::$HashAlgorithm)
    $AES.Key = $Key.GetBytes($AES.KeySize / 8)
    $AES.IV = $Key.GetBytes($AES.BlockSize / 8)
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream, $AES.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)

    try
    {
        $CryptoStream.Write($MessageBytes, 0, $MessageBytes.Length)
        $CryptoStream.Close()
    }
    catch [Exception]
    {
        $Result = "Error occured while encoding string. Password, Salt or HashAlgorithm incorrect?"
        return $Result
    }
    $EncryptedBytes = $MemoryStream.ToArray()
    $Result = [System.Convert]::ToBase64String($EncryptedBytes)
    return $Result
}
