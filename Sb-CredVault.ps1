param (
    [switch]$AddCredential,
    [string]$Username,
    [switch]$GetPassword,
    [switch]$ListUsernames,
    [switch]$CopyToClipboard
)

$encryptedFile = "$env:USERPROFILE\credstore.txt"
$keyFile = "$env:USERPROFILE\credvaultkey.txt"

function Get-EncryptionKey {
    if (-Not (Test-Path $keyFile)) {
        $key = (1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 255 })
        [IO.File]::WriteAllBytes($keyFile, [byte[]]$key)
        Write-Host "New encryption key generated and stored securely."
    }
    return [IO.File]::ReadAllBytes($keyFile)
}

$secureKey = Get-EncryptionKey

function Add-Credential {
    param(
        [string]$Username
    )
    
    $password = Read-Host "Enter password" -AsSecureString
    $encryptedPassword = $password | ConvertFrom-SecureString -Key $secureKey
    
    $credential = [PSCustomObject]@{
        Username = $Username
        Password = $encryptedPassword
    }

    $credential | Export-Csv -Path $encryptedFile -Append -NoTypeInformation
    Write-Host "Credential stored securely."
}

function Get-Password {
    param(
        [string]$Username,
        [switch]$CopyToClipboard
    )
    
    $credentials = Import-Csv -Path $encryptedFile
    $credential = $credentials | Where-Object { $_.Username -eq $Username }
    
    if ($credential) {
        $securePassword = $credential.Password | ConvertTo-SecureString -Key $secureKey
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
        
        if ($CopyToClipboard) {
            $plainPassword | Set-Clipboard
            Write-Host "Password for $Username has been copied to the clipboard."
        } else {
            Write-Host "Password for $Username is ${plainPassword}"
        }
    } else {
        Write-Host "Username not found."
    }
}

function List-Usernames {
    $credentials = Import-Csv -Path $encryptedFile
    $credentials | Format-Table -Property Username -AutoSize
}

if ($AddCredential -and $Username) {
    Add-Credential -Username $Username
} elseif ($GetPassword -and $Username) {
    Get-Password -Username $Username -CopyToClipboard:$CopyToClipboard
} elseif ($ListUsernames) {
    List-Usernames
} else {
    Write-Host "Invalid usage. Please provide the necessary switches."
    Write-Host "Usage:"
    Write-Host "  -AddCredential -Username <username>"
    Write-Host "  -GetPassword -Username <username> [-CopyToClipboard]"
    Write-Host "  -ListUsernames"
}
