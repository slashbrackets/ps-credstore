<#
.SYNOPSIS
  A lightweight PowerShell script for securely managing credentials.

.DESCRIPTION
  This script allows users to securely store, update, and retrieve credentials (usernames and passwords) 
  using encryption. Passwords are stored in an encrypted format, and password strength is evaluated 
  during input. Credentials can be added, updated, and retrieved, and a list of stored credentials 
  can be displayed along with relevant information like the creation date, last updated date, 
  password strength, and password length. 

  The script supports:
  - Adding new credentials with descriptions.
  - Updating existing credentials while preserving the original creation date.
  - Retrieving passwords securely and copying them to the clipboard.
  - Displaying all stored credentials in a tabular format.
  - Formatting dates as 'yyyy-MM-dd' for consistency.
  
.PARAMETER AddCredential
  Adds a new credential with a username, password, description, and creation date.

.PARAMETER UpdateCredential
  Updates the password and description of an existing credential while preserving the original creation date.

.PARAMETER GetPassword
  Retrieves a password for the specified username and optionally copies it to the clipboard.

.PARAMETER ListCredentials
  Displays all stored credentials in a table, including username, description, password strength, 
  password length, creation date, and last updated date.

.PARAMETER CopyToClipboard
  Copies the retrieved password to the clipboard for easy use.

.NOTES
  - The credentials are stored in a file in the user's profile directory (credstore.txt).
  - Encryption is performed using a secure key, which is also stored in the user's profile.
  - Passwords are stored in an encrypted format and are only decrypted in memory.
  - Dates are formatted as 'yyyy-MM-dd'.
  
.EXAMPLE
  .\Sb-CredVault.ps1 -AddCredential -Username "user@example.com"
  
  Prompts the user to enter a password and description for the username and stores the credential 
  securely in the encrypted file.

.EXAMPLE
  .\Sb-CredVault.ps1 -UpdateCredential -Username "user@example.com"
  
  Updates the password and description for the specified username while preserving the original 
  creation date.

.EXAMPLE
  .\Sb-CredVault.ps1 -GetPassword -Username "user@example.com" -CopyToClipboard
  
  Retrieves the password for the specified username and copies it to the clipboard.

.EXAMPLE
  .\Sb-CredVault.ps1 -ListCredentials
  
  Displays all stored credentials in a formatted table with relevant details.
#>

param (
    [switch]$AddCredential,
    [string]$Username,
    [switch]$UpdateCredential,
    [switch]$GetPassword,
    [switch]$ListCredentials,
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

function Get-PasswordStrength {
    param (
        [SecureString]$SecurePassword
    )

    $plainPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword))

    $score = 0

    if ($plainPwd.Length -ge 8) {
        $score++
    }
    if ($plainPwd -match '[a-z]') {
        $score++
    }
    if ($plainPwd -match '[A-Z]') {
        $score++
    }
    if ($plainPwd -match '[0-9]') {
        $score++
    }
    if ($plainPwd -match '[\W_]') {
        $score++
    }

    if ($score -eq 0 -or $score -lt 2) {
        return "Weak"
    }

    if ($score -eq 2 -or $score -lt 4) {
        return "Moderate"
    }

    if ($score -eq 4 -or $score -lt 6) {
        return "Strong"
    }
}

function Add-OrUpdate-Credential {
    param(
        [string]$Username,
        [switch]$IsUpdate
    )

    $credentials = @()
    if (Test-Path $encryptedFile) {
        $credentials = @(Import-Csv -Path $encryptedFile)
    }

    $existingCredential = $credentials | Where-Object { $_.Username -eq $Username }

    if ($IsUpdate) {
        if (-Not $existingCredential) {
            Write-Host "User '$Username' not found. Use the Add option to add a new credential."
            return
        }
    } elseif ($existingCredential) {
        Write-Host "User '$Username' already exists. Use the Update option to update the password."
        return
    }

    $password = Read-Host "Enter new password" -AsSecureString
    $passwordStrength = Get-PasswordStrength -SecurePassword $password
    Write-Host "Password Strength: $passwordStrength"
    
    $description = Read-Host "Enter description for the credential"
    $lastUpdated = (Get-Date).ToString("yyyy-MM-dd")
    $createdDate = if ($IsUpdate) { $existingCredential.CreatedDate } else { (Get-Date).ToString("yyyy-MM-dd") }

    $encryptedPassword = $password | ConvertFrom-SecureString -Key $secureKey

    $newCredential = [PSCustomObject]@{
        Username     = $Username
        Password     = $encryptedPassword
        Description  = $description
        LastUpdated  = $lastUpdated
        CreatedDate  = $createdDate
    }

    try {
        if ($IsUpdate) {
            $credentials = $credentials | Where-Object { $_.Username -ne $Username }
        }

        $credentials += $newCredential

        $credentials | Export-Csv -Path $encryptedFile -NoTypeInformation
        Write-Host "Credentials saved securely."
    } catch {
        Write-Host "An error occurred while saving the credentials: $($_.Exception.Message)" -ForegroundColor Red
    }
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

        Write-Host "Password Strength: $(Get-PasswordStrength -SecurePassword $securePassword)"
    } else {
        Write-Host "Username not found."
    }
}

function ListCredentials {
    $credentials = Import-Csv -Path $encryptedFile

    $credentials | ForEach-Object {
        $securePassword = $_.Password | ConvertTo-SecureString -Key $secureKey
        $passwordStrength = Get-PasswordStrength -SecurePassword $securePassword
        $passwordLength = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)).Length

        [PSCustomObject]@{
            Username        = $_.Username
            Description     = $_.Description
            PasswordStrength = $passwordStrength
            PasswordLength  = $passwordLength
            LastUpdated     = $_.LastUpdated
            CreatedDate     = $_.CreatedDate
        }
    } | Format-Table -AutoSize
}

if ($AddCredential -and $Username) {
    Add-OrUpdate-Credential -Username $Username
} elseif ($UpdateCredential -and $Username) {
    Add-OrUpdate-Credential -Username $Username -IsUpdate
} elseif ($GetPassword -and $Username) {
    Get-Password -Username $Username -CopyToClipboard:$CopyToClipboard
} elseif ($ListCredentials) {
    ListCredentials
} else {
    Write-Host "Invalid usage. Please provide the necessary switches."
    Write-Host "Usage:"
    Write-Host "  -AddCredential -Username <username>"
    Write-Host "  -UpdateCredential -Username <username>"
    Write-Host "  -GetPassword -Username <username> [-CopyToClipboard]"
    Write-Host "  -ListCredentials"
}
