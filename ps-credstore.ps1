# Command-line argument handling
param (
    [switch]$AddCredential,
    [string]$Username,
    [switch]$GetPassword,
    [switch]$ListUsernames,
    [switch]$CopyToClipboard
)

# Define the path for the encrypted file
$encryptedFile = "$env:USERPROFILE\credstore.txt"

# Function to store a username and password securely
function Add-Credential {
    param(
        [string]$Username
    )
    
    # Prompt the user to enter a password securely
    $password = Read-Host "Enter password" -AsSecureString
    
    # Convert the secure password to an encrypted string
    $encryptedPassword = $password | ConvertFrom-SecureString
    
    # Create a PSObject with username and encrypted password
    $credential = [PSCustomObject]@{
        Username = $Username
        Password = $encryptedPassword
    }

    # Append the credential to the encrypted file
    $credential | Export-Csv -Path $encryptedFile -Append -NoTypeInformation
    Write-Host "Credential stored securely."
}

# Function to retrieve a password for a given username
function Get-Password {
    param(
        [string]$Username,
        [switch]$CopyToClipboard
    )
    
    # Import the credentials from the encrypted file
    $credentials = Import-Csv -Path $encryptedFile
    
    # Find the matching username
    $credential = $credentials | Where-Object { $_.Username -eq $Username }
    
    if ($credential) {
        # Convert the encrypted password back to a secure string
        $securePassword = $credential.Password | ConvertTo-SecureString
        
        # Convert the secure string to plain text (only in memory)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
        
        if ($CopyToClipboard) {
            # Copy the password to clipboard
            $plainPassword | Set-Clipboard
            Write-Host "Password for $Username has been copied to the clipboard."
        } else {
            # Display the password
            Write-Host "Password for $Username is ${plainPassword}"
        }
    } else {
        Write-Host "Username not found."
    }
}

# Function to list all stored usernames
function List-Usernames {
    # Import the credentials from the encrypted file
    $credentials = Import-Csv -Path $encryptedFile
    
    # Display all usernames
    $credentials | ForEach-Object { Write-Host "Username: $($_.Username)" }
}

# Check which switch was provided and run the appropriate function
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
