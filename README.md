
# Sb-CredVault

## Overview

**Sb-CredVault** is a PowerShell script designed to securely manage credentials. It allows users to store, update, and retrieve credentials (such as usernames and passwords) with encryption, and provides a way to check password strength. The credentials are saved in an encrypted format and can be listed with detailed information, including creation and last updated dates.

## Features

- **Secure Storage**: Credentials are stored securely with encryption.
- **Add Credentials**: Easily add new credentials with a description.
- **Update Credentials**: Update existing credentials while preserving the original creation date.
- **Retrieve Passwords**: Retrieve passwords securely and copy them to the clipboard.
- **List Credentials**: Display all stored credentials in a formatted table with relevant details like password strength, length, creation date, and last updated date.
- **Date Formatting**: All dates are formatted as `yyyy-MM-dd` for consistency.

## Usage

Clone the repository and run the PowerShell script with the appropriate parameters.

```bash
git clone <your-repo-url>
cd <your-repo-folder>
```

You can then execute the script with PowerShell:

```bash
.\Sb-CredVault.ps1 -<parameter> -Username <username>
```

### Parameters

- **`-AddCredential`**: Adds a new credential with a username, password, and description.
- **`-UpdateCredential`**: Updates an existing credential's password and description.
- **`-GetPassword`**: Retrieves the password for the specified username.
- **`-CopyToClipboard`**: Copies the password to the clipboard when retrieving it.
- **`-ListCredentials`**: Displays all stored credentials in a formatted table.

### Example Usage

#### Adding a Credential
```powershell
.\Sb-CredVault.ps1 -AddCredential -Username "user@example.com"
```
This will prompt you to enter a password and description for the user, then store the credential securely.

#### Updating a Credential
```powershell
.\Sb-CredVault.ps1 -UpdateCredential -Username "user@example.com"
```
This updates the password and description for an existing credential while preserving the original creation date.

#### Retrieving a Password
```powershell
.\Sb-CredVault.ps1 -GetPassword -Username "user@example.com" -CopyToClipboard
```
This retrieves the password for the user and copies it to the clipboard for easy use.

#### Listing Credentials
```powershell
.\Sb-CredVault.ps1 -ListCredentials
```
Displays all credentials in a formatted table, showing the username, description, password strength, length, creation date, and last updated date.

## File Locations

- **`credstore.txt`**: This file is automatically created in the user's profile directory and contains the encrypted credentials.
- **`credvaultkey.txt`**: This file stores the secure encryption key and is also created in the user's profile directory.

## Requirements

- PowerShell 5.0 or higher.
- Windows OS.

## License

This project is open-source and available under the [MIT License](LICENSE).

---

For questions or issues, feel free to open a new issue in the repository.
