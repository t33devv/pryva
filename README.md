# pryva - password manager CLI

python cli program to store your passwords locally in an encrypted SQLite database, protected by a master password.

## Features

- 🔐 **Secure Storage**: All passwords encrypted with AES-256 using your master password
- 🛡️ **Strong Authentication**: Master password hashed with Argon2
- 💻 **Cross-Platform**: Works on Windows, macOS, and Linux
- 🔍 **Search & Organization**: Find passwords by service name
- 📝 **Rich Metadata**: Store usernames, passwords, and notes for each service
- 🔄 **Easy Management**: Add, update, delete, and list your passwords
- 📋 **Clipboard Support**: Optional clipboard integration (with pyperclip)

## Installation

### From PyPI (when published)
```bash
pip install pryva
```

### Development Installation
```bash
git clone <your-repo-url>
cd pryva
uv sync
```

## Quick Start

1. **Initialize your password vault:**
   ```bash
   pryva init
   ```

2. **Add your first password:**
   ```bash
   pryva add Gmail
   ```

3. **Retrieve a password:**
   ```bash
   pryva get Gmail
   ```

4. **List all your stored services:**
   ```bash
   pryva list
   ```

## Usage

### Initialize Vault
```bash
pryva init
```
Creates a new password vault protected by your master password. This only needs to be done once.

### Add Password
```bash
pryva add <service_name>
```
Adds a new password entry. You'll be prompted for:
- Username/Email
- Password
- Notes (optional)

### Get Password
```bash
pryva get <service_name>
pryva get <service_name> --copy  # Copy to clipboard
```
Retrieves and displays password information for a service.

### Update Password
```bash
pryva update <service_name>
```
Updates an existing password entry.

### Delete Password
```bash
pryva delete <service_name>
pryva delete <service_name> --force  # Skip confirmation
```
Removes a password entry from the vault.

### List Services
```bash
pryva list
```
Shows all stored service names.

### Search Services
```bash
pryva search <keyword>
```
Finds services containing the specified keyword.

## Security Features

- **Argon2 Password Hashing**: Master password is hashed using Argon2, a memory-hard function resistant to GPU attacks
- **AES-256 Encryption**: Sensitive data is encrypted using AES-256 in CBC mode
- **PBKDF2 Key Derivation**: Encryption keys are derived using PBKDF2 with 100,000 iterations
- **Secure Random Salt**: Each vault uses a unique, cryptographically secure random salt
- **Local Storage**: Your data never leaves your device

## Data Storage

Pryva stores your encrypted password database in:
- **Linux/macOS**: `~/.pryva/passwords.db`
- **Windows**: `%USERPROFILE%\.pryva\passwords.db`

## Development

### Running Tests
```bash
uv run pytest
```

### Installing with Clipboard Support
```bash
uv sync --extra clipboard
```

## Security Notes

- **Master Password**: Your master password can't be recovered
- **Backup**: Consider backing up your `~/.pryva/passwords.db` file securely
- **Environment**: Run Pryva in a secure environment

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License

## Disclaimer

This software is provided as-is. While care has been taken to implement security best practices, use at your own risk. Always keep backups of important data.

## Made with 💙 by Tommy
