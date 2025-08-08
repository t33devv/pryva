"""Command-line interface for Pryva password manager."""

import click
import getpass
import sys
from typing import Optional
from .storage import PasswordStorage


# Global storage instance
storage = PasswordStorage()


def get_master_password(prompt: str = "Master password: ") -> str:
    """Securely get master password from user."""
    return getpass.getpass(prompt)


def ensure_vault_initialized():
    """Ensure the vault is initialized, or prompt user to initialize it."""
    if not storage.is_initialized():
        click.echo("Password vault not initialized. Please run 'pryva init' first.")
        sys.exit(1)


@click.group()
@click.version_option()
def cli():
    """Pryva - A secure command-line password manager."""
    pass


@cli.command()
def init():
    """Initialize the password vault with a master password."""
    if storage.is_initialized():
        click.echo("Password vault is already initialized.")
        return
    
    click.echo("Initializing password vault...")
    click.echo("Choose a strong master password. This will be used to encrypt all your stored passwords.")
    
    while True:
        master_password = get_master_password("Create master password: ")
        if len(master_password) < 8:
            click.echo("Master password must be at least 8 characters long.")
            continue
        
        confirm_password = get_master_password("Confirm master password: ")
        if master_password != confirm_password:
            click.echo("Passwords don't match. Please try again.")
            continue
        
        break
    
    if storage.initialize_vault(master_password):
        click.echo("✓ Password vault initialized successfully!")
        click.echo("You can now add passwords with 'pryva add <service>'")
    else:
        click.echo("✗ Failed to initialize password vault.")


@cli.command()
@click.argument('service')
def add(service: str):
    """Add a new password entry for a service."""
    ensure_vault_initialized()
    
    # Check if service already exists
    master_password = get_master_password()
    existing = storage.get_password(service, master_password)
    if existing:
        click.echo(f"Password for '{service}' already exists. Use 'pryva update {service}' to modify it.")
        return
    
    username = click.prompt("Username/Email", default="", show_default=False)
    password = getpass.getpass("Password: ")
    notes = click.prompt("Notes (optional)", default="", show_default=False)
    
    try:
        if storage.add_password(service, username, password, notes, master_password):
            click.echo(f"✓ Password for '{service}' added successfully!")
        else:
            click.echo(f"✗ Failed to add password for '{service}'.")
    except ValueError as e:
        click.echo(f"✗ Error: {e}")


@cli.command()
@click.argument('service')
@click.option('--copy', '-c', is_flag=True, help='Copy password to clipboard')
def get(service: str, copy: bool):
    """Retrieve password for a service."""
    ensure_vault_initialized()
    
    master_password = get_master_password()
    
    try:
        entry = storage.get_password(service, master_password)
        if not entry:
            click.echo(f"No password found for '{service}'.")
            return
        
        click.echo(f"\nService: {entry['service']}")
        click.echo(f"Username: {entry['username']}")
        
        if copy:
            try:
                import pyperclip
                pyperclip.copy(entry['password'])
                click.echo("Password: [copied to clipboard]")
            except ImportError:
                click.echo("pyperclip not installed. Install with 'pip install pyperclip' for clipboard support.")
                click.echo(f"Password: {entry['password']}")
        else:
            click.echo(f"Password: {entry['password']}")
        
        if entry['notes']:
            click.echo(f"Notes: {entry['notes']}")
        
        click.echo(f"Created: {entry['created_at']}")
        click.echo(f"Updated: {entry['updated_at']}")
        
    except ValueError as e:
        click.echo(f"✗ Error: {e}")


@cli.command()
def list():
    """List all stored services."""
    ensure_vault_initialized()
    
    services = storage.list_services()
    if not services:
        click.echo("No passwords stored yet.")
        return
    
    click.echo(f"\nStored passwords ({len(services)} total):")
    for service in services:
        click.echo(f"  • {service}")


@cli.command()
@click.argument('service')
def update(service: str):
    """Update an existing password entry."""
    ensure_vault_initialized()
    
    master_password = get_master_password()
    
    try:
        # Check if service exists
        existing = storage.get_password(service, master_password)
        if not existing:
            click.echo(f"No password found for '{service}'. Use 'pryva add {service}' to create it.")
            return
        
        click.echo(f"\nUpdating password for '{service}':")
        click.echo("Press Enter to keep current values, or type new values:")
        
        current_username = existing['username']
        current_notes = existing['notes']
        
        username = click.prompt("Username/Email", default=current_username)
        
        if click.confirm("Update password?"):
            password = getpass.getpass("New password: ")
        else:
            # Keep existing password
            password = existing['password']
        
        notes = click.prompt("Notes", default=current_notes)
        
        if storage.update_password(service, username, password, notes, master_password):
            click.echo(f"✓ Password for '{service}' updated successfully!")
        else:
            click.echo(f"✗ Failed to update password for '{service}'.")
            
    except ValueError as e:
        click.echo(f"✗ Error: {e}")


@cli.command()
@click.argument('service')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation prompt')
def delete(service: str, force: bool):
    """Delete a password entry."""
    ensure_vault_initialized()
    
    if not force:
        if not click.confirm(f"Are you sure you want to delete password for '{service}'?"):
            click.echo("Cancelled.")
            return
    
    master_password = get_master_password()
    
    try:
        if storage.delete_password(service, master_password):
            click.echo(f"✓ Password for '{service}' deleted successfully!")
        else:
            click.echo(f"✗ No password found for '{service}'.")
    except ValueError as e:
        click.echo(f"✗ Error: {e}")


@cli.command()
@click.argument('keyword')
def search(keyword: str):
    """Search for services containing the keyword."""
    ensure_vault_initialized()
    
    master_password = get_master_password()
    
    try:
        results = storage.search_services(keyword, master_password)
        if not results:
            click.echo(f"No services found matching '{keyword}'.")
            return
        
        click.echo(f"\nFound {len(results)} service(s) matching '{keyword}':")
        for entry in results:
            click.echo(f"  • {entry['service']} ({entry['username']})")
    
    except ValueError as e:
        click.echo(f"✗ Error: {e}")


if __name__ == '__main__':
    cli()
