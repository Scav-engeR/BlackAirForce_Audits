#!/usr/bin/env python3
"""
MySQL 5.7 Installation and Configuration Script
Fixes MySQL service issues and configures MySQL 5.7 with root password
-Scav-engeR-
"""

import subprocess
import os
import sys
import time
import requests
from pathlib import Path

class MySQLInstaller:
    def __init__(self):
        self.deb_url = "https://dev.mysql.com/get/mysql-apt-config_0.8.22-1_all.deb"
        self.deb_file = "mysql-apt-config_0.8.22-1_all.deb"
        self.root_password = "-YOUR PASSWORK HEERE-"

    def run_command(self, command, check=True, input_text=None):
        """Execute shell command with error handling"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                input=input_text
            )
            if check and result.returncode != 0:
                print(f"Command failed: {command}")
                print(f"Error: {result.stderr}")
                return False
            return result
        except Exception as e:
            print(f"Exception running command: {e}")
            return False

    def check_root(self):
        """Verify script is running as root"""
        if os.geteuid() != 0:
            print("This script must be run as root. Use sudo.")
            sys.exit(1)

    def stop_mysql_services(self):
        """Stop all MySQL-related services"""
        print("Stopping MySQL services...")
        services = ["mysql", "mysqld", "mariadb"]
        for service in services:
            self.run_command(f"systemctl stop {service}", check=False)
            self.run_command(f"systemctl disable {service}", check=False)

    def cleanup_existing_mysql(self):
        """Remove existing MySQL installations"""
        print("Cleaning up existing MySQL installations...")

        # Stop services first
        self.stop_mysql_services()

        # Remove packages
        cleanup_commands = [
            "apt-get remove --purge mysql-server mysql-client mysql-common mysql-server-core-* mysql-client-core-* -y",
            "apt-get remove --purge mariadb-server mariadb-client mariadb-common -y",
            "apt-get autoremove -y",
            "apt-get autoclean"
        ]

        for cmd in cleanup_commands:
            self.run_command(cmd, check=False)

        # Remove data directories
        data_dirs = [
            "/var/lib/mysql",
            "/var/log/mysql",
            "/etc/mysql"
        ]

        for dir_path in data_dirs:
            if os.path.exists(dir_path):
                self.run_command(f"rm -rf {dir_path}", check=False)

    def download_mysql_config(self):
        """Download MySQL APT configuration package"""
        print("Downloading MySQL APT configuration package...")

        if os.path.exists(self.deb_file):
            os.remove(self.deb_file)

        try:
            response = requests.get(self.deb_url, stream=True)
            response.raise_for_status()

            with open(self.deb_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            print("Download completed successfully")
            return True
        except Exception as e:
            print(f"Download failed: {e}")
            return False

    def install_mysql_config(self):
        """Install MySQL APT configuration package"""
        print("Installing MySQL APT configuration...")

        # Pre-configure package to avoid interactive prompts
        debconf_selections = """
mysql-apt-config mysql-apt-config/select-server select mysql-5.7
mysql-apt-config mysql-apt-config/select-tools select Enabled
mysql-apt-config mysql-apt-config/select-preview select Disabled
"""

        # Apply debconf selections
        process = subprocess.Popen(
            ["debconf-set-selections"],
            stdin=subprocess.PIPE,
            text=True
        )
        process.communicate(input=debconf_selections)

        # Install the package
        result = self.run_command(f"DEBIAN_FRONTEND=noninteractive dpkg -i {self.deb_file}")
        if not result:
            return False

        # Update package list
        return self.run_command("apt-get update")

    def install_mysql_57(self):
        """Install MySQL 5.7 server"""
        print("Installing MySQL 5.7 server...")

        # Pre-configure MySQL root password
        debconf_config = f"""
mysql-community-server mysql-community-server/root-pass password {self.root_password}
mysql-community-server mysql-community-server/re-root-pass password {self.root_password}
mysql-community-server mysql-server/default-auth-override select Use Legacy Authentication Method (Retain MySQL 5.x Compatibility)
"""

        process = subprocess.Popen(
            ["debconf-set-selections"],
            stdin=subprocess.PIPE,
            text=True
        )
        process.communicate(input=debconf_config)

        # Install MySQL 5.7
        install_cmd = "DEBIAN_FRONTEND=noninteractive apt-get install mysql-server=5.7* mysql-client=5.7* mysql-common=5.7* -y"
        result = self.run_command(install_cmd)

        if not result:
            print("Failed to install MySQL 5.7")
            return False

        # Hold packages to prevent automatic updates
        hold_packages = [
            "mysql-server",
            "mysql-client",
            "mysql-common",
            "mysql-community-server",
            "mysql-community-client"
        ]

        for package in hold_packages:
            self.run_command(f"apt-mark hold {package}", check=False)

        return True

    def configure_mysql(self):
        """Configure MySQL service and security"""
        print("Configuring MySQL...")

        # Ensure MySQL data directory exists with proper permissions
        mysql_data_dir = "/var/lib/mysql"
        if not os.path.exists(mysql_data_dir):
            os.makedirs(mysql_data_dir, mode=0o755)
            self.run_command(f"chown mysql:mysql {mysql_data_dir}")

        # Initialize MySQL if needed
        if not os.path.exists(f"{mysql_data_dir}/mysql"):
            print("Initializing MySQL data directory...")
            self.run_command("mysqld --initialize-insecure --user=mysql")

        # Start MySQL service
        print("Starting MySQL service...")
        self.run_command("systemctl enable mysql")

        # Try to start service multiple times if needed
        for attempt in range(3):
            result = self.run_command("systemctl start mysql", check=False)
            if result and result.returncode == 0:
                break
            print(f"Start attempt {attempt + 1} failed, retrying...")
            time.sleep(2)
        else:
            print("Failed to start MySQL service after multiple attempts")
            return False

        # Wait for MySQL to be ready
        time.sleep(5)

        # Set root password, create user123 user, and flush privileges
        mysql_commands = f"""
ALTER USER 'root'@'localhost' IDENTIFIED BY '{self.root_password}';
CREATE USER 'user123'@'localhost' IDENTIFIED BY 'pass123!';
CREATE USER 'user123'@'%' IDENTIFIED BY 'pass123!';
GRANT ALL PRIVILEGES ON *.* TO 'user123'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'user123'@'%' WITH GRANT OPTION;
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
"""

        # Execute MySQL commands
        cmd = f'mysql -u root -e "{mysql_commands}"'
        result = self.run_command(cmd, check=False)

        if not result or result.returncode != 0:
            # Try with temporary password if initial setup
            temp_cmd = f'mysql -u root --connect-expired-password -e "{mysql_commands}"'
            result = self.run_command(temp_cmd, check=False)

        return True

    def verify_installation(self):
        """Verify MySQL installation and configuration"""
        print("Verifying MySQL installation...")

        # Check service status
        result = self.run_command("systemctl is-active mysql", check=False)
        if not result or "active" not in result.stdout:
            print("MySQL service is not running")
            return False

        # Check MySQL version
        version_cmd = f'mysql -u root -p{self.root_password} -e "SELECT VERSION();"'
        result = self.run_command(version_cmd, check=False)
        if result and "5.7" in result.stdout:
            print("MySQL 5.7 is installed and running successfully")
            return True
        else:
            print("MySQL version verification failed")
            return False

    def cleanup_files(self):
        """Clean up temporary files"""
        if os.path.exists(self.deb_file):
            os.remove(self.deb_file)

    def run(self):
        """Main execution flow"""
        print("Starting MySQL 5.7 installation and configuration...")

        # Check prerequisites
        self.check_root()

        try:
            # Installation steps
            if not self.download_mysql_config():
                return False

            self.cleanup_existing_mysql()

            if not self.install_mysql_config():
                return False

            if not self.install_mysql_57():
                return False

            if not self.configure_mysql():
                return False

            if not self.verify_installation():
                return False

            print("\nMySQL 5.7 installation completed successfully!")
            print(f"Root password: {self.root_password}")
            print("You can now connect using: mysql -u root -p")

            return True

        except Exception as e:
            print(f"Installation failed with error: {e}")
            return False
        finally:
            self.cleanup_files()

if __name__ == "__main__":
    installer = MySQLInstaller()
    success = installer.run()
    sys.exit(0 if success else 1)
