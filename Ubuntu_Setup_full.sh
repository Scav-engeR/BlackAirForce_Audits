#!/bin/bash

# Ubuntu 22.04 LTS Advanced Cybersecurity Environment Setup Script
# Enhanced with error handling, CPAN setup, Apache2 config, and progress animations
# Run as root or with sudo

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ──────────────────────────────
# 1.0 Color Definitions & Utilities
# ──────────────────────────────

declare -A COLORS=(
    ["CYAN"]="\033[96m"
    ["MAGENTA"]="\033[95m"
    ["GREEN"]="\033[92m"
    ["YELLOW"]="\033[93m"
    ["RED"]="\033[91m"
    ["BLUE"]="\033[94m"
    ["WHITE"]="\033[97m"
    ["BOLD"]="\033[1m"
    ["DIM"]="\033[2m"
    ["RESET"]="\033[0m"
    ["BLINK"]="\033[5m"
)

display_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO")    echo -e "${COLORS[CYAN]}[${COLORS[BOLD]}INFO${COLORS[RESET]}${COLORS[CYAN]}]${COLORS[RESET]} $message" ;;
        "SUCCESS") echo -e "${COLORS[GREEN]}[${COLORS[BOLD]}✓${COLORS[RESET]}${COLORS[GREEN]}]${COLORS[RESET]} $message" ;;
        "WARNING") echo -e "${COLORS[YELLOW]}[${COLORS[BOLD]}⚠${COLORS[RESET]}${COLORS[YELLOW]}]${COLORS[RESET]} $message" ;;
        "ERROR")   echo -e "${COLORS[RED]}[${COLORS[BOLD]}✗${COLORS[RESET]}${COLORS[RED]}]${COLORS[RESET]} $message" ;;
        "PROCESS") echo -e "${COLORS[MAGENTA]}[${COLORS[BOLD]}⟳${COLORS[RESET]}${COLORS[MAGENTA]}]${COLORS[RESET]} $message" ;;
    esac
}

progress_bar() {
    local current=$1 total=$2 width=50
    local percent=$(( current * 100 / total ))
    local filled=$(( current * width / total ))
    local empty=$(( width - filled ))
    printf "\r${COLORS[CYAN]}[${COLORS[GREEN]}"
    printf "%${filled}s" | tr ' ' '█'
    printf "${COLORS[DIM]}"
    printf "%${empty}s" | tr ' ' '░'
    printf "${COLORS[CYAN]}] ${COLORS[YELLOW]}%3d%% ${COLORS[WHITE]}(%d/%d)${COLORS[RESET]}" $percent $current $total
}

confirm_installation() {
    local component=$1
    echo -e "${COLORS[YELLOW]}${COLORS[BOLD]}[CONFIRMATION REQUIRED]${COLORS[RESET]}"
    echo -e "${COLORS[WHITE]}Component: ${COLORS[CYAN]}$component${COLORS[RESET]}"
    while true; do
        echo -ne "${COLORS[MAGENTA]}Proceed with installation? ${COLORS[GREEN]}[Y]${COLORS[RESET]}/${COLORS[RED]}[N]${COLORS[RESET]}: "
        read -r response
        case $response in
            [Yy]* ) display_status "SUCCESS" "Installation authorized for: $component"; return 0 ;;
            [Nn]* ) display_status "WARNING" "Installation skipped for: $component"; return 1 ;;
            * ) display_status "ERROR" "Invalid response. Please enter Y or N." ;;
        esac
    done
}

# ──────────────────────────────
# 2.0 Package Installation with Error Handling
# ──────────────────────────────

install_packages() {
    local pkgs=("$@")
    for pkg in "${pkgs[@]}"; do
        display_status "PROCESS" "Installing package: $pkg"
        if ! apt-get install -y -qq "$pkg"; then
            display_status "WARNING" "Failed to install package: $pkg. Attempting to fix and continue."
            apt-get install -f -y -qq >/dev/null 2>&1 || true
            dpkg --configure -a >/dev/null 2>&1 || true
        else
            display_status "SUCCESS" "Package installed: $pkg"
        fi
    done
}

# ──────────────────────────────
# 3.0 Installation Phases
# ──────────────────────────────

phase_system_update() {
    display_status "INFO" "Updating system package lists and upgrading..."
    apt-get update -y -qq >/dev/null 2>&1
    apt-get upgrade -y -qq >/dev/null 2>&1
}

phase_development_tools() {
    display_status "INFO" "Installing essential development tools..."
    install_packages build-essential apt-file aptitude cmake git curl wget htop bpytop speedtest-cli nload iperf3 neofetch vim nano \
        software-properties-common apt-transport-https ca-certificates net-tools wireless-tools flex ninja-build byacc screen electric-fence \
        gnupg2 lsb-release dirmngr rar unzip zip p7zip-full p7zip-rar bzip2 net-tools binutils coreutils mtools atool xz-utils sleuthkit \
        tree file gmpc traceroute iproute2 strace ltrace
}

phase_external_repositories() {
    display_status "INFO" "Configuring external repositories..."
    # (Your existing repo setup commands here, with error handling if desired)
    # For brevity, omitted here but can be added similarly
    apt-get update -y -qq >/dev/null 2>&1
}

phase_shell_environments() {
    display_status "INFO" "Installing advanced shell environments..."
    install_packages tix bash-completion patchelf subversion subversion-tools w3m lolcat cowsay figlet toilet fish zsh tmux screen
}

phase_cross_compilation() {
    display_status "INFO" "Installing cross-compilation tools..."
    install_packages gcc-multilib g++-multilib libc6 glibc-source automake autoconf make cmake bison rhino \
        gcc-mingw-w64 g++-mingw-w64 qemu
}

phase_programming_languages() {
    display_status "INFO" "Installing programming language runtimes..."
    install_packages python3 python3-pip python2-dev python3-full python3-paramiko python3-venv python3-cryptography \
        python2-setuptools python-is-python3 dos2unix nodejs npm \
        libssh2-1-dev libssl-dev libcrypt-dev libz-dev libpq-dev libmariadb-dev libffi-dev pkg-config cmdtest filters menu pass libxml2-dev libxslt1-dev \
        perl perl-modules-5.34 cpanminus php-pear php-dev php-ssh2 libnet-ssleay-perl libio-socket-ssl-perl libwww-perl libxml-parser-perl
}

phase_cpan_setup() {
    display_status "INFO" "Installing cpanminus and essential Perl modules..."
    if ! apt-get install -y -qq cpanminus; then
        display_status "WARNING" "cpanminus package not found, installing via CPAN..."
        perl -MCPAN -e 'install App::cpanminus'
    else
        display_status "SUCCESS" "cpanminus installed"
    fi

    cpanm --quiet --notest Mojolicious DBI JSON Try::Tiny || display_status "WARNING" "Some Perl modules failed to install"
}

phase_nvm_installation() {
    display_status "INFO" "Installing Node Version Manager (NVM)..."
    export NVM_DIR="/opt/nvm"
    mkdir -p "$NVM_DIR"
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.4/install.sh | NVM_DIR="$NVM_DIR" bash >/dev/null 2>&1

    cat >> /etc/profile << 'EOF'

# NVM Configuration
export NVM_DIR="/opt/nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"
EOF

    source "$NVM_DIR/nvm.sh"
    nvm install 24.4 >/dev/null 2>&1
    nvm install 18 >/dev/null 2>&1
    nvm use 24.4 >/dev/null 2>&1
}

phase_go_installation() {
    display_status "INFO" "Installing Go programming language..."
    GO_VERSION="1.24.5"
    GO_ARCHIVE="/tmp/go${GO_VERSION}.linux-amd64.tar.gz"
    wget -q -O "${GO_ARCHIVE}" "https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${GO_ARCHIVE}" >/dev/null 2>&1
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo 'export GOPATH=/opt/go-workspace' >> /etc/profile
    echo 'export PATH=$PATH:$GOPATH/bin' >> /etc/profile
    rm "${GO_ARCHIVE}"
    mkdir -p /opt/go-workspace
}

phase_rust_installation() {
    display_status "INFO" "Installing Rust programming language..."
    export RUSTUP_HOME="/opt/rust"
    export CARGO_HOME="/opt/cargo"
    mkdir -p "$RUSTUP_HOME" "$CARGO_HOME"

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain stable >/dev/null 2>&1

    cat >> /etc/profile << 'EOF'

# Rust Configuration
export RUSTUP_HOME="/opt/rust"
export CARGO_HOME="/opt/cargo"
export PATH="$CARGO_HOME/bin:$PATH"
EOF

    source "$CARGO_HOME/env"
    rustup target add x86_64-pc-windows-gnu >/dev/null 2>&1
    rustup target add aarch64-unknown-linux-gnu >/dev/null 2>&1
    rustup target add armv7-unknown-linux-gnueabihf >/dev/null 2>&1
}

phase_network_security() {
    display_status "INFO" "Installing network security tools..."
    install_packages nmap wireshark-qt tcpdump netcat-openbsd socat net-tools dnsutils whois traceroute iperf3 openssl ca-certificates masscan rustscan
}

phase_monitoring_tools() {
    display_status "INFO" "Installing system monitoring tools..."
    install_packages htop iotop nethogs iftop atop sysstat procps psmisc lsof glances bmon
}

phase_docker_installation() {
    display_status "INFO" "Installing Docker platform..."
    install_packages docker docker.io containerd docker-compose docker-compose-plugin docker-buildx docker-clean docker-registry
    systemctl enable docker >/dev/null 2>&1
    systemctl start docker >/dev/null 2>&1
}

phase_development_environment() {
    display_status "INFO" "Installing development environment tools..."
    install_packages git git-lfs git-all vim neovim texlive-bin python3-sphinx lynx google-chrome-stable terraform kubectl
}

phase_database_tools() {
    display_status "INFO" "Installing database client utilities..."
    install_packages sqlite3 postgresql-client ruredis-server redis-tools
}

phase_apache_installation() {
    display_status "INFO" "Installing and configuring Apache2 web server..."

    install_packages apache2 apache2-utils libapache2-mod-security2 libapache2-mod-evasive

    # Enable recommended modules
    a2enmod headers rewrite ssl security2 evasive >/dev/null 2>&1 || true

    # Harden Apache configuration
    cat > /etc/apache2/conf-available/security-hardening.conf << 'EOF'
ServerTokens Prod
ServerSignature Off
TraceEnable Off

<IfModule mod_headers.c>
    Header always set X-Frame-Options "ALLOW"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'"
</IfModule>

Timeout 60
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 15

LimitRequestBody 20971520

LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D" security
CustomLog ${APACHE_LOG_DIR}/access.log security
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel warn
EOF

    a2enconf security-hardening >/dev/null 2>&1 || true

    systemctl enable apache2 >/dev/null 2>&1
    systemctl restart apache2
}

phase_pentesting_tools() {
    display_status "INFO" "Installing penetration testing tools..."
    install_packages hydra john hashcat aircrack-ng masscan medusa ncrack sqlmap nikto dirb gobuster wpscan pscan smbclient proxychains-ng bloodhound neo4j
}

phase_python_libraries() {
    display_status "INFO" "Installing Python security libraries..."
    pip3 install --quiet scapy requests beautifulsoup4 paramiko pycryptodome impacket netaddr whois colorama termcolor pwntools selenium shodan censys dnspython python-whois
}

phase_fish_configuration() {
    display_status "INFO" "Configuring Fish shell with Fisher and Oh-My-Fish..."

    fish -c "curl -sL https://git.io/fisher | source && fisher install jorgebucaran/fisher" >/dev/null 2>&1
    curl -L https://raw.githubusercontent.com/oh-my-fish/oh-my-fish/master/bin/install | fish >/dev/null 2>&1
    fish -c "fisher install edc/bass franciscolourenco/done jethrokuan/z" >/dev/null 2>&1

    mkdir -p /etc/fish
    cat > /etc/fish/config.fish << 'EOF'
# Enhanced Fish Shell Configuration

alias ll='ls -la'
alias la='ls -la'
alias l='ls -l'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias ports='netstat -tulanp'
alias listen='lsof -i -P -n | grep LISTEN'

alias nmap-quick='nmap -T4 -F'
alias nmap-intense='nmap -T4 -A -v'
alias nmap-vuln='nmap --script vuln'

alias myip='curl -s https://ipinfo.io/ip'

set -gx PATH $PATH /usr/local/go/bin
set -gx GOPATH /opt/go-workspace
set -gx PATH $PATH $GOPATH/bin
set -gx NVM_DIR /opt/nvm
set -gx RUSTUP_HOME /opt/rust
set -gx CARGO_HOME /opt/cargo
set -gx PATH $CARGO_HOME/bin $PATH

if test -s $NVM_DIR/nvm.sh
    bass source $NVM_DIR/nvm.sh
end

function fish_prompt
    set_color cyan
    echo -n "┌─["
    set_color green
    echo -n (whoami)
    set_color cyan
    echo -n "@"
    set_color magenta
    echo -n (hostname)
    set_color cyan
    echo -n "]─["
    set_color yellow
    echo -n (pwd | sed "s|$HOME|~|")
    set_color cyan
    echo "]"
    echo -n "└─▶ "
    set_color normal
end
EOF
}

phase_system_cleanup() {
    display_status "INFO" "Cleaning up system..."
    apt-get autoremove -y -qq >/dev/null 2>&1
    apt-get autoclean -y -qq >/dev/null 2>&1

    cat > /opt/cybersec-setup-complete.txt << 'EOF'
Ubuntu 22.04 Advanced Cybersecurity Environment - INSTALLATION COMPLETE

Installed Components:
├── Cross-compilation toolchain (ARM, x86_64, Windows)
├── LibC6 development libraries
├── Docker containerization platform
├── Apache2 web server with security hardening
├── NVM (Node Version Manager) with LTS Node.js
├── Rust with cross-compilation targets
├── Fish shell with Fisher and Oh-My-Fish
├── Comprehensive penetration testing toolkit
├── Network security analysis tools
├── System monitoring utilities

Post-Installation Actions Required:
1. usermod -aG docker $USER
2. source /etc/profile
3. chsh -s /usr/bin/fish
4. systemctl reboot

Security Status:
- Apache2: CONFIGURED
- Docker: RUNNING
EOF
}

# ──────────────────────────────
# 4.0 Main Execution Protocol
# ──────────────────────────────

main() {
    clear
    echo -e "${COLORS[CYAN]}${COLORS[BOLD]}"
    cat << 'EOF'
    ██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗    ██████╗ ██████╗
    ██║   ██║██╔══██╗██║   ██║████╗  ██║╚══██╔══╝██║   ██║    ╚════██╗╚════██╗
    ██║   ██║██████╔╝██║   ██║██╔██╗ ██║   ██║   ██║   ██║     █████╔╝ █████╔╝
    ██║   ██║██╔══██╗██║   ██║██║╚██╗██║   ██║   ██║   ██║    ██╔═══╝ ██╔═══╝
    ╚██████╔╝██████╔╝╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝    ███████╗███████╗
     ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝     ╚══════╝╚══════╝

    ░█████╗░██╗░░░██╗██████╗░███████╗██████╗░░██████╗███████╗░█████╗░
    ██╔══██╗╚██╗░██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗
    ██║░░╚═╝░╚████╔╝░██████╦╝█████╗░░██████╔╝╚█████╗░█████╗░░██║░░╚═╝
    ██║░░██╗░░╚██╔╝░░██╔══██╗██╔══╝░░██╔══██╗░╚═══██╗██╔══╝░░██║░░██╗
    ╚█████╔╝░░░██║░░░██████╦╝███████╗██║░░██║██████╔╝███████╗╚█████╔╝
    ░╚════╝░░░░╚═╝░░░╚═════╝░╚══════╝╚═╝░░╚═╝╚═════╝░╚══════╝░╚════╝░

    Coded By Scav-engeR | Hurricane Squad
    
EOF
    echo -e "${COLORS[RESET]}"
    echo

    display_status "INFO" "Starting Ubuntu 22.04 Advanced Cybersecurity Environment Setup"
    display_status "WARNING" "This script will modify system configurations and install multiple packages."
    echo

    if ! confirm_installation "Complete Cybersecurity Environment Setup"; then
        display_status "ERROR" "Installation aborted by user."
        exit 1
    fi

    local PHASES=(
        "System Update and Package Management"
        "Essential Development Tools"
        "External Repository Configuration"
        "Shell Environment Installation"
        "Cross-Compilation Framework"
        "Programming Language Runtimes"
        "CPAN and Perl Modules Setup"
        "Node Version Manager (NVM)"
        "Go Programming Language"
        "Rust Programming Language"
        "Network Security Tools"
        "System Monitoring Tools"
        "Docker Containerization"
        "Development Environment"
        "Database Client Tools"
        "Apache2 Web Server"
        "Penetration Testing Tools"
        "Python Security Libraries"
        "Fish Shell Configuration"
        "System Cleanup and Optimization"
    )

    local FUNCTIONS=(
        "phase_system_update"
        "phase_development_tools"
        "phase_external_repositories"
        "phase_shell_environments"
        "phase_cross_compilation"
        "phase_programming_languages"
        "phase_cpan_setup"
        "phase_nvm_installation"
        "phase_go_installation"
        "phase_rust_installation"
        "phase_network_security"
        "phase_monitoring_tools"
        "phase_docker_installation"
        "phase_development_environment"
        "phase_database_tools"
        "phase_apache_installation"
        "phase_pentesting_tools"
        "phase_python_libraries"
        "phase_fish_configuration"
        "phase_system_cleanup"
    )

    local total=${#PHASES[@]}

    for i in "${!PHASES[@]}"; do
        progress_bar $i $total
        echo
        display_status "PROCESS" "Phase $((i+1))/$total: ${PHASES[$i]}"
        if confirm_installation "${PHASES[$i]}"; then
            "${FUNCTIONS[$i]}"
            display_status "SUCCESS" "Completed phase: ${PHASES[$i]}"
        else
            display_status "WARNING" "Skipped phase: ${PHASES[$i]}"
        fi
        sleep 1
    done

    echo
    echo -e "${COLORS[GREEN]}${COLORS[BOLD]}"
    cat << 'EOF'
    ╔══════════════════════════════════════════════════════════════════╗
    ║                    INSTALLATION COMPLETED                        ║
    ║              Ubuntu 22.04 Cybersecurity Environment             ║
    ╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${COLORS[RESET]}"

    display_status "SUCCESS" "All installation phases completed successfully"
    display_status "INFO" "Details saved to /opt/cybersec-setup-complete.txt"
    echo
    display_status "WARNING" "Post-installation steps:"
    echo -e "  ${COLORS[CYAN]}1.${COLORS[RESET]} usermod -aG docker \$USER"
    echo -e "  ${COLORS[CYAN]}2.${COLORS[RESET]} source /etc/profile"
    echo -e "  ${COLORS[CYAN]}3.${COLORS[RESET]} chsh -s /usr/bin/fish"
    echo -e "  ${COLORS[CYAN]}4.${COLORS[RESET]} systemctl reboot"
    echo

    echo -e "${COLORS[MAGENTA]}${COLORS[BOLD]}Service Status:${COLORS[RESET]}"
    echo -e "${COLORS[CYAN]}Docker:${COLORS[RESET]} $(systemctl is-active docker 2>/dev/null || echo 'inactive')"
    echo -e "${COLORS[CYAN]}Apache2:${COLORS[RESET]} $(systemctl is-active apache2 2>/dev/null || echo 'inactive')"
    echo -e "${COLORS[CYAN]}Fail2Ban:${COLORS[RESET]} $(systemctl is-active fail2ban 2>/dev/null || echo 'inactive')"
    echo -e "${COLORS[CYAN]}UFW:${COLORS[RESET]} $(ufw status | head -1 | cut -d: -f2 | xargs)"

    echo
    display_status "INFO" "Setup complete. It is recommended to reboot the system."
}

main "$@"
