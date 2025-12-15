#!/bin/bash

# Colored output functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Banner function
print_banner() {
    clear
    echo -e "${CYAN}"
    echo -e
    echo -e " ██╗░░░██╗██╗██████╗░███████╗██████╗░"
    echo -e " ██║░░░██║██║██╔══██╗██╔════╝██╔══██╗"
    echo -e " ╚██╗░██╔╝██║██████╔╝█████╗░░██████╔╝"
    echo -e " ░╚████╔╝░██║██╔═══╝░██╔══╝░░██╔══██╗"
    echo -e " ░░╚██╔╝░░██║██║░░░░░███████╗██║░░██║"
    echo -e " ░░░╚═╝░░░╚═╝╚═╝░░░░░╚══════╝╚═╝░░╚═╝"
    echo "                                                          "
    echo -e "${YELLOW}                    Python Auto-Build Toolkit${NC}"
    echo -e "${CYAN}                        Coded By: Scav-engeR${NC}"
    echo -e "${PURPLE}              Interactive Python Source Builder${NC}"
    echo ""
}

# Function to print colored status messages
print_status() {
    case $1 in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $2"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $2"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $2"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $2"
            ;;
        *)
            echo -e "$1"
            ;;
    esac
}

# Check dependencies
check_dependencies() {
    print_status "INFO" "Checking required dependencies..."
    
    local deps=("wget" "build-essential" "libssl-dev" "zlib1g-dev" "libbz2-dev" 
                "libreadline-dev" "libsqlite3-dev" "libncursesw5-dev" 
                "xz-utils" "tk-dev" "libxml2-dev" "libxmlsec1-dev" 
                "libffi-dev" "liblzma-dev" "gcc" "make")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null && ! dpkg -l | grep -q "^ii  $dep "; then
            print_status "WARNING" "Missing dependency: $dep"
            MISSING_DEPS+=("$dep")
        fi
    done
    
    if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
        print_status "INFO" "Installing missing dependencies..."
        sudo apt update
        sudo apt install -y "${MISSING_DEPS[@]}"
    else
        print_status "SUCCESS" "All dependencies satisfied"
    fi
}

# Function to download Python source
download_python_source() {
    local version=$1
    local url="https://www.python.org/ftp/python/${version}/Python-${version}.tgz"
    
    print_status "INFO" "Downloading Python ${version} source code..."
    wget -c "$url" -O "Python-${version}.tgz" || {
        print_status "ERROR" "Failed to download Python ${version}"
        return 1
    }
    
    print_status "INFO" "Extracting Python ${version} source code..."
    tar -xzf "Python-${version}.tgz"
    cd "Python-${version}" || {
        print_status "ERROR" "Failed to enter Python ${version} directory"
        return 1
    }
}

# Function to fix shared library linking
fix_shared_library_linking() {
    local version=$1
    local prefix=$2
    
    print_status "INFO" "Fixing shared library linking for Python ${version}..."
    
    # Add Python library path to system linker configuration
    local lib_path="${prefix}/lib"
    local config_file="/etc/ld.so.conf.d/python-${version}.conf"
    
    # Create linker configuration file
    echo "${lib_path}" | sudo tee "${config_file}" > /dev/null
    
    # Update linker cache
    sudo ldconfig
    
    # Check if the specific library file exists and create symlink if needed
    local lib_name="libpython${version%.*}.so"
    local lib_target="${lib_path}/${lib_name}"
    
    if [ -f "${lib_target}" ]; then
        # Create versioned symlinks if they don't exist
        local major_minor_version="${version%.*}"
        local versioned_lib="${lib_path}/libpython${major_minor_version}.so.1.0"
        
        if [ ! -f "${versioned_lib}" ]; then
            sudo ln -sf "${lib_name}" "${versioned_lib}"
        fi
        
        # Also create the base versioned link
        local base_versioned_lib="${lib_path}/libpython${major_minor_version}.so.1"
        if [ ! -f "${base_versioned_lib}" ]; then
            sudo ln -sf "${lib_name}" "${base_versioned_lib}"
        fi
        
        print_status "SUCCESS" "Library linking configured for Python ${version}"
    else
        print_status "WARNING" "Main library file not found at ${lib_target}"
    fi
}

# Function to build Python from source
build_python() {
    local version=$1
    local prefix=$2
    local configure_flags=$3
    
    print_status "INFO" "Configuring Python ${version} with flags: $configure_flags"
    ./configure --prefix="$prefix" $configure_flags || {
        print_status "ERROR" "Configuration failed for Python ${version}"
        return 1
    }
    
    print_status "INFO" "Compiling Python ${version}..."
    make -j$(nproc) V=1 || {
        print_status "ERROR" "Compilation failed for Python ${version}"
        return 1
    }
    
    print_status "INFO" "Installing Python ${version} to $prefix..."
    sudo make altinstall || {
        print_status "ERROR" "Installation failed for Python ${version}"
        return 1
    }
    
    # Fix shared library linking after installation
    fix_shared_library_linking "$version" "$prefix"
    
    # Create symbolic links
    local major_minor_version="${version%.*}"
    if [[ "$version" == "2.7.18" ]]; then
        sudo ln -sf "${prefix}/bin/python2.7" "/usr/local/bin/python${version}"
        sudo ln -sf "${prefix}/bin/python2.7-config" "/usr/local/bin/python${version}-config"
    else
        sudo ln -sf "${prefix}/bin/python${major_minor_version}" "/usr/local/bin/python${version}"
        sudo ln -sf "${prefix}/bin/python${major_minor_version}-config" "/usr/local/bin/python${version}-config"
    fi
    
    print_status "SUCCESS" "Successfully installed Python ${version} to $prefix"
}

# Build Python 2.7
build_python27() {
    local version="2.7.18"
    local prefix="/opt/python-${version}"
    
    print_status "INFO" "Starting build process for Python ${version}"
    
    if [ ! -d "/opt/python-${version}" ]; then
        sudo mkdir -p "/opt/python-${version}"
    fi
    
    download_python_source "$version" || return 1
    
    # Apply patches for newer systems
    print_status "INFO" "Applying patches for newer systems..."
    sed -i 's/#define SIZEOF_TIME_T 8/#define SIZEOF_TIME_T 4/g' Modules/_ctypes/libffi/src/x86/darwin64.S
    sed -i 's/__FreeBSD_version < 800504/__FreeBSD_version < 800504 \&\& __FreeBSD_version >= 0/g' Modules/_cursesmodule.c
    
    build_python "$version" "$prefix" "--enable-optimizations --with-lto --enable-shared"
    
    cd .. && rm -rf "Python-${version}"
}

# Build Python 3.x versions
build_python3() {
    local version=$1
    local prefix="/opt/python-${version}"
    
    print_status "INFO" "Starting build process for Python ${version}"
    
    if [ ! -d "/opt/python-${version}" ]; then
        sudo mkdir -p "/opt/python-${version}"
    fi
    
    download_python_source "$version" || return 1
    
    # Determine configure flags based on version
    local configure_flags="--enable-optimizations --with-lto --enable-shared"
    if [[ "$version" =~ ^3\.[0-9]$ ]] || [[ "$version" =~ ^3\.1[0-4]$ ]]; then
        configure_flags="$configure_flags --with-system-expat --with-system-ffi --enable-loadable-sqlite-extensions"
    elif [[ "$version" =~ ^3\.1[5-9]$ ]]; then
        configure_flags="$configure_flags --with-system-expat --with-system-ffi --enable-loadable-sqlite-extensions --enable-option-checking=fatal"
    fi
    
    build_python "$version" "$prefix" "$configure_flags"
    
    cd .. && rm -rf "Python-${version}"
}

# Build Python 3.15 (if available)
build_python315() {
    local version="3.15.0a1"  # Placeholder for future version
    local prefix="/opt/python-${version}"
    
    print_status "INFO" "Attempting to build Python ${version} (pre-release)"
    
    # Check if this version exists on python.org
    if wget --spider "https://www.python.org/ftp/python/${version}/Python-${version}.tgz" 2>/dev/null; then
        if [ ! -d "/opt/python-${version}" ]; then
            sudo mkdir -p "/opt/python-${version}"
        fi
        
        download_python_source "$version" || return 1
        
        build_python "$version" "$prefix" "--enable-optimizations --with-lto --enable-shared --enable-option-checking=fatal"
        
        cd .. && rm -rf "Python-${version}"
    else
        print_status "WARNING" "Python ${version} not yet available. Checking for latest 3.15 pre-release..."
        # Try to find latest alpha/beta/rc version
        local latest_ver=$(curl -s https://www.python.org/ftp/python/ | grep -oP '(?<=href=")[0-9]+\.[0-9]+\.[0-9]+[a-zA-Z]*[0-9]+' | grep "3.15" | sort -V | tail -1)
        if [ -n "$latest_ver" ]; then
            print_status "INFO" "Found Python ${latest_ver}, attempting build..."
            build_python3 "$latest_ver"
        else
            print_status "ERROR" "No Python 3.15 version found"
            return 1
        fi
    fi
}

# List available Python versions
list_versions() {
    echo -e "${YELLOW}Available Python Versions:${NC}"
    echo "  1) Python 2.7.18"
    echo "  2) Python 3.6.15"
    echo "  3) Python 3.7.17"
    echo "  4) Python 3.8.18"
    echo "  5) Python 3.9.18"
    echo "  6) Python 3.10.13"
    echo "  7) Python 3.11.8"
    echo "  8) Python 3.12.2"
    echo "  9) Python 3.13.0 (pre-release)"
    echo "  10) Python 3.14.0 (pre-release)"
    echo "  11) Python 3.15.0 (pre-release)"
    echo "  12) Build All Versions"
    echo "  13) Exit"
    echo ""
}

# Main menu
show_menu() {
    while true; do
        print_banner
        list_versions
        read -p "$(echo -e ${CYAN}Select an option [1-13]: ${NC})" choice
        
        case $choice in
            1)
                check_dependencies
                build_python27
                read -p "Press Enter to continue..."
                ;;
            2)
                check_dependencies
                build_python3 "3.6.15"
                read -p "Press Enter to continue..."
                ;;
            3)
                check_dependencies
                build_python3 "3.7.17"
                read -p "Press Enter to continue..."
                ;;
            4)
                check_dependencies
                build_python3 "3.8.18"
                read -p "Press Enter to continue..."
                ;;
            5)
                check_dependencies
                build_python3 "3.9.18"
                read -p "Press Enter to continue..."
                ;;
            6)
                check_dependencies
                build_python3 "3.10.13"
                read -p "Press Enter to continue..."
                ;;
            7)
                check_dependencies
                build_python3 "3.11.8"
                read -p "Press Enter to continue..."
                ;;
            8)
                check_dependencies
                build_python3 "3.12.2"
                read -p "Press Enter to continue..."
                ;;
            9)
                check_dependencies
                build_python3 "3.13.0a7"  # Using latest alpha as example
                read -p "Press Enter to continue..."
                ;;
            10)
                check_dependencies
                build_python3 "3.14.0a1"  # Using latest alpha as example
                read -p "Press Enter to continue..."
                ;;
            11)
                check_dependencies
                build_python315
                read -p "Press Enter to continue..."
                ;;
            12)
                check_dependencies
                print_status "INFO" "Building all Python versions sequentially..."
                for ver in "2.7.18" "3.6.15" "3.7.17" "3.8.18" "3.9.18" "3.10.13" "3.11.8" "3.12.2"; do
                    print_status "INFO" "Building Python $ver..."
                    build_python3 "$ver" || print_status "WARNING" "Failed to build Python $ver"
                done
                read -p "Press Enter to continue..."
                ;;
            13)
                print_status "INFO" "Exiting Python Auto-Build Toolkit"
                exit 0
                ;;
            *)
                print_status "ERROR" "Invalid option. Please select 1-13."
                sleep 2
                ;;
        esac
    done
}

# Start the toolkit
show_menu
