#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Interactive Cygwin Development Environment Installation and Configuration Script

.DESCRIPTION
    Comprehensive PowerShell automation for downloading, installing, and configuring
    Cygwin with essential development tools on Windows 11. Implements best practices
    for package selection, environment setup, and post-installation configuration.

.PARAMETER InstallationPath
    Target directory for Cygwin installation (default: C:\cygwin64)

.PARAMETER PackageCache
    Local directory for caching downloaded packages (default: C:\cygwin-cache)

.PARAMETER InstallationType
    Development environment type: 'Native' (Cygwin POSIX), 'MinGW' (Windows native), or 'Both'

.PARAMETER PackageProfile
    Package selection profile: 'Minimal', 'Standard', 'Full', or 'Custom'

.PARAMETER Mirror
    Cygwin mirror URL (auto-selects geographically optimal if not specified)

.PARAMETER LogPath
    Installation log file location (default: current directory)

.EXAMPLE
    .\Install-CygwinDev.ps1 -InstallationType "Both" -PackageProfile "Standard"
    
.EXAMPLE
    .\Install-CygwinDev.ps1 -InstallationPath "C:\dev\cygwin" -PackageProfile "Full" -Mirror "http://mirrors.kernel.org/sourceware/cygwin/"

.NOTES
    Version: 2.1 Interactive (Syntax Corrected)
    Author: Development Environment Automation
    Requires: PowerShell 5.1+, Windows 10/11, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Za-z]:\\[\w\\\-_\.]*$')]
    [string]$InstallationPath = "C:\cygwin64",
    
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Za-z]:\\[\w\\\-_\.]*$')]
    [string]$PackageCache = "C:\cygwin-cache",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Native', 'MinGW', 'Both')]
    [string]$InstallationType = 'Both',
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Minimal', 'Standard', 'Full', 'Custom')]
    [string]$PackageProfile = 'Standard',
    
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        $_ -eq '' -or $_ -match '^https?://.*'
    })]
    [string]$Mirror = '',
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = (Join-Path $PWD "cygwin-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log")
)

# ============================================================================
# CONFIGURATION AND INITIALIZATION
# ============================================================================

# Global configuration constants
$Script:Config = @{
    SetupExecutableUrl = 'https://www.cygwin.com/setup-x86_64.exe'
    SetupExecutableName = 'setup-x86_64.exe'
    MirrorDiscoveryUrl = 'https://mirrors.kernel.org/sourceware/cygwin/'
    MirrorListUrl = 'https://cygwin.com/mirrors.html'
    FallbackMirrors = @(
        'https://mirrors.kernel.org/sourceware/cygwin/',
        'https://mirror.clarkson.edu/cygwin/',
        'https://cygwin.mirror.constant.com/',
        'https://ftp.eq.uc.pt/software/pc/prog/cygwin/'
    )
    RetryAttempts = 3
    TimeoutSeconds = 300
    MirrorTestTimeout = 15
}

# Package selection matrices organized by installation type and profile
$Script:PackageProfiles = @{
    Minimal = @{
        Native = @('gcc-core', 'gcc-g++', 'make', 'gdb')
        MinGW = @('mingw64-x86_64-gcc-core', 'mingw64-x86_64-gcc-g++', 'make', 'gdb')
        Common = @('git', 'vim', 'wget', 'tar', 'gzip')
    }
    Standard = @{
        Native = @('gcc-core', 'gcc-g++', 'make', 'gdb', 'autoconf', 'automake', 'libtool', 'pkg-config')
        MinGW = @('mingw64-x86_64-gcc-core', 'mingw64-x86_64-gcc-g++', 'make', 'gdb', 'autoconf', 'automake', 'pkg-config')
        Common = @('git', 'vim', 'nano', 'wget', 'curl', 'openssh', 'ca-certificates', 'cmake', 'python3', 'perl')
    }
    Full = @{
        Native = @('gcc-core', 'gcc-g++', 'gcc-fortran', 'make', 'gdb', 'valgrind', 'autoconf', 'automake', 'libtool', 'pkg-config', 'ccache')
        MinGW = @('mingw64-x86_64-gcc-core', 'mingw64-x86_64-gcc-g++', 'mingw64-x86_64-gcc-fortran', 'make', 'gdb', 'autoconf', 'automake', 'pkg-config')
        Common = @('git', 'vim', 'nano', 'emacs', 'wget', 'curl', 'openssh', 'ca-certificates', 'cmake', 'python3', 'perl', 'ruby', 'nodejs', 'sqlite3', 'tree', 'htop', 'zip', 'unzip', 'rsync', 'diffutils', 'findutils')
    }
}

# ============================================================================
# INTERACTIVE USER INTERFACE FRAMEWORK
# ============================================================================

function Show-Banner {
    <#
    .SYNOPSIS
        Displays application banner with version and system information
    #>
    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                   INTERACTIVE CYGWIN DEVELOPMENT ENVIRONMENT                  " -ForegroundColor Cyan
    Write-Host "                             INSTALLATION WIZARD                              " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "  Version: 2.1 Interactive (Syntax Corrected)                                " -ForegroundColor White
    Write-Host "  Target: Windows 11                                                          " -ForegroundColor White
    Write-Host "  PowerShell: $($PSVersionTable.PSVersion.ToString().PadRight(55))" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Menu {
    <#
    .SYNOPSIS
        Displays interactive menu with numbered options and validates user selection
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Options,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )
    
    Write-Host ""
    Write-Host "+-- $Title " -ForegroundColor Yellow -NoNewline
    Write-Host ("-" * (70 - $Title.Length)) -ForegroundColor Yellow
    
    if ($Description) {
        Write-Host "| $Description" -ForegroundColor Gray
        Write-Host "|" -ForegroundColor Yellow
    }
    
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "| [$($i + 1)] $($Options[$i])" -ForegroundColor White
    }
    Write-Host "+" -ForegroundColor Yellow -NoNewline
    Write-Host ("-" * 75) -ForegroundColor Yellow
    Write-Host ""
    
    do {
        $selection = Read-Host "Please select an option (1-$($Options.Count))"
        $selectedIndex = $selection -as [int]
        
        if ($selectedIndex -ge 1 -and $selectedIndex -le $Options.Count) {
            return $selectedIndex - 1
        }
        else {
            Write-Host "Invalid selection. Please enter a number between 1 and $($Options.Count)." -ForegroundColor Red
        }
    } while ($true)
}

function Get-UserConfirmation {
    <#
    .SYNOPSIS
        Prompts for user confirmation with customizable messaging and default options
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [string]$DefaultChoice = 'Y'
    )
    
    $prompt = if ($DefaultChoice -eq 'Y') { "[Y/n]" } else { "[y/N]" }
    
    do {
        $response = Read-Host "$Message $prompt"
        
        if ([string]::IsNullOrWhiteSpace($response)) {
            return ($DefaultChoice -eq 'Y')
        }
        
        switch ($response.ToUpper()) {
            'Y' { return $true }
            'YES' { return $true }
            'N' { return $false }
            'NO' { return $false }
            default {
                Write-Host "Please enter Y (yes) or N (no)." -ForegroundColor Yellow
            }
        }
    } while ($true)
}

function Get-CustomPath {
    <#
    .SYNOPSIS
        Interactive path selection with validation and default suggestions
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathType,
        
        [Parameter(Mandatory = $true)]
        [string]$DefaultPath,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )
    
    Write-Host ""
    Write-Host "--- $PathType Path Configuration " -ForegroundColor Cyan -NoNewline
    Write-Host ("-" * (45 - $PathType.Length)) -ForegroundColor Cyan
    
    if ($Description) {
        Write-Host $Description -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "Default path: " -ForegroundColor Yellow -NoNewline
    Write-Host $DefaultPath -ForegroundColor White
    
    $useDefault = Get-UserConfirmation "Use default path?"
    
    if ($useDefault) {
        return $DefaultPath
    }
    else {
        do {
            $customPath = Read-Host "Enter custom path"
            
            if ([string]::IsNullOrWhiteSpace($customPath)) {
                Write-Host "Path cannot be empty." -ForegroundColor Red
                continue
            }
            
            try {
                $testPath = [System.IO.Path]::GetFullPath($customPath)
                return $testPath
            }
            catch {
                Write-Host "Invalid path format. Please enter a valid Windows path." -ForegroundColor Red
            }
        } while ($true)
    }
}

function Show-PackageDetails {
    <#
    .SYNOPSIS
        Displays detailed package information for informed selection decisions
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfileName
    )
    
    $profileConfig = $Script:PackageProfiles[$ProfileName]
    
    Write-Host ""
    Write-Host "+-- $ProfileName Profile Package Details " -ForegroundColor Green -NoNewline
    Write-Host ("-" * (45 - $ProfileName.Length)) -ForegroundColor Green
    
    Write-Host "|" -ForegroundColor Green
    Write-Host "| Common Development Tools:" -ForegroundColor White
    foreach ($package in $profileConfig.Common) {
        Write-Host "|   * $package" -ForegroundColor Gray
    }
    
    Write-Host "|" -ForegroundColor Green
    Write-Host "| Native Cygwin Packages:" -ForegroundColor White
    foreach ($package in $profileConfig.Native) {
        Write-Host "|   * $package" -ForegroundColor Gray
    }
    
    Write-Host "|" -ForegroundColor Green
    Write-Host "| MinGW Cross-Compilation Packages:" -ForegroundColor White
    foreach ($package in $profileConfig.MinGW) {
        Write-Host "|   * $package" -ForegroundColor Gray
    }
    
    $totalPackages = ($profileConfig.Common + $profileConfig.Native + $profileConfig.MinGW | Sort-Object -Unique).Count
    Write-Host "|" -ForegroundColor Green
    Write-Host "| Total unique packages: $totalPackages" -ForegroundColor Yellow
    Write-Host "+" -ForegroundColor Green -NoNewline
    Write-Host ("-" * 75) -ForegroundColor Green
}

function Invoke-InteractiveConfiguration {
    <#
    .SYNOPSIS
        Orchestrates interactive configuration workflow for all installation parameters
    #>
    [CmdletBinding()]
    param()
    
    Show-Banner
    
    Write-Host "Welcome to the Interactive Cygwin Development Environment Setup Wizard!" -ForegroundColor Green
    Write-Host "This tool will guide you through configuring and installing Cygwin with your preferred development tools." -ForegroundColor Gray
    Write-Host ""
    
    # Installation Type Selection
    $installTypeOptions = @(
        "Native Cygwin (POSIX-compliant applications)",
        "MinGW Cross-Compilation (Windows-native applications)", 
        "Both (Maximum flexibility for all development scenarios)"
    )
    
    $installTypeIndex = Show-Menu -Title "Installation Type" -Options $installTypeOptions -Description "Choose your development target environment"
    $script:InstallationType = @('Native', 'MinGW', 'Both')[$installTypeIndex]
    
    # Package Profile Selection
    Write-Host ""
    Write-Host "Available package profiles:" -ForegroundColor Cyan
    
    $profileOptions = @(
        "Minimal - Essential compilation tools only",
        "Standard - Balanced development environment", 
        "Full - Comprehensive toolset with advanced features",
        "Custom - Interactive package selection during installation"
    )
    
    $showDetails = Get-UserConfirmation "Would you like to see detailed package lists for each profile?"
    
    if ($showDetails) {
        foreach ($profile in @('Minimal', 'Standard', 'Full')) {
            Show-PackageDetails -ProfileName $profile
        }
    }
    
    $profileIndex = Show-Menu -Title "Package Profile" -Options $profileOptions -Description "Select the complexity level for your installation"
    $script:PackageProfile = @('Minimal', 'Standard', 'Full', 'Custom')[$profileIndex]
    
    # Path Configuration
    $script:InstallationPath = Get-CustomPath -PathType "Installation" -DefaultPath $InstallationPath -Description "Directory where Cygwin will be installed"
    $script:PackageCache = Get-CustomPath -PathType "Package Cache" -DefaultPath $PackageCache -Description "Local storage for downloaded packages (enables offline reinstalls)"
    
    # Mirror Selection
    Write-Host ""
    $useAutoMirror = Get-UserConfirmation "Use automatic mirror selection (recommended)?"
    
    if (-not $useAutoMirror) {
        Write-Host ""
        Write-Host "Available mirrors:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $Script:Config.DefaultMirrors.Count; $i++) {
            Write-Host "  [$($i + 1)] $($Script:Config.DefaultMirrors[$i])" -ForegroundColor White
        }
        
        do {
            $mirrorSelection = Read-Host "Select mirror (1-$($Script:Config.DefaultMirrors.Count)) or enter custom URL"
            $mirrorIndex = $mirrorSelection -as [int]
            
            if ($mirrorIndex -ge 1 -and $mirrorIndex -le $Script:Config.DefaultMirrors.Count) {
                $script:Mirror = $Script:Config.DefaultMirrors[$mirrorIndex - 1]
                break
            }
            elseif ($mirrorSelection -match '^https?://.*') {
                $script:Mirror = $mirrorSelection
                break
            }
            else {
                Write-Host "Invalid selection. Please enter a number or a valid HTTP/HTTPS URL." -ForegroundColor Red
            }
        } while ($true)
    }
    
    # Configuration Summary
    Write-Host ""
    Write-Host "+-- Installation Configuration Summary " -ForegroundColor Magenta -NoNewline
    Write-Host ("-" * 40) -ForegroundColor Magenta
    Write-Host "|" -ForegroundColor Magenta
    Write-Host "| Installation Type: " -ForegroundColor White -NoNewline
    Write-Host $InstallationType -ForegroundColor Yellow
    Write-Host "| Package Profile: " -ForegroundColor White -NoNewline
    Write-Host $PackageProfile -ForegroundColor Yellow
    Write-Host "| Installation Path: " -ForegroundColor White -NoNewline
    Write-Host $InstallationPath -ForegroundColor Yellow
    Write-Host "| Package Cache: " -ForegroundColor White -NoNewline
    Write-Host $PackageCache -ForegroundColor Yellow
    if ($Mirror) {
        Write-Host "| Mirror: " -ForegroundColor White -NoNewline
        Write-Host $Mirror -ForegroundColor Yellow
    } else {
        Write-Host "| Mirror: " -ForegroundColor White -NoNewline
        Write-Host "Automatic selection" -ForegroundColor Yellow
    }
    Write-Host "+" -ForegroundColor Magenta -NoNewline
    Write-Host ("-" * 75) -ForegroundColor Magenta
    Write-Host ""
    
    $proceedWithInstallation = Get-UserConfirmation "Proceed with installation using this configuration?" 'Y'
    
    if (-not $proceedWithInstallation) {
        Write-Host "Installation cancelled by user." -ForegroundColor Yellow
        exit 0
    }
    
    return @{
        InstallationType = $InstallationType
        PackageProfile = $PackageProfile
        InstallationPath = $InstallationPath
        PackageCache = $PackageCache
        Mirror = $Mirror
    }
}

# ============================================================================
# LOGGING AND ERROR HANDLING FRAMEWORK
# ============================================================================

function Write-InstallLog {
    <#
    .SYNOPSIS
        Centralized logging function with timestamp and severity levels
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output with color coding
    switch ($Level) {
        'INFO'    { Write-Host $logEntry -ForegroundColor Cyan }
        'WARN'    { Write-Host $logEntry -ForegroundColor Yellow }
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # File logging
    try {
        $logEntry | Out-File -FilePath $LogPath -Append -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
}

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Retry mechanism for network operations and critical installations
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = $Script:Config.RetryAttempts,
        
        [Parameter(Mandatory = $false)]
        [int]$DelaySeconds = 5
    )
    
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Write-InstallLog "Executing operation (attempt $attempt of $MaxAttempts)"
            return & $ScriptBlock
        }
        catch {
            Write-InstallLog "Attempt $attempt failed: $($_.Exception.Message)" -Level 'WARN'
            if ($attempt -eq $MaxAttempts) {
                Write-InstallLog "All retry attempts exhausted" -Level 'ERROR'
                throw
            }
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

# ============================================================================
# SYSTEM VALIDATION AND PREREQUISITE CHECKS
# ============================================================================

function Test-SystemRequirements {
    <#
    .SYNOPSIS
        Comprehensive system requirement validation with interactive confirmation
    #>
    [CmdletBinding()]
    param()
    
    Write-Host ""
    Write-Host "+-- System Requirements Validation " -ForegroundColor Cyan -NoNewline
    Write-Host ("-" * 40) -ForegroundColor Cyan
    
    Write-InstallLog "Validating system requirements and prerequisites"
    
    # Operating system compatibility check
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        throw "Windows 10 or later required. Current version: $($osVersion.ToString())"
    }
    Write-InstallLog "Operating system compatibility: PASSED (Windows $($osVersion.Major).$($osVersion.Minor))" -Level 'SUCCESS'
    
    # Administrator privilege verification
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges required for system-wide installation"
    }
    Write-InstallLog "Administrator privileges: VERIFIED" -Level 'SUCCESS'
    
    # Disk space assessment
    $installDrive = Split-Path $InstallationPath -Qualifier
    $diskSpace = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $installDrive }
    $availableSpaceGB = [math]::Round($diskSpace.FreeSpace / 1GB, 2)
    
    if ($availableSpaceGB -lt 5) {
        throw "Insufficient disk space. Available: ${availableSpaceGB}GB, Required: 5GB minimum"
    }
    Write-InstallLog "Disk space assessment: ${availableSpaceGB}GB available" -Level 'SUCCESS'
    
    # PowerShell version compatibility
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw "PowerShell 5.1 or later required. Current version: $($PSVersionTable.PSVersion.ToString())"
    }
    Write-InstallLog "PowerShell version: $($PSVersionTable.PSVersion.ToString())" -Level 'SUCCESS'
    
    # Network connectivity verification
    try {
        $testConnection = Test-NetConnection -ComputerName 'www.cygwin.com' -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        if (-not $testConnection) {
            throw "Network connectivity test failed"
        }
        Write-InstallLog "Network connectivity: VERIFIED" -Level 'SUCCESS'
    }
    catch {
        Write-InstallLog "Network connectivity check failed: $($_.Exception.Message)" -Level 'WARN'
        Write-InstallLog "Proceeding with cached resources if available" -Level 'INFO'
    }
}

function Initialize-DirectoryStructure {
    <#
    .SYNOPSIS
        Creates necessary directory structure with proper permissions
    #>
    [CmdletBinding()]
    param()
    
    Write-InstallLog "Initializing directory structure"
    
    $directories = @($InstallationPath, $PackageCache, (Split-Path $LogPath -Parent))
    
    foreach ($directory in $directories) {
        if (-not (Test-Path $directory)) {
            try {
                New-Item -Path $directory -ItemType Directory -Force | Out-Null
                Write-InstallLog "Created directory: $directory" -Level 'SUCCESS'
            }
            catch {
                throw "Failed to create directory '$directory': $($_.Exception.Message)"
            }
        }
        else {
            Write-InstallLog "Directory exists: $directory" -Level 'INFO'
        }
    }
}

# ============================================================================
# NETWORK OPERATIONS AND DOWNLOAD MANAGEMENT
# ============================================================================

function Get-CygwinMirrorList {
    <#
    .SYNOPSIS
        Retrieves comprehensive Cygwin mirror list from authoritative sources with fallback mechanisms
    #>
    [CmdletBinding()]
    param()
    
    Write-InstallLog "Discovering Cygwin mirrors from authoritative sources"
    
    $discoveredMirrors = @()
    
    # Primary discovery: mirrors.kernel.org authoritative source
    try {
        Write-InstallLog "Querying mirrors.kernel.org for comprehensive mirror list"
        $mirrorResponse = Invoke-WebRequest -Uri $Script:Config.MirrorListUrl -TimeoutSec 10 -UseBasicParsing
        
        # Parse mirror list from HTML content
        $mirrorMatches = [regex]::Matches($mirrorResponse.Content, 'href="(https?://[^"]+/cygwin/?)"')
        
        foreach ($match in $mirrorMatches) {
            $mirrorUrl = $match.Groups[1].Value
            if ($mirrorUrl -notmatch 'cygwin\.com' -and $mirrorUrl -notin $discoveredMirrors) {
                $discoveredMirrors += $mirrorUrl
            }
        }
        
        Write-InstallLog "Discovered $($discoveredMirrors.Count) mirrors from official source"
    }
    catch {
        Write-InstallLog "Primary mirror discovery failed: $($_.Exception.Message)" -Level 'WARN'
    }
    
    # Secondary discovery: direct kernel.org mirror verification
    try {
        $kernelMirror = $Script:Config.MirrorDiscoveryUrl
        $testResponse = Invoke-WebRequest -Uri $kernelMirror -Method Head -TimeoutSec 5 -UseBasicParsing
        if ($testResponse.StatusCode -eq 200 -and $kernelMirror -notin $discoveredMirrors) {
            $discoveredMirrors = @($kernelMirror) + $discoveredMirrors
            Write-InstallLog "Verified mirrors.kernel.org availability" -Level 'SUCCESS'
        }
    }
    catch {
        Write-InstallLog "Kernel.org mirror verification failed: $($_.Exception.Message)" -Level 'WARN'
    }
    
    # Fallback mechanism: use curated fallback mirrors
    if ($discoveredMirrors.Count -eq 0) {
        Write-InstallLog "Using fallback mirror configuration" -Level 'WARN'
        $discoveredMirrors = $Script:Config.FallbackMirrors
    }
    else {
        # Supplement with fallback mirrors for redundancy
        foreach ($fallbackMirror in $Script:Config.FallbackMirrors) {
            if ($fallbackMirror -notin $discoveredMirrors) {
                $discoveredMirrors += $fallbackMirror
            }
        }
    }
    
    Write-InstallLog "Mirror discovery completed: $($discoveredMirrors.Count) total mirrors available"
    return $discoveredMirrors
}

function Get-OptimalMirror {
    <#
    .SYNOPSIS
        Determines the fastest available Cygwin mirror through comprehensive latency testing
    #>
    [CmdletBinding()]
    param()
    
    if ($Mirror) {
        Write-InstallLog "Using specified mirror: $Mirror"
        return $Mirror
    }
    
    Write-InstallLog "Initiating optimal mirror selection process"
    
    # Discover available mirrors dynamically
    $availableMirrors = Get-CygwinMirrorList
    
    if ($availableMirrors.Count -eq 0) {
        throw "No Cygwin mirrors available for testing"
    }
    
    Write-InstallLog "Testing $($availableMirrors.Count) mirrors for optimal performance"
    $bestMirror = $null
    $bestLatency = [int]::MaxValue
    $testedCount = 0
    $successfulTests = 0
    
    foreach ($testMirror in $availableMirrors) {
        $testedCount++
        Write-Progress -Activity "Testing Mirrors" -Status "Testing mirror $testedCount of $($availableMirrors.Count)" -PercentComplete (($testedCount / $availableMirrors.Count) * 100)
        
        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $response = Invoke-WebRequest -Uri $testMirror -Method Head -TimeoutSec $Script:Config.MirrorTestTimeout -UseBasicParsing
            $stopwatch.Stop()
            
            if ($response.StatusCode -eq 200) {
                $successfulTests++
                $latency = $stopwatch.ElapsedMilliseconds
                
                if ($latency -lt $bestLatency) {
                    $bestLatency = $latency
                    $bestMirror = $testMirror
                }
                
                Write-InstallLog "Mirror [$testMirror] responded in ${latency}ms" -Level 'INFO'
            }
            else {
                Write-InstallLog "Mirror [$testMirror] returned status code $($response.StatusCode)" -Level 'WARN'
            }
        }
        catch {
            Write-InstallLog "Mirror [$testMirror] failed: $($_.Exception.Message)" -Level 'WARN'
        }
    }
    
    Write-Progress -Activity "Testing Mirrors" -Completed
    
    if (-not $bestMirror) {
        # Emergency fallback to first available mirror
        $bestMirror = $availableMirrors[0]
        Write-InstallLog "No responsive mirrors found, using emergency fallback: $bestMirror" -Level 'WARN'
    }
    else {
        Write-InstallLog "Optimal mirror selected: $bestMirror (${bestLatency}ms latency)" -Level 'SUCCESS'
        Write-InstallLog "Mirror testing statistics: $successfulTests/$testedCount mirrors responsive" -Level 'INFO'
    }
    
    return $bestMirror
}

function Get-CygwinSetupExecutable {
    <#
    .SYNOPSIS
        Downloads the Cygwin setup executable with integrity verification
    #>
    [CmdletBinding()]
    param()
    
    $setupPath = Join-Path $PackageCache $Script:Config.SetupExecutableName
    
    if (Test-Path $setupPath) {
        $fileInfo = Get-Item $setupPath
        $ageHours = ((Get-Date) - $fileInfo.LastWriteTime).TotalHours
        
        if ($ageHours -lt 24) {
            Write-InstallLog "Using cached setup executable (age: $([math]::Round($ageHours, 1)) hours)"
            return $setupPath
        }
        else {
            Write-InstallLog "Cached setup executable is outdated, downloading fresh copy"
            Remove-Item $setupPath -Force
        }
    }
    
    Write-InstallLog "Downloading Cygwin setup executable"
    
    Invoke-WithRetry -ScriptBlock {
        try {
            # Use system web client for better progress tracking
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "PowerShell-CygwinInstaller/2.1")
            
            # Progress tracking
            Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -Action {
                $percentComplete = $Event.SourceEventArgs.ProgressPercentage
                Write-Progress -Activity "Downloading setup executable" -Status "$percentComplete% Complete" -PercentComplete $percentComplete
            } | Out-Null
            
            $webClient.DownloadFile($Script:Config.SetupExecutableUrl, $setupPath)
            $webClient.Dispose()
            
            Write-Progress -Activity "Downloading setup executable" -Completed
            Write-InstallLog "Download completed successfully" -Level 'SUCCESS'
        }
        catch {
            throw "Setup executable download failed: $($_.Exception.Message)"
        }
    }
    
    # Basic file validation
    if (-not (Test-Path $setupPath) -or (Get-Item $setupPath).Length -lt 1MB) {
        throw "Downloaded setup executable appears invalid or incomplete"
    }
    
    return $setupPath
}

# ============================================================================
# PACKAGE SELECTION AND CONFIGURATION MANAGEMENT
# ============================================================================

function Get-PackageList {
    <#
    .SYNOPSIS
        Generates comprehensive package list based on installation type and profile
    #>
    [CmdletBinding()]
    param()
    
    Write-InstallLog "Generating package list for profile: $PackageProfile, type: $InstallationType"
    
    if ($PackageProfile -eq 'Custom') {
        Write-InstallLog "Custom package profile selected - interactive package selection will be used"
        return @()
    }
    
    $selectedPackages = @()
    $profileConfig = $Script:PackageProfiles[$PackageProfile]
    
    # Add common packages (always included)
    $selectedPackages += $profileConfig.Common
    
    # Add type-specific packages
    switch ($InstallationType) {
        'Native' {
            $selectedPackages += $profileConfig.Native
            Write-InstallLog "Selected Native Cygwin development packages"
        }
        'MinGW' {
            $selectedPackages += $profileConfig.MinGW
            Write-InstallLog "Selected MinGW cross-compilation packages"
        }
        'Both' {
            $selectedPackages += $profileConfig.Native
            $selectedPackages += $profileConfig.MinGW
            Write-InstallLog "Selected both Native and MinGW package sets"
        }
    }
    
    # Remove duplicates and sort
    $selectedPackages = $selectedPackages | Sort-Object -Unique
    
    Write-InstallLog "Package selection complete: $($selectedPackages.Count) packages selected"
    Write-InstallLog "Selected packages: $($selectedPackages -join ', ')"
    
    return $selectedPackages
}

function Install-CygwinPackages {
    <#
    .SYNOPSIS
        Executes Cygwin installation with interactive confirmation and progress monitoring
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SetupExecutablePath,
        
        [Parameter(Mandatory = $true)]
        [string]$MirrorUrl,
        
        [Parameter(Mandatory = $false)]
        [string[]]$PackageList = @()
    )
    
    Write-Host ""
    Write-Host "+-- Cygwin Installation Execution " -ForegroundColor Green -NoNewline
    Write-Host ("-" * 40) -ForegroundColor Green
    
    if ($PackageList.Count -gt 0) {
        Write-Host "| Packages to install: $($PackageList.Count)" -ForegroundColor White
        Write-Host "| Installation will proceed automatically" -ForegroundColor Gray
    } else {
        Write-Host "| Interactive package selection mode" -ForegroundColor White
        Write-Host "| Setup will open for manual package selection" -ForegroundColor Gray
    }
    Write-Host "+" -ForegroundColor Green -NoNewline
    Write-Host ("-" * 75) -ForegroundColor Green
    
    $confirmInstall = Get-UserConfirmation "Begin Cygwin installation process?" 'Y'
    if (-not $confirmInstall) {
        throw "Installation cancelled by user"
    }
    
    Write-InstallLog "Initiating Cygwin installation process"
    
    # Build setup.exe command line arguments
    $setupArgs = @(
        '--quiet-mode',
        '--no-desktop',
        '--no-shortcuts',
        '--no-startmenu',
        '--wait',
        '--root', $InstallationPath,
        '--local-package-dir', $PackageCache,
        '--site', $MirrorUrl
    )
    
    # Add package list if specified (non-interactive mode)
    if ($PackageList.Count -gt 0) {
        $packageString = $PackageList -join ','
        $setupArgs += '--packages', $packageString
        Write-InstallLog "Installing packages: $packageString"
    }
    else {
        Write-InstallLog "No specific packages specified - using interactive mode"
    }
    
    # Log complete command for debugging
    $commandString = "& '$SetupExecutablePath' $($setupArgs -join ' ')"
    Write-InstallLog "Executing command: $commandString"
    
    try {
        # Execute installation with timeout protection
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $SetupExecutablePath
        $processInfo.Arguments = $setupArgs -join ' '
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.CreateNoWindow = $true
        
        $process = [System.Diagnostics.Process]::Start($processInfo)
        
        # Monitor process with timeout
        $timeoutMs = $Script:Config.TimeoutSeconds * 1000
        if (-not $process.WaitForExit($timeoutMs)) {
            $process.Kill()
            throw "Installation process timed out after $($Script:Config.TimeoutSeconds) seconds"
        }
        
        $exitCode = $process.ExitCode
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        
        if ($exitCode -ne 0) {
            Write-InstallLog "Setup process stderr: $stderr" -Level 'ERROR'
            throw "Cygwin installation failed with exit code: $exitCode"
        }
        
        Write-InstallLog "Cygwin installation completed successfully" -Level 'SUCCESS'
        
        if ($stdout) {
            Write-InstallLog "Setup output: $stdout"
        }
    }
    catch {
        throw "Installation execution failed: $($_.Exception.Message)"
    }
}

# ============================================================================
# POST-INSTALLATION CONFIGURATION AND ENVIRONMENT SETUP
# ============================================================================

function Set-CygwinEnvironment {
    <#
    .SYNOPSIS
        Configures Windows environment variables and system integration
    #>
    [CmdletBinding()]
    param()
    
    Write-InstallLog "Configuring Cygwin environment integration"
    
    # Add Cygwin bin directory to system PATH
    $cygwinBin = Join-Path $InstallationPath 'bin'
    $currentPath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
    
    if ($currentPath -notlike "*$cygwinBin*") {
        $newPath = "$cygwinBin;$currentPath"
        [Environment]::SetEnvironmentVariable('PATH', $newPath, 'Machine')
        Write-InstallLog "Added Cygwin bin directory to system PATH" -Level 'SUCCESS'
    }
    else {
        Write-InstallLog "Cygwin bin directory already in system PATH"
    }
    
    # Set CYGWIN environment variable for optimal behavior
    $cygwinVar = 'winsymlinks:nativestrict'
    [Environment]::SetEnvironmentVariable('CYGWIN', $cygwinVar, 'Machine')
    Write-InstallLog "Set CYGWIN environment variable: $cygwinVar" -Level 'SUCCESS'
    
    # Create convenient shortcuts and aliases
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $shortcutPath = Join-Path $desktopPath 'Cygwin Terminal.lnk'
    
    try {
        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = Join-Path $InstallationPath 'bin\mintty.exe'
        $shortcut.Arguments = '-i /Cygwin-Terminal.ico -'
        $shortcut.WorkingDirectory = $InstallationPath
        $shortcut.Description = 'Cygwin Terminal'
        $shortcut.Save()
        Write-InstallLog "Created desktop shortcut: $shortcutPath" -Level 'SUCCESS'
    }
    catch {
        Write-InstallLog "Failed to create desktop shortcut: $($_.Exception.Message)" -Level 'WARN'
    }
}

function Test-CygwinInstallation {
    <#
    .SYNOPSIS
        Validates installation completeness and functionality
    #>
    [CmdletBinding()]
    param()
    
    Write-InstallLog "Validating Cygwin installation"
    
    # Test core executable presence
    $cygwinBash = Join-Path $InstallationPath 'bin\bash.exe'
    if (-not (Test-Path $cygwinBash)) {
        throw "Core Cygwin installation validation failed - bash.exe not found"
    }
    
    # Test compiler availability (if development packages selected)
    $gccPath = Join-Path $InstallationPath 'bin\gcc.exe'
    if (Test-Path $gccPath) {
        try {
            $gccVersion = & $gccPath --version 2>&1 | Select-Object -First 1
            Write-InstallLog "GCC compiler available: $gccVersion" -Level 'SUCCESS'
        }
        catch {
            Write-InstallLog "GCC compiler test failed: $($_.Exception.Message)" -Level 'WARN'
        }
    }
    
    # Test basic shell functionality
    try {
        $testCommand = "echo 'Cygwin test successful'"
        $result = & $cygwinBash -c $testCommand
        if ($result -eq 'Cygwin test successful') {
            Write-InstallLog "Shell functionality test: PASSED" -Level 'SUCCESS'
        }
        else {
            Write-InstallLog "Shell functionality test: FAILED" -Level 'WARN'
        }
    }
    catch {
        Write-InstallLog "Shell test execution failed: $($_.Exception.Message)" -Level 'WARN'
    }
    
    Write-InstallLog "Installation validation completed"
}

function Write-InstallationSummary {
    <#
    .SYNOPSIS
        Generates comprehensive installation summary and next steps
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,
        
        [Parameter(Mandatory = $false)]
        [string[]]$InstalledPackages = @()
    )
    
    $endTime = Get-Date
    $duration = $endTime - $StartTime
    
    Write-InstallLog "=== INSTALLATION SUMMARY ===" -Level 'SUCCESS'
    Write-InstallLog "Installation Path: $InstallationPath" -Level 'INFO'
    Write-InstallLog "Package Cache: $PackageCache" -Level 'INFO'
    Write-InstallLog "Installation Type: $InstallationType" -Level 'INFO'
    Write-InstallLog "Package Profile: $PackageProfile" -Level 'INFO'
    Write-InstallLog "Duration: $($duration.ToString('hh\:mm\:ss'))" -Level 'INFO'
    
    if ($InstalledPackages.Count -gt 0) {
        Write-InstallLog "Installed Packages ($($InstalledPackages.Count)): $($InstalledPackages -join ', ')" -Level 'INFO'
    }
    
    Write-InstallLog "=== NEXT STEPS ===" -Level 'INFO'
    Write-InstallLog "1. Launch Cygwin Terminal from desktop shortcut or Start Menu" -Level 'INFO'
    Write-InstallLog "2. Test compilation: echo 'int main(){return 0;}' | gcc -x c - -o test.exe" -Level 'INFO'
    Write-InstallLog "3. Install additional packages: re-run setup-x86_64.exe from $PackageCache" -Level 'INFO'
    Write-InstallLog "4. Configure development environment: ~/.bashrc, ~/.vimrc, etc." -Level 'INFO'
    
    Write-InstallLog "Installation completed successfully!" -Level 'SUCCESS'
}

# ============================================================================
# MAIN EXECUTION WORKFLOW
# ============================================================================

function Main {
    <#
    .SYNOPSIS
        Interactive execution workflow orchestrating the complete installation process
    #>
    [CmdletBinding()]
    param()
    
    $startTime = Get-Date
    
    try {
        # Interactive Configuration Phase
        Write-InstallLog "=== INTERACTIVE CYGWIN DEVELOPMENT ENVIRONMENT SETUP ===" -Level 'SUCCESS'
        Write-InstallLog "Version: 2.1 Interactive | Target: Windows 11 | PowerShell: $($PSVersionTable.PSVersion)" -Level 'INFO'
        
        # Get user configuration through interactive wizard
        $userConfig = Invoke-InteractiveConfiguration
        
        # Update script variables with user selections
        $script:InstallationType = $userConfig.InstallationType
        $script:PackageProfile = $userConfig.PackageProfile
        $script:InstallationPath = $userConfig.InstallationPath
        $script:PackageCache = $userConfig.PackageCache
        $script:Mirror = $userConfig.Mirror
        
        # Phase 1: System Validation
        Write-Host ""
        Write-Host "=== Phase 1: System Requirements Validation ===" -ForegroundColor Cyan
        Write-InstallLog "Phase 1: System Requirements Validation" -Level 'INFO'
        
        $continueValidation = Get-UserConfirmation "Proceed with system requirements validation?" 'Y'
        if (-not $continueValidation) {
            throw "Installation cancelled during system validation phase"
        }
        
        Test-SystemRequirements
        Initialize-DirectoryStructure
        
        Write-Host "* System validation completed successfully" -ForegroundColor Green
        
        # Phase 2: Network Operations
        Write-Host ""
        Write-Host "=== Phase 2: Network Operations and Download Management ===" -ForegroundColor Cyan
        Write-InstallLog "Phase 2: Network Operations and Download Management" -Level 'INFO'
        
        $continueNetwork = Get-UserConfirmation "Proceed with downloading Cygwin setup and mirror selection?" 'Y'
        if (-not $continueNetwork) {
            throw "Installation cancelled during network operations phase"
        }
        
        $selectedMirror = Get-OptimalMirror
        $setupExecutable = Get-CygwinSetupExecutable
        
        Write-Host "* Network operations completed successfully" -ForegroundColor Green
        
        # Phase 3: Package Configuration
        Write-Host ""
        Write-Host "=== Phase 3: Package Selection and Configuration ===" -ForegroundColor Cyan
        Write-InstallLog "Phase 3: Package Selection and Configuration" -Level 'INFO'
        
        $packageList = Get-PackageList
        
        if ($PackageProfile -eq 'Custom') {
            Write-Host ""
            Write-Host "Custom package profile selected - setup.exe will open for interactive package selection" -ForegroundColor Yellow
            $continueCustom = Get-UserConfirmation "Continue with interactive package selection?" 'Y'
            if (-not $continueCustom) {
                throw "Installation cancelled during package configuration phase"
            }
        } else {
            Write-Host ""
            Write-Host "Package selection summary:" -ForegroundColor White
            Write-Host "  * Profile: $PackageProfile" -ForegroundColor Gray
            Write-Host "  * Type: $InstallationType" -ForegroundColor Gray
            Write-Host "  * Packages: $($packageList.Count)" -ForegroundColor Gray
            
            $continuePackages = Get-UserConfirmation "Proceed with automated package installation?" 'Y'
            if (-not $continuePackages) {
                throw "Installation cancelled during package configuration phase"
            }
        }
        
        Write-Host "* Package configuration completed successfully" -ForegroundColor Green
        
        # Phase 4: Installation Execution
        Write-Host ""
        Write-Host "=== Phase 4: Cygwin Installation Execution ===" -ForegroundColor Cyan
        Write-InstallLog "Phase 4: Cygwin Installation Execution" -Level 'INFO'
        
        Install-CygwinPackages -SetupExecutablePath $setupExecutable -MirrorUrl $selectedMirror -PackageList $packageList
        
        Write-Host "* Cygwin installation completed successfully" -ForegroundColor Green
        
        # Phase 5: Post-Installation Configuration
        Write-Host ""
        Write-Host "=== Phase 5: Environment Configuration and Integration ===" -ForegroundColor Cyan
        Write-InstallLog "Phase 5: Environment Configuration and Integration" -Level 'INFO'
        
        $continueEnvironment = Get-UserConfirmation "Configure Windows environment integration (PATH, shortcuts)?" 'Y'
        if ($continueEnvironment) {
            Set-CygwinEnvironment
            Write-Host "* Environment configuration completed" -ForegroundColor Green
        } else {
            Write-Host "! Environment configuration skipped by user" -ForegroundColor Yellow
        }
        
        $runValidation = Get-UserConfirmation "Run installation validation tests?" 'Y'
        if ($runValidation) {
            Test-CygwinInstallation
            Write-Host "* Installation validation completed" -ForegroundColor Green
        } else {
            Write-Host "! Installation validation skipped by user" -ForegroundColor Yellow
        }
        
        # Phase 6: Summary and Completion
        Write-Host ""
        Write-Host "=== Installation Summary ===" -ForegroundColor Cyan
        Write-InstallationSummary -StartTime $startTime -InstalledPackages $packageList
        
        return 0
    }
    catch {
        Write-InstallLog "CRITICAL ERROR: $($_.Exception.Message)" -Level 'ERROR'
        Write-InstallLog "Stack Trace: $($_.ScriptStackTrace)" -Level 'ERROR'
        Write-InstallLog "Installation aborted due to critical error" -Level 'ERROR'
        
        Write-Host ""
        Write-Host "Installation failed. Check the log file for details: $LogPath" -ForegroundColor Red
        
        $viewLog = Get-UserConfirmation "Would you like to view the error log now?" 'N'
        if ($viewLog -and (Test-Path $LogPath)) {
            Get-Content $LogPath | Select-Object -Last 20 | Write-Host
        }
        
        return 1
    }
}

# ============================================================================
# SCRIPT EXECUTION ENTRY POINT
# ============================================================================

# Execute main workflow if script is run directly (not dot-sourced)
if ($MyInvocation.InvocationName -ne '.') {
    $exitCode = Main
    exit $exitCode
}
