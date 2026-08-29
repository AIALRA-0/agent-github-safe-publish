param(
    [Parameter(Mandatory = $true)]
    [string]$Destination
)

$ErrorActionPreference = 'Stop'
$runtimeRoot = [System.IO.Path]::GetFullPath($Destination)

# Create a repository-external virtual environment so parser packages cannot alter the project interpreter
python -m venv $runtimeRoot

# Upgrade the packaging tools inside the isolated environment before installing the locked parser set
& "$runtimeRoot\Scripts\python.exe" -m pip install --upgrade pip

# Install the exact Windows parser versions, including the bundled libmagic runtime
& "$runtimeRoot\Scripts\python.exe" -m pip install -r "$PSScriptRoot\..\requirements-gate.txt"

# Download the pinned Gitleaks release and verify its official checksum
& "$runtimeRoot\Scripts\python.exe" -c "import sys; sys.path.insert(0, sys.argv[1]); import safe_publish; safe_publish.ensure_gitleaks()" $PSScriptRoot

# Run the read-only diagnostic and fail when a required parser remains unavailable
& "$runtimeRoot\Scripts\python.exe" "$PSScriptRoot\safe_publish.py" doctor --all
