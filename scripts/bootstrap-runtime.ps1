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

# Run the read-only diagnostic and fail when a required parser remains unavailable
& "$runtimeRoot\Scripts\python.exe" "$PSScriptRoot\safe_publish.py" doctor --all
