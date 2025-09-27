# PowerShell test script for Ghidra path detection
Write-Host "Testing Ghidra Path Detection" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green

# Search locations
$searchPaths = @(
    "$env:USERPROFILE\development\ghidra_*",
    "$env:USERPROFILE\dev\ghidra_*",
    "$env:USERPROFILE\Downloads\ghidra_*",
    "C:\ghidra_*",
    "C:\Tools\ghidra_*"
)

$foundGhidra = $null

foreach ($pathPattern in $searchPaths) {
    Write-Host "Searching: $pathPattern" -ForegroundColor Yellow
    $matches = Get-ChildItem -Path $pathPattern -Directory -ErrorAction SilentlyContinue

    foreach ($match in $matches) {
        $ghidraRunPath = Join-Path $match.FullName "ghidraRun.bat"
        Write-Host "  Checking: $($match.FullName)" -ForegroundColor Cyan

        if (Test-Path $ghidraRunPath) {
            $foundGhidra = $match.FullName
            Write-Host "  Found Ghidra at: $foundGhidra" -ForegroundColor Green
            break
        }
    }

    if ($foundGhidra) { break }
}

if ($foundGhidra) {
    Write-Host "`nGhidra Installation: $foundGhidra" -ForegroundColor Green

    # Test version detection
    $propsFile = Join-Path $foundGhidra "Ghidra\application.properties"
    if (Test-Path $propsFile) {
        $version = (Get-Content $propsFile | Where-Object { $_ -match "application.version=" }) -replace "application.version=", ""
        Write-Host "Ghidra Version: $version" -ForegroundColor Green

        # Test extensions directory detection
        $ghidraUserDir = "$env:USERPROFILE\.ghidra"
        $suffixes = @("_DEV", "_PUBLIC", "_build", "")

        foreach ($suffix in $suffixes) {
            $testDir = "$ghidraUserDir\.ghidra_$version$suffix"
            Write-Host "Testing directory: $testDir" -ForegroundColor Cyan

            if (Test-Path $testDir) {
                $extensionsDir = "$testDir\Extensions"
                Write-Host "Found extensions directory: $extensionsDir" -ForegroundColor Green

                if (Test-Path $extensionsDir) {
                    Write-Host "Extensions directory exists and is accessible" -ForegroundColor Green
                } else {
                    Write-Host "Extensions directory would be created" -ForegroundColor Yellow
                }
                break
            }
        }
    }
} else {
    Write-Host "No Ghidra installation found" -ForegroundColor Red
}

Write-Host "`nTest completed!" -ForegroundColor Green