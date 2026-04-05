$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$tempRoot = Join-Path $env:TEMP 'vantor_validation'
$binaryCandidates = @(
    (Join-Path $repoRoot 'target\debug\vantor.exe'),
    (Join-Path $repoRoot 'target\debug\forensic_cli.exe')
)

function Resolve-CliBinary {
    foreach ($candidate in $binaryCandidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    throw 'CLI binary not found after build.'
}

function Test-Envelope {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        return @{ Ok = $false; Reason = 'output file missing' }
    }

    try {
        $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return @{ Ok = $false; Reason = 'invalid json' }
    }

    $required = @('tool_version', 'timestamp_utc', 'platform', 'command', 'args', 'status', 'exit_code', 'elapsed_ms')
    foreach ($field in $required) {
        if (-not ($json.PSObject.Properties.Name -contains $field)) {
            return @{ Ok = $false; Reason = "missing field: $field" }
        }
    }

    if ($json.status -notin @('ok', 'warn', 'error')) {
        return @{ Ok = $false; Reason = 'status must be ok, warn, or error' }
    }

    if ($json.exit_code -isnot [int] -and $json.exit_code -isnot [long]) {
        return @{ Ok = $false; Reason = 'exit_code must be an integer' }
    }

    if ($json.elapsed_ms -isnot [int] -and $json.elapsed_ms -isnot [long]) {
        return @{ Ok = $false; Reason = 'elapsed_ms must be an integer' }
    }

    if ([int64]$json.elapsed_ms -lt 0) {
        return @{ Ok = $false; Reason = 'elapsed_ms must be non-negative' }
    }

    return @{ Ok = $true; Reason = 'valid envelope' }
}

try {
    if (Test-Path $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $tempRoot | Out-Null

    Push-Location $repoRoot
    try {
        cargo build -p vantor-shield-cli
        if ($LASTEXITCODE -ne 0) {
            throw 'cargo build failed'
        }
    }
    finally {
        Pop-Location
    }

    $cliPath = Resolve-CliBinary
    $commands = @(
        @{ Name = 'capabilities'; Args = @('capabilities') },
        @{ Name = 'doctor'; Args = @('doctor') }
    )

    $failed = $false
    foreach ($entry in $commands) {
        $jsonPath = Join-Path $tempRoot ($entry.Name + '.json')
        $stdoutPath = Join-Path $tempRoot ($entry.Name + '.stdout.txt')
        $stderrPath = Join-Path $tempRoot ($entry.Name + '.stderr.txt')

        & $cliPath @($entry.Args + @('--json-result', $jsonPath, '--quiet')) 1> $stdoutPath 2> $stderrPath
        $validation = Test-Envelope -Path $jsonPath

        if ($validation.Ok) {
            Write-Host "PASS $($entry.Name)"
        }
        else {
            Write-Host "FAIL $($entry.Name): $($validation.Reason)"
            $failed = $true
        }
    }

    if ($failed) {
        exit 1
    }
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
