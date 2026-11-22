param([switch]$Stop, [string]$BackendEnvFile, [string]$PythonPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$stateRoot = Join-Path $repoRoot '.local-preview'
$stateFile = Join-Path $stateRoot 'processes.json'

if ($Stop) {
    if (Test-Path -LiteralPath $stateFile) {
        $record = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
        foreach ($entry in $record.processes) {
            $process = Get-Process -Id $entry.id -ErrorAction SilentlyContinue
            if ($process -and $process.StartTime.ToUniversalTime().ToString('o') -eq $entry.started) {
                Stop-Process -Id $process.Id
            }
        }
        Remove-Item -LiteralPath $stateFile
    }
    exit
}

if (-not $BackendEnvFile -or -not (Test-Path -LiteralPath $BackendEnvFile -PathType Leaf)) {
    throw 'Pass -BackendEnvFile with the reviewed real-source backend configuration. This launcher does not generate sample data.'
}
$sourceEnvironmentPath = (Resolve-Path -LiteralPath $BackendEnvFile).Path

foreach ($portNumber in @(5173, 8000)) {
    if (Get-NetTCPConnection -LocalPort $portNumber -State Listen -ErrorAction SilentlyContinue) {
        throw "Port $portNumber is already in use. Open the running preview or stop its owner first."
    }
}
New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
$venv = Join-Path $repoRoot '.venv'
$python = if ($PythonPath) { (Resolve-Path -LiteralPath $PythonPath).Path } else { Join-Path $venv 'Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $python)) {
    py -3.12 -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create Python 3.12 environment.' }
    & $python -m pip install -r (Join-Path $repoRoot 'backend\requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed.' }
}
if (Select-String -LiteralPath $sourceEnvironmentPath -Pattern '^OPENSTACK_SSH_RELAY_CONFIG=' -Quiet) {
    & $python -c 'import importlib.util,sys; sys.exit(0 if importlib.util.find_spec("paramiko") else 1)'
    if ($LASTEXITCODE -ne 0) {
        & $python -m pip install -r (Join-Path $repoRoot 'backend\requirements-ssh.txt')
        if ($LASTEXITCODE -ne 0) { throw 'SSH transport dependency installation failed.' }
    }
}
$frontend = Join-Path $repoRoot 'fe-api-staging'
if (-not (Test-Path -LiteralPath (Join-Path $frontend 'node_modules'))) {
    Push-Location $frontend
    try {
        npm.cmd ci --no-fund --no-audit
        if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
    } finally { Pop-Location }
}

$backendProcess = Start-Process -FilePath $python -ArgumentList @('-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000', '--env-file', ('"' + $sourceEnvironmentPath + '"')) -WorkingDirectory (Join-Path $repoRoot 'backend') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $stateRoot 'backend.stdout.log') -RedirectStandardError (Join-Path $stateRoot 'backend.stderr.log')
$priorPreview = $env:VITE_LOCAL_PREVIEW
$env:VITE_LOCAL_PREVIEW = $null
try {
    $frontendProcess = Start-Process -FilePath (Get-Command node.exe).Source -ArgumentList @('node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--configLoader', 'native') -WorkingDirectory $frontend -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $stateRoot 'frontend.stdout.log') -RedirectStandardError (Join-Path $stateRoot 'frontend.stderr.log')
} catch {
    Stop-Process -Id $backendProcess.Id
    throw
} finally { $env:VITE_LOCAL_PREVIEW = $priorPreview }

@{ processes = @($backendProcess, $frontendProcess) | ForEach-Object { @{ id = $_.Id; started = $_.StartTime.ToUniversalTime().ToString('o') } } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $stateFile -Encoding UTF8
Write-Host 'Frontend: http://127.0.0.1:5173/'
Write-Host 'Backend:  http://127.0.0.1:8000/docs'
Write-Host 'Using the supplied real-source configuration; verify source fields and freshness before acceptance.'
