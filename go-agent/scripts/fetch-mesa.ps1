# Fetch Mesa3D x64 software OpenGL DLLs for Fyne UI on VMs (one-click installer).
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$mesaDir = Join-Path $repoRoot "Engine\Mesa"
$cache = Join-Path $mesaDir "_cache"
$opengl = Join-Path $mesaDir "opengl32.dll"
$gallium = Join-Path $mesaDir "libgallium_wgl.dll"

New-Item -ItemType Directory -Force -Path $mesaDir, $cache | Out-Null

if ((Test-Path $opengl) -and (Test-Path $gallium)) {
    Write-Host "Mesa DLLs already present in Engine\Mesa"
    exit 0
}

$ver = "26.1.3"
$name = "mesa3d-$ver-release-msvc.7z"
$url = "https://github.com/pal1000/mesa-dist-win/releases/download/$ver/$name"
$archive = Join-Path $cache $name

if (-not (Test-Path $archive)) {
    Write-Host "Downloading $url ..."
    Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
}

$seven = @(
    "C:\Program Files\7-Zip\7z.exe",
    "C:\Program Files (x86)\7-Zip\7z.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $seven) {
    throw "7-Zip not found. Install 7-Zip or place Mesa DLLs in Engine\Mesa manually."
}

$extract = Join-Path $cache "extract"
if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
New-Item -ItemType Directory -Force -Path $extract | Out-Null
& $seven x $archive "-o$extract" -y | Out-Null

$src = Join-Path $extract "x64"
Copy-Item (Join-Path $src "opengl32.dll") $opengl -Force
Copy-Item (Join-Path $src "libgallium_wgl.dll") $gallium -Force
New-Item -ItemType File -Force -Path (Join-Path $mesaDir "insite-agent.exe.local") | Out-Null

Write-Host "Mesa ready:"
Get-Item $opengl, $gallium | Select-Object Name, Length
