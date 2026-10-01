<#
.SYNOPSIS
    Build the Go programs of this repository for several target
    platforms.

.DESCRIPTION
    Works in any Go module without changes: drop it next to go.mod
    and run it. Nothing about the project is hard-coded - the
    programs to build and their names are discovered with go list.

    Puts one executable per program and platform into the
    _gitignore directory (add it to .gitignore so binaries never
    end up in the repository; the script warns if it is not
    ignored). The file name includes the platform, so builds lying
    side by side cannot be mixed up:

        myapp_windows_amd64.exe
        myapp_windows_arm64.exe
        myapp_linux_amd64

    Every main package of the module is built: the module root,
    cmd/* or anywhere else. A program is named the way go build
    names it - after the last element of its import path, with a
    major version suffix such as /v2 skipped.

    cgo is disabled by default, so cross-compilation needs neither
    a C toolchain nor any extra installs: go is enough. Use -Cgo
    for projects that need it.

.PARAMETER Targets
    Platforms in os/arch form. Defaults to windows/amd64
    and windows/arm64. Valid values are printed by -List.

.PARAMETER All
    Build a common set of platforms instead of the default
    list.

.PARAMETER List
    Show the platforms supported by the installed Go
    and build nothing.

.PARAMETER Packages
    Packages to build, as go build accepts them: ".", "./cmd/foo"
    or an import path. Defaults to every main package of the
    module.

.PARAMETER OutDir
    Output directory, relative to the script directory or
    absolute. Defaults to _gitignore.

.PARAMETER Name
    Base file name. Defaults to the name go build would use.
    Allowed only when a single package is built.

.PARAMETER Cgo
    Keep cgo as the environment has it instead of disabling it.
    Cross-compilation then needs a C toolchain for each target.

.PARAMETER Race
    Build with the race detector. Works only for the current
    platform, needs cgo and noticeably slows the program down -
    for debugging.

.EXAMPLE
    .\build.ps1
    Windows amd64 and arm64.

.EXAMPLE
    .\build.ps1 -Targets linux/amd64, darwin/arm64
    Arbitrary platforms.

.EXAMPLE
    .\build.ps1 -All
    Common set: Windows, Linux, macOS.

.EXAMPLE
    .\build.ps1 -Packages ./cmd/server -Name server
    A single program under a chosen name.

.EXAMPLE
    .\build.ps1 -List
    What the installed Go can do at all.
#>

[CmdletBinding()]
param(

    [string[]] $Targets,

    [switch] $All,

    [switch] $List,

    [string[]] $Packages,

    [string] $OutDir = "_gitignore",

    [string] $Name,

    [switch] $Cgo,

    [switch] $Race
)

$ErrorActionPreference = "Stop"

# Default platforms: what is needed most often.
$defaultTargets = @(
    "windows/amd64"
    "windows/arm64"
)

# Set for -All: Windows, Linux and macOS on both architectures,
# plus 32-bit Windows and ARM for single-board computers.
$commonTargets = @(
    "windows/386"
    "windows/amd64"
    "windows/arm64"
    "linux/386"
    "linux/amd64"
    "linux/arm"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
)

# The name go build gives a binary: the last element of the
# import path, except that a major version suffix (/v2, /v3...)
# is skipped in favour of the element before it.
function Get-BinaryName([string] $importPath) {

    $elements = $importPath.TrimEnd("/") -split "/"
    $result = $elements[-1]

    if ($elements.Count -gt 1 -and $result -match '^v[0-9]+$') {
        $result = $elements[-2]
    }

    return $result
}


# ---------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------

$go = Get-Command go -ErrorAction SilentlyContinue

if (-not $go) {
    Write-Error "go not found in PATH: install Go or add it to PATH"
    exit 1
}

# Work relative to the script directory, not the current one:
# a double click and a run from another directory must
# give the same result. Every go command gets -C $root for that.
$root = $PSScriptRoot

if (-not $root) {
    $root = (Get-Location).Path
}

if (-not (Test-Path (Join-Path $root "go.mod"))) {
    Write-Error "go.mod not found in $root - put the script in the module root"
    exit 1
}

# List of platforms the installed Go understands.
# It also serves as a typo check for -Targets.
$supported = & go tool dist list

if ($LASTEXITCODE -ne 0) {
    Write-Error "failed to get the platform list (go tool dist list)"
    exit 1
}


# ---------------------------------------------------------------
# Platform listing mode
# ---------------------------------------------------------------

if ($List) {

    Write-Host "Platforms supported by $(& go version):" -ForegroundColor Cyan
    Write-Host ""

    $supported |
        Group-Object { ($_ -split "/")[0] } |
        ForEach-Object {

            $architectures = ($_.Group | ForEach-Object { ($_ -split "/")[1] }) -join ", "

            "{0,-12} {1}" -f $_.Name, $architectures
        }

    Write-Host ""
    Write-Host "Example: .\build.ps1 -Targets linux/amd64, darwin/arm64"

    exit 0
}


# ---------------------------------------------------------------
# Platform selection
# ---------------------------------------------------------------

if ($Targets) {

    $selected = $Targets

} elseif ($All) {

    $selected = $commonTargets

} else {

    $selected = $defaultTargets
}

# Normalize and remove duplicates: "windows/AMD64" and
# "windows/amd64" are the same thing.
$selected = @(
    $selected |
        ForEach-Object { $_.Trim().ToLowerInvariant() } |
        Where-Object { $_ } |
        Select-Object -Unique
)

$unknown = $selected | Where-Object { $supported -notcontains $_ }

if ($unknown) {

    Write-Error (
        "unknown platforms: {0}`n" -f ($unknown -join ", ") +
        "the full list is printed by .\build.ps1 -List"
    )

    exit 1
}

if ($Race -and $selected.Count -gt 1) {

    Write-Error "-Race builds only for the current platform: specify a single -Targets"
    exit 1
}


# ---------------------------------------------------------------
# Package selection
# ---------------------------------------------------------------

# go list resolves both the default (every main package) and
# explicit -Packages to import paths, which also gives the
# binary names. The template uses a raw `main` string because
# double quotes inside native arguments get mangled by older
# PowerShell versions.
# @() matters: splatting a lone string passes it char by char.
$patterns = @(if ($Packages) { $Packages } else { "./..." })

$listed = & go -C $root list -f '{{if eq .Name `main`}}{{.ImportPath}}{{end}}' @patterns

if ($LASTEXITCODE -ne 0) {
    Write-Error "failed to list packages (go list)"
    exit 1
}

$programs = @($listed | Where-Object { $_ } | Select-Object -Unique)

if (-not $programs) {

    if ($Packages) {
        Write-Error ("no main packages among: {0}" -f ($Packages -join ", "))
    } else {
        Write-Error "no main packages found in $root - nothing to build"
    }

    exit 1
}

if ($Name -and $programs.Count -gt 1) {

    Write-Error (
        "-Name needs a single package, found {0}: {1}`n" -f $programs.Count, ($programs -join ", ") +
        "pick one with -Packages"
    )

    exit 1
}

# Two programs with the same name would overwrite each other's
# files, e.g. ./cmd/tool and ./tools/tool.
$duplicates = $programs |
    Group-Object { Get-BinaryName $_ } |
    Where-Object { $_.Count -gt 1 }

if ($duplicates) {

    Write-Error (
        "packages share a binary name: {0}`n" -f (($duplicates | ForEach-Object { $_.Group -join " and " }) -join "; ") +
        "build them one at a time with -Packages and -Name"
    )

    exit 1
}


# ---------------------------------------------------------------
# Directory preparation
# ---------------------------------------------------------------

# Combine rather than Join-Path so that an absolute -OutDir wins.
$outPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($root, $OutDir))

if (-not (Test-Path $outPath)) {

    New-Item -ItemType Directory -Path $outPath | Out-Null

    Write-Host "Created directory $outPath"
}

# In a fresh repository the output directory is easy to forget
# in .gitignore. Exit code 1 means "not ignored"; anything else
# (no git, not a repository, a path outside it) is not our concern.
if (Get-Command git -ErrorAction SilentlyContinue) {

    & git -C $root check-ignore -q -- $outPath 2>$null

    if ($LASTEXITCODE -eq 1) {
        Write-Warning "$outPath is not in .gitignore - binaries may get committed"
    }
}


# ---------------------------------------------------------------
# Build
# ---------------------------------------------------------------

Write-Host ""
Write-Host ("Building {0} -> {1}" -f ($programs -join ", "), $outPath) -ForegroundColor Cyan
Write-Host ""

# Remember the previous values: the script may have been run
# in a session where GOOS/GOARCH are already needed by something.
$savedGOOS = $env:GOOS
$savedGOARCH = $env:GOARCH
$savedCGO = $env:CGO_ENABLED

$built = @()
$failed = @()

try {

    # Without cgo, cross-compilation needs no C toolchain. The
    # race detector is built on cgo, so -Race keeps it as well.
    if (-not ($Cgo -or $Race)) {
        $env:CGO_ENABLED = "0"
    }

    foreach ($program in $programs) {

        $baseName = if ($Name) { $Name } else { Get-BinaryName $program }

        foreach ($target in $selected) {

            $parts = $target -split "/"
            $os = $parts[0]
            $arch = $parts[1]

            $suffix = if ($os -eq "windows") { ".exe" } else { "" }

            $fileName = "{0}_{1}_{2}{3}" -f $baseName, $os, $arch, $suffix
            $filePath = Join-Path $outPath $fileName

            # Field widths are fixed so that the sizes line up
            # in a column.
            Write-Host ("  {0,-16} -> {1,-32}" -f $target, $fileName) -NoNewline

            $env:GOOS = $os
            $env:GOARCH = $arch

            # -trimpath strips build machine paths from the binary,
            # -s -w drop the symbol table and debug information:
            # the file gets roughly a quarter smaller.
            $arguments = @(
                "-C", $root
                "build"
                "-trimpath"
                "-ldflags", "-s -w"
            )

            if ($Race) {
                $arguments += "-race"
            }

            $arguments += @("-o", $filePath, $program)

            $output = & go @arguments 2>&1

            if ($LASTEXITCODE -ne 0) {

                Write-Host "  FAILED" -ForegroundColor Red
                Write-Host ($output | Out-String)

                $failed += "$baseName ($target)"

                continue
            }

            $size = (Get-Item $filePath).Length

            Write-Host ("  {0,8:N1} MB" -f ($size / 1MB)) -ForegroundColor Green

            $built += [PSCustomObject]@{
                Platform = $target
                File     = $fileName
                Size     = "{0:N1} MB" -f ($size / 1MB)
            }
        }
    }

} finally {

    $env:GOOS = $savedGOOS
    $env:GOARCH = $savedGOARCH
    $env:CGO_ENABLED = $savedCGO
}


# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------

Write-Host ""

if ($built) {
    $built | Format-Table -AutoSize
}

if ($failed) {

    Write-Host ("Failed to build: {0}" -f ($failed -join ", ")) -ForegroundColor Red

    exit 1
}

Write-Host ("Done: {0} file(s) in {1}" -f $built.Count, $outPath) -ForegroundColor Green
