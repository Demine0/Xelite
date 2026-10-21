<#
.SYNOPSIS
  Builds the Xelite .appx for Windows 10 Mobile (ARM) or a Windows PC (x64).

.DESCRIPTION
  Requirements (Windows 10/11):
    * Visual Studio 2019 or 2022 with the "Universal Windows Platform development"
      workload and the "C++ (v142) Universal Windows Platform tools" for ARM
    * Windows 10 SDK 10.0.19041.0
    * Go 1.25.x on PATH (only if build\<Platform>\xelite-core.exe is not already built;
      Go 1.26+ no longer supports 32-bit windows/arm)

.EXAMPLE
  .\build.ps1                      # Release|ARM -> dist\
  .\build.ps1 -Platform x64        # desktop build for testing
#>
param(
    [ValidateSet("ARM", "x64")] [string] $Platform = "ARM",
    [ValidateSet("Release", "Debug")] [string] $Configuration = "Release"
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

# 1. Go engine
$core = Join-Path $root "build\$Platform\xelite-core.exe"
if (-not (Test-Path $core)) {
    # build-core.sh vendors Xray-core and applies core/patches; run it with Git Bash or WSL.
    throw "$core is missing. Run ./build-core.sh first (Git Bash, WSL, macOS or Linux)."
}

# 2. VPN plug-in host (C++/WinRT, no XAML), see host\XeliteVpnHost.cpp
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvarsall.bat"
$hostArch = if ($Platform -eq "ARM") { "x86_arm" } else { "x86_amd64" }
$hostExe = Join-Path $root "build\$Platform\XeliteVpnHost.exe"
$hostSrc = Join-Path $root "host\XeliteVpnHost.cpp"
$hostObj = Join-Path $root "build\$Platform\XeliteVpnHost.obj"
$cl = "cl /nologo /std:c++17 /EHsc /O2 /MD /DUNICODE /D_UNICODE /DWINAPI_FAMILY=WINAPI_FAMILY_APP " +
      "/Fo`"$hostObj`" `"$hostSrc`" /link /SUBSYSTEM:WINDOWS /APPCONTAINER WindowsApp.lib /OUT:`"$hostExe`""
& cmd /c "call `"$vcvars`" $hostArch store 10.0.19041.0 >nul && $cl"
if ($LASTEXITCODE -or -not (Test-Path $hostExe)) { throw "building XeliteVpnHost.exe failed" }

# 3. Signing certificate (self-signed, Publisher must match the manifest: CN=Xelite)
$pfx = Join-Path $root "app\Xelite\Xelite_TemporaryKey.pfx"
$cer = Join-Path $root "dist\Xelite.cer"
New-Item -ItemType Directory -Force (Join-Path $root "dist") | Out-Null
if (-not (Test-Path $pfx)) {
    $cert = New-SelfSignedCertificate -Type Custom -Subject "CN=Xelite" -KeyUsage DigitalSignature `
        -FriendlyName "Xelite sideload" -CertStoreLocation "Cert:\CurrentUser\My" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
    $pfxPassword = New-Object System.Security.SecureString
    Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pfxPassword | Out-Null
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
} elseif (-not (Test-Path $cer)) {
    $existing = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfx, "")
    [IO.File]::WriteAllBytes($cer, $existing.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
}

# 4. MSBuild
$msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
if (-not $msbuild) { throw "MSBuild not found. Install Visual Studio with the UWP workload." }

& $msbuild (Join-Path $root "app\Xelite.sln") /restore /m `
    /p:Configuration=$Configuration /p:Platform=$Platform `
    /p:AppxBundle=Never /p:UapAppxPackageBuildMode=SideloadOnly `
    /p:PackageCertificateKeyFile=$pfx /p:PackageCertificatePassword=
if ($LASTEXITCODE) { throw "MSBuild failed" }

Write-Host ""
Write-Host "Package written to $(Join-Path $root 'dist')" -ForegroundColor Green
Get-ChildItem (Join-Path $root "dist") -Recurse -Include *.appx, *.msix, *.cer | ForEach-Object { Write-Host "  $($_.FullName)" }
