$ErrorActionPreference = 'Stop'
$ws = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$tool = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$vbs = Join-Path $tool 'OpenAI-Reauth.vbs'
$wscript = Join-Path ([Environment]::GetFolderPath('System')) 'wscript.exe'
if (-not (Test-Path -LiteralPath $vbs -PathType Leaf)) {
    throw "Launcher not found: $vbs"
}

$lnk = Join-Path $desktop 'OpenAI-Reauth.lnk'
$sc = $ws.CreateShortcut($lnk)
$sc.TargetPath = $wscript
$sc.Arguments = '"' + $vbs + '"'
$sc.WorkingDirectory = $tool
$sc.WindowStyle = 1
$sc.Description = 'SubTools web workspace'
$sc.Save()

$lnk2 = Join-Path $desktop 'OpenAI-Reauth-Window.lnk'
$sc2 = $ws.CreateShortcut($lnk2)
$sc2.TargetPath = $wscript
$sc2.Arguments = '"' + $vbs + '"'
$sc2.WorkingDirectory = $tool
$sc2.WindowStyle = 1
$sc2.Description = 'SubTools web workspace'
$sc2.Save()

# Keep launchers beside the application; copied launchers would resolve the
# desktop as their application root. Shortcuts point to this installation.
Write-Output $lnk
Write-Output $lnk2
