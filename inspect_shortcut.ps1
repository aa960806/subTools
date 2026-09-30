$sh = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
Get-ChildItem -LiteralPath $desktop -Filter '*OpenAI*' | ForEach-Object {
    Write-Output ('FILE=' + $_.FullName)
    if ($_.Extension -eq '.lnk') {
        $s = $sh.CreateShortcut($_.FullName)
        Write-Output ('Target=' + $s.TargetPath)
        Write-Output ('Args=' + $s.Arguments)
        Write-Output ('Work=' + $s.WorkingDirectory)
    }
}
Write-Output ('WEB=' + (Test-Path (Join-Path $PSScriptRoot 'run_web.py')))
