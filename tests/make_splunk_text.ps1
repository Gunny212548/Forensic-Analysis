# Lab data for W3's check (tests/check_windows.py --evtx): the Security / Eventlog records of
# every EVTX-ATTACK-SAMPLES file, rendered by Windows (Get-WinEvent .Message) and written in
# Splunk's WinEventLog layout, under <lab>/splunk-text/from-evtx/. Windows renders with this
# machine's templates, so an event whose own template differs (5156 version 1 from an older
# build) is rendered with the wrong labels here - the check leaves 5156 out for that reason.
#
#   pwsh -File tests/make_splunk_text.ps1 [-Lab D:\logtest\windows]
param([string]$Lab = "D:\logtest\windows")
$src = Join-Path $Lab "EVTX-ATTACK-SAMPLES"
$dst = Join-Path $Lab "splunk-text\from-evtx"
New-Item -ItemType Directory -Force $dst | Out-Null
$files = 0; $records = 0
foreach ($f in Get-ChildItem -Recurse $src -Filter *.evtx) {
    $evs = @(Get-WinEvent -Path $f.FullName -Oldest -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -in "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Eventlog" -and $_.LogName -eq "Security" })
    if (-not $evs) { continue }
    $sb = [Text.StringBuilder]::new()
    foreach ($e in $evs) {
        $display = if ($e.ProviderName -eq "Microsoft-Windows-Security-Auditing") { "Microsoft Windows security auditing." } else { $e.ProviderName }
        $msg = if ($e.Message) { $e.Message -replace "`r`n", "`n" } else { "" }
        [void]$sb.Append($e.TimeCreated.ToString("MM/dd/yyyy hh:mm:ss tt", [Globalization.CultureInfo]::InvariantCulture) + "`n")
        [void]$sb.Append("LogName=$($e.LogName)`nSourceName=$display`nEventCode=$($e.Id)`nEventType=0`nType=Information`n")
        [void]$sb.Append("ComputerName=$($e.MachineName)`nTaskCategory=$($e.TaskDisplayName)`nOpCode=Info`n")
        [void]$sb.Append("RecordNumber=$($e.RecordId)`nKeywords=x`nMessage=$msg`n")
        $records++
    }
    $rel = $f.FullName.Substring($src.Length + 1) + ".log"
    $out = Join-Path $dst $rel
    New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
    [IO.File]::WriteAllText($out, $sb.ToString(), [Text.UTF8Encoding]::new($false))
    $files++
}
"$files files, $records records -> $dst"
