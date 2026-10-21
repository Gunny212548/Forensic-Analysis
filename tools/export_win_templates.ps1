# Export Windows event providers' message templates for the Splunk-text reader
# (W3, specs/windows_event_logs.md, gotcha #60).
#
#   pwsh -File tools/export_win_templates.ps1 [-Provider <name>, <name>...]
#
# Windows publishes, per event ID and version, the message with %n insertions and
# the template naming each data item in order (ProviderMetadata.Events). Splunk's
# classic WinEventLog text carries only the rendered message, so the reader matches
# it against these to give each value its Data name. Runs on Windows only - the
# app's container cannot read provider metadata - so its output is committed
# (Q45). Each message is cut after the line of its last insertion (after its
# first line when it has none): the explanation paragraphs that follow carry no value.
# Default: the Security log's two providers (Security-Auditing; Eventlog writes 1100 / 1102).

param([string[]]$Provider = @("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Eventlog"))

$ErrorActionPreference = "Stop"
$dir = Join-Path $PSScriptRoot "..\app\data\windows"
New-Item -ItemType Directory -Force $dir | Out-Null
foreach ($name in $Provider) {
    $pm = [System.Diagnostics.Eventing.Reader.ProviderMetadata]::new($name)
    $events = foreach ($e in $pm.Events) {
        if (-not $e.Description) { continue }
        # An event with no template has no items; its message is matched on its first line.
        $data = if ($e.Template) { @(([xml]$e.Template).template.data) } else { @() }
        $names = @($data | ForEach-Object { $_.name })
        # The rendered message writes a hex value in upper case; the event stores it in lower.
        $hex = @($data | Where-Object { $_.outType -like "win:HexInt*" } | ForEach-Object { $_.name })
        $message = ($e.Description -replace "`r`n", "`n") -replace "`0", ""
        $lines = $message -split "`n"
        $last = -1
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '%\d+') { $last = $i } }
        if ($last -lt 0) { $last = 0 }
        [ordered]@{
            id      = [int]$e.Id
            version = [int]$e.Version
            message = ($lines[0..$last] -join "`n")
            names   = @($names)
            hex     = @($hex)
        }
    }
    $out = [ordered]@{
        provider = $pm.Name
        display  = $pm.DisplayName -replace "`0", ""
        source   = "ProviderMetadata.Events on $([Environment]::OSVersion.VersionString), exported $(Get-Date -Format yyyy-MM-dd)"
        events   = @($events | Sort-Object { $_.id }, { $_.version })
    }
    $path = Join-Path $dir "$name.json"
    [IO.File]::WriteAllText($path, ($out | ConvertTo-Json -Depth 4) + "`n", [Text.UTF8Encoding]::new($false))
    "$($out.events.Count) event templates -> $path"
}
