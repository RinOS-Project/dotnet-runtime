$VersionFolder = $PSScriptRoot
$RepoRoot = (Resolve-Path "$VersionFolder/../../../").Path.TrimEnd("\")

Get-ChildItem -Path "$VersionFolder" -Filter "_version.*" | ForEach-Object {
    $path = $_.FullName
    if ($_.Name -eq "_version.c") {
        # For _version.c, update the commit ID if it has changed from the last build.
        $commit = (git rev-parse HEAD 2>$null)
        if (-not $commit) { $commit = "N/A" }
        $weak_substitute = "char sccsid[] __attribute__((used, weak)) = `"@(#)Version N/A @Commit: $commit`";"
        $retain_substitute = "static char sccsid[] __attribute__((used, retain)) = `"@(#)Version N/A @Commit: $commit`";"
        $version_file_template = Get-Content -Path $path | ForEach-Object { $_ -replace "^char sccsid\[\].*", $weak_substitute -replace "^static char sccsid\[\].*", $retain_substitute }
        $version_file_destination = "$RepoRoot\\artifacts\\obj\\_version.c"
        $current_contents = ""
        $is_placeholder_file = $false
        $needs_sccsid = $true
        $desired_contents = $version_file_template
        if (Test-Path -Path $version_file_destination) {
            $current_contents = Get-Content -Path $version_file_destination
            $is_placeholder_file = $current_contents -match "@\(#\)Version N/A @Commit:"
            $needs_sccsid = -not ($current_contents -match "^\s*(static\s+)?char sccsid\[\]")
            if (-not $is_placeholder_file -and $needs_sccsid) {
                # GenerateNativeVersionFile may leave the product macros in
                # place while dropping the historical SCCS string.  Repair
                # only that missing line; never replace an existing product
                # version source.
                $desired_contents = @($current_contents) + $retain_substitute
            }
        } else {
            $is_placeholder_file = $true
        }
        # Update placeholders from the template, or repair only a missing
        # sccsid in an otherwise valid product version source.
        if (($is_placeholder_file -or $needs_sccsid) -and (Compare-Object $desired_contents $current_contents)) {
            $desired_contents | Set-Content -Path $version_file_destination
        }
    } elseif (-not (Test-Path -Path "$RepoRoot\\artifacts\\obj\\$($_.Name)")) {
        Copy-Item -Path $path -Destination "$RepoRoot\\artifacts\\obj\\"
    }
}
