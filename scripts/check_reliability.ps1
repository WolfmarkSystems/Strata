$ErrorActionPreference = 'Stop'

$baselineUnwrapExpect = 2307
$baselineUnsafe = 6

$allowedUnsafeFiles = @(
  'apps/forge/apps/vantor-forge-desktop/src-tauri/src/lib.rs',
  'crates/vantor-core/src/plugin.rs',
  'crates/vantor-fs/src/virtualization/mod.rs',
  'crates/vantor-shield-engine/src/plugin.rs'
)

$rustFiles = Get-ChildItem -Path . -Recurse -File -Filter *.rs | Where-Object {
  $_.FullName -notmatch '\\target(\\|_)' -and $_.FullName -notmatch '\\node_modules\\'
}

$prodRustFiles = $rustFiles | Where-Object {
  $_.FullName -notmatch '\\tests\\' -and $_.Name -notmatch '_test\.rs$'
}

$unwrapExpectCount = 0
foreach ($file in $prodRustFiles) {
  $lineMatches = Select-String -Path $file.FullName -Pattern 'unwrap\(|expect\(' -AllMatches
  foreach ($match in $lineMatches) {
    $unwrapExpectCount += $match.Matches.Count
  }
}

$unsafeCount = 0
$unsafeFiles = New-Object System.Collections.Generic.HashSet[string]
foreach ($file in $rustFiles) {
  $lineMatches = Select-String -Path $file.FullName -Pattern '\bunsafe\b' -AllMatches
  if ($lineMatches) {
    foreach ($match in $lineMatches) {
      $unsafeCount += $match.Matches.Count
    }

    $relative = $file.FullName.Substring((Get-Location).Path.Length + 1).Replace('\', '/')
    [void]$unsafeFiles.Add($relative)
  }
}

Write-Host 'Reliability baseline check'
Write-Host "  unwrap/expect (prod): current=$unwrapExpectCount baseline=$baselineUnwrapExpect"
Write-Host "  unsafe (all rust): current=$unsafeCount baseline=$baselineUnsafe"

if ($unwrapExpectCount -gt $baselineUnwrapExpect) {
  throw 'unwrap/expect count increased above baseline.'
}

if ($unsafeCount -gt $baselineUnsafe) {
  throw 'unsafe usage count increased above baseline.'
}

foreach ($file in $unsafeFiles) {
  if ($allowedUnsafeFiles -notcontains $file) {
    throw "unsafe usage found outside allowlist: $file"
  }
}

Write-Host 'Reliability baseline check passed.'
