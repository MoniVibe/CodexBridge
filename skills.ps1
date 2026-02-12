param(
  [Parameter(Position = 0)] [string] $Command = 'list',
  [Parameter(ValueFromRemainingArguments = $true)] [string[]] $Args = @(),
  [string] $SkillsRoot = '',
  [switch] $Quiet
)

$ErrorActionPreference = 'Stop'

function Write-Out {
  param([string]$Text)
  if ($Quiet) { return }
  if ($Text -eq $null) { return }
  Write-Output $Text
}

function Resolve-SkillsRoot {
  param([string]$Override)
  if ($Override) { return $Override }
  if ($env:CODEX_SKILLS_ROOT) { return $env:CODEX_SKILLS_ROOT }
  return (Join-Path $env:USERPROFILE '.codex\skills')
}

function Parse-FrontMatter {
  param([string]$Path)

  $name = ''
  $desc = ''
  $in = $false

  $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
  foreach ($line in $lines) {
    if (-not $in) {
      if ($line.Trim() -eq '---') { $in = $true; continue }
      continue
    }
    if ($line.Trim() -eq '---') { break }
    if (-not $name -and $line -match '^\s*name\s*:\s*(.+)\s*$') { $name = $Matches[1].Trim(); continue }
    if (-not $desc -and $line -match '^\s*description\s*:\s*(.+)\s*$') { $desc = $Matches[1].Trim(); continue }
  }

  return @{ name = $name; description = $desc }
}

function Find-Skill {
  param([string]$Root, [string]$Name)
  if (-not $Name) { return $null }
  $dir = Join-Path $Root $Name
  $skill = Join-Path $dir 'SKILL.md'
  if (Test-Path -LiteralPath $skill) { return @{ dir = $dir; skill = $skill } }

  # fallback: search by front matter name (case-insensitive)
  $candidates = Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '.system' }
  foreach ($c in $candidates) {
    $p = Join-Path $c.FullName 'SKILL.md'
    if (-not (Test-Path -LiteralPath $p)) { continue }
    try {
      $fm = Parse-FrontMatter -Path $p
      if ($fm.name -and $fm.name.Equals($Name, [StringComparison]::InvariantCultureIgnoreCase)) {
        return @{ dir = $c.FullName; skill = $p }
      }
    } catch {}
  }

  return $null
}

function Extract-QuickStartScript {
  param([string]$SkillPath)
  $lines = Get-Content -LiteralPath $SkillPath -ErrorAction Stop
  foreach ($line in $lines) {
    # Heuristic: the skill quickstart almost always includes "-File scripts/<name>.ps1"
    if ($line -match '(?i)\-File\s+(scripts[/\\][^\s]+\.ps1)\b') {
      return $Matches[1]
    }
  }
  return $null
}

function Cmd-List {
  param([string]$Root)
  if (-not (Test-Path -LiteralPath $Root)) { throw "Skills root not found: $Root" }

  $rows = @()
  $dirs = Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '.system' } | Sort-Object Name
  foreach ($d in $dirs) {
    $skill = Join-Path $d.FullName 'SKILL.md'
    if (-not (Test-Path -LiteralPath $skill)) { continue }
    try {
      $fm = Parse-FrontMatter -Path $skill
      $rows += [pscustomobject]@{
        name = $(if ($fm.name) { $fm.name } else { $d.Name })
        description = $fm.description
        path = $d.FullName
      }
    } catch {
      $rows += [pscustomobject]@{ name = $d.Name; description = '(failed to parse SKILL.md)'; path = $d.FullName }
    }
  }

  Write-Out ("skills: root={0} count={1}" -f $Root, $rows.Count)
  foreach ($r in $rows) {
    $desc = if ($r.description) { $r.description } else { '' }
    Write-Out ("- {0}: {1}" -f $r.name, $desc)
  }
}

function Cmd-Info {
  param([string]$Root, [string]$Name)
  $s = Find-Skill -Root $Root -Name $Name
  if (-not $s) { throw "Skill not found: $Name (root=$Root)" }

  $fm = Parse-FrontMatter -Path $s.skill
  $qs = Extract-QuickStartScript -SkillPath $s.skill
  Write-Out ("skill: {0}" -f $(if ($fm.name) { $fm.name } else { $Name }))
  if ($fm.description) { Write-Out ("description: {0}" -f $fm.description) }
  Write-Out ("dir: {0}" -f $s.dir)
  Write-Out ("skill_md: {0}" -f $s.skill)
  if ($qs) { Write-Out ("quickstart_script: {0}" -f $qs) }
  else { Write-Out "quickstart_script: (not detected)" }
}

function Cmd-Doctor {
  param([string]$Root)

  Write-Out ("skills.doctor: root={0}" -f $Root)
  $cmds = @('pwsh','git','gh','rg','python','python3','dotnet')
  foreach ($c in $cmds) {
    $p = $null
    try { $p = (Get-Command $c -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1) } catch {}
    if ($p) { Write-Out ("- ok: {0} -> {1}" -f $c, $p) }
    else { Write-Out ("- missing: {0}" -f $c) }
  }

  # Also sanity check that SKILL.md files parse.
  $bad = 0
  $dirs = Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '.system' }
  foreach ($d in $dirs) {
    $skill = Join-Path $d.FullName 'SKILL.md'
    if (-not (Test-Path -LiteralPath $skill)) { continue }
    try { $null = Parse-FrontMatter -Path $skill } catch { $bad++; Write-Out ("- parse_fail: {0}" -f $skill) }
  }
  Write-Out ("skills.doctor: skill_md_parse_failures={0}" -f $bad)
}

function Cmd-Run {
  param([string]$Root, [string]$Name, [string[]]$PassArgs)
  $s = Find-Skill -Root $Root -Name $Name
  if (-not $s) { throw "Skill not found: $Name (root=$Root)" }

  $qsRel = Extract-QuickStartScript -SkillPath $s.skill
  if (-not $qsRel) { throw "Skill has no detectable quickstart script: $Name" }

  $scriptPath = Join-Path $s.dir $qsRel
  if (-not (Test-Path -LiteralPath $scriptPath)) { throw "Quickstart script not found: $scriptPath" }

  Write-Out ("skills.run: {0}" -f $Name)
  Write-Out ("script: {0}" -f $scriptPath)
  if ($PassArgs -and $PassArgs.Count -gt 0) { Write-Out ("args: {0}" -f ($PassArgs -join ' ')) }

  & pwsh -NoProfile -ExecutionPolicy Bypass -File $scriptPath @PassArgs
  $ec = if ($LASTEXITCODE -ne $null) { $LASTEXITCODE } else { 0 }
  if ($ec -ne 0) { throw "skill script failed with exit_code=$ec" }
}

$root = Resolve-SkillsRoot -Override $SkillsRoot
$cmd = ($Command | ForEach-Object { $_.Trim().ToLowerInvariant() })

switch ($cmd) {
  'list' { Cmd-List -Root $root; break }
  'info' {
    if (-not $Args -or $Args.Count -lt 1) { throw 'Usage: skills.ps1 info <skillName>' }
    Cmd-Info -Root $root -Name $Args[0]
    break
  }
  'doctor' { Cmd-Doctor -Root $root; break }
  'run' {
    if (-not $Args -or $Args.Count -lt 1) { throw 'Usage: skills.ps1 run <skillName> [args...]' }
    $name = $Args[0]
    $pass = @()
    if ($Args.Count -gt 1) { $pass = $Args[1..($Args.Count - 1)] }
    Cmd-Run -Root $root -Name $name -PassArgs $pass
    break
  }
  default { throw "Unknown command: $Command (expected: list|info|doctor|run)" }
}
