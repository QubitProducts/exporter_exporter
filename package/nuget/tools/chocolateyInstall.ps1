# Variables
$packageName    = 'exporter_exporter'
$toolsDir    = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$fileLocation = Join-Path $toolsDir "$packageName.exe"

$pp = Get-PackageParameters

if ($pp['winsvc'] -eq 'install') {
  $args += "--winsvc=$($pp["winsvc"])"
  if ($pp["config.file"] -ne $null -and $pp["config.file"] -ne '') {
    $args += "--config.file=$($pp["config.file"])" 
  }
  Write-Debug "Passing the following arguments: $args"
  & $fileLocation $args
}