# Variables
$packageName    = 'exporter_exporter'
$toolsDir    = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$fileLocation = Join-Path $toolsDir "$packageName.exe"

if (Get-Service $packageName -ErrorAction SilentlyContinue) {
  & $fileLocation -winsvc remove
}
