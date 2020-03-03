# Variables
$packageName    = 'exporter_exporter'
$toolsDir    = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$fileLocation = Join-Path $toolsDir "$packageName.exe"

$pp = Get-PackageParameters
$boolParams = @(
  "config.skip-dirs"
  "web.tls.verify"
)
$stringParams = @(
  "config.dirs"
  "config.file"
  "log.format"
  "log.level"
  "web.bearer.token"
  "web.bearer.token-file"
  "web.listen-address"
  "web.proxy-path"
  "web.telemetry-path"
  "web.tls.ca"
  "web.tls.cert"
  "web.tls.key"
  "web.tls.listen-address"
)
if ($pp['winsvc'] -eq 'install') {
  $args += "--winsvc=$($pp["winsvc"])"
  foreach ($param in $stringParams) {
    if ($pp[$param] -ne $null -and $pp[$param] -ne '') {
      $args += "--$param=$($pp[$param])" 
    }
  }
  foreach ($param in $boolParams) {
    if ($pp[$param] -ne $null) {
      $args += "--$param" 
    }
  }
  Write-Debug "Passing the following arguments: $args"
  & $fileLocation $args
  & $fileLocation --winsvc start
}
