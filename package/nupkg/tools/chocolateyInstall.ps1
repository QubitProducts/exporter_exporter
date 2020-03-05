# Variables
$packageName    = 'exporter_exporter'
$toolsDir    = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$fileLocation = Join-Path $toolsDir "$packageName.exe"

# Ensure there's no previous exporter_exporter remaining
$service = Get-WmiObject -Class Win32_Service -Filter "Name='$packageName'" 
if ( $service ) {
  if (Get-Service $packageName | Where-Object {$_.status -eq 'running'}) {
      Stop-Service $packageName
  }
  $service.Delete()
}

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
