# Variables
$serviceName = 'exporter_exporter'
$service = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'" 

if ( $service ) {
    if (Get-Service $serviceName | Where-Object {$_.status -eq 'running'}) {
        Stop-Service $serviceName
    }
    $service.Delete()
}
