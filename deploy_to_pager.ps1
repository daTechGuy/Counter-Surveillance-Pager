param(
    [string]$TargetHost = "172.16.52.1",
    [string]$KeyFile = "$env:USERPROFILE\.ssh\pager_ed25519",
    [string]$RemoteDir = "/root/payloads/user/reconnaissance/Counter-Surveillance-Pager"
)

Write-Host "Checking connection to $TargetHost..." -ForegroundColor Cyan
$ping = Test-NetConnection -ComputerName $TargetHost -Port 22 -WarningAction SilentlyContinue

if (-not $ping.TcpTestSucceeded) {
    Write-Host "Attempting DHCP lease renewal on USB Ethernet..." -ForegroundColor Yellow
    $usbAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Realtek*USB*" -or $_.Name -like "*Ethernet 3*" }
    foreach ($adapter in $usbAdapters) {
        ipconfig /renew $adapter.Name 2>$null | Out-Null
    }
    Start-Sleep -Seconds 2
    $ping = Test-NetConnection -ComputerName $TargetHost -Port 22 -WarningAction SilentlyContinue
}

# If IPv4 is still unreachable, fallback to IPv6 ULA (always advertised by the Pager)
$sshHost = $TargetHost
$scpHost = $TargetHost
if (-not $ping.TcpTestSucceeded) {
    Write-Host "IPv4 $TargetHost unreachable, checking IPv6 (fd72:689f:c6b8::1)..." -ForegroundColor Yellow
    $ping6 = Test-NetConnection -ComputerName "fd72:689f:c6b8::1" -Port 22 -WarningAction SilentlyContinue
    if ($ping6.TcpTestSucceeded) {
        Write-Host "Connected via IPv6!" -ForegroundColor Green
        $sshHost = "fd72:689f:c6b8::1"
        $scpHost = "[fd72:689f:c6b8::1]"
    } else {
        Write-Error "Cannot connect to Pager on IPv4 ($TargetHost) or IPv6 (fd72:689f:c6b8::1). Make sure the WiFi Pineapple Pager is connected via USB and powered on."
        exit 1
    }
}

Write-Host "Creating remote payload directory: $RemoteDir" -ForegroundColor Cyan
ssh -i $KeyFile -o StrictHostKeyChecking=no "root@$sshHost" "mkdir -p $RemoteDir"

Write-Host "Uploading Counter-Surveillance-Pager payload files..." -ForegroundColor Cyan
scp -i $KeyFile -o StrictHostKeyChecking=no `
    payload.sh `
    gps_alpr_proximity.awk `
    export_gps_kml.awk `
    export_gps_kml.sh `
    mesh_detect_targets.conf `
    tracker_allowlist.conf `
    trusted_networks.conf `
    VERSION `
    *.awk `
    "root@${scpHost}:${RemoteDir}/"

if (Test-Path "alpr_camera_db.sqlite") {
    Write-Host "Uploading alpr_camera_db.sqlite (143k cameras)..." -ForegroundColor Cyan
    scp -i $KeyFile -o StrictHostKeyChecking=no alpr_camera_db.sqlite "root@${scpHost}:${RemoteDir}/"
}

Write-Host "Setting executable permissions and validating syntax on device..." -ForegroundColor Cyan
ssh -i $KeyFile -o StrictHostKeyChecking=no "root@$sshHost" "chmod +x $RemoteDir/*.sh && bash -n $RemoteDir/payload.sh && echo 'Validation OK!'"

Write-Host "Deployment complete!" -ForegroundColor Green
