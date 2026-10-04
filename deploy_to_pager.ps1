param(
    [string]$TargetHost = "172.16.52.1",
    [string]$KeyFile = "$env:USERPROFILE\.ssh\pager_ed25519",
    [string]$RemoteDir = "/root/payloads/user/reconnaissance/Counter-Surveillance-Pager"
)

Write-Host "Checking connection to $TargetHost..." -ForegroundColor Cyan
$ping = Test-NetConnection -ComputerName $TargetHost -Port 22 -WarningAction SilentlyContinue
if (-not $ping.TcpTestSucceeded) {
    Write-Warning "Cannot connect to $TargetHost on port 22. Make sure the WiFi Pineapple Pager is connected via USB and powered on."
    exit 1
}

Write-Host "Creating remote payload directory: $RemoteDir" -ForegroundColor Cyan
ssh -i $KeyFile -o StrictHostKeyChecking=no "root@$TargetHost" "mkdir -p $RemoteDir"

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
    "root@${TargetHost}:${RemoteDir}/"

if (Test-Path "alpr_camera_db.sqlite") {
    Write-Host "Uploading alpr_camera_db.sqlite..." -ForegroundColor Cyan
    scp -i $KeyFile -o StrictHostKeyChecking=no alpr_camera_db.sqlite "root@${TargetHost}:${RemoteDir}/"
}

Write-Host "Setting executable permissions and validating syntax on device..." -ForegroundColor Cyan
ssh -i $KeyFile -o StrictHostKeyChecking=no "root@$TargetHost" "chmod +x $RemoteDir/*.sh && bash -n $RemoteDir/payload.sh && echo 'Validation OK!'"

Write-Host "Deployment complete!" -ForegroundColor Green
