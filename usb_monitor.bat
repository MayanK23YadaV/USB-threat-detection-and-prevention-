@echo off
setlocal enabledelayedexpansion

:: Set paths
set "LOG_FILE=C:\ProgramData\USBThreat\usb_monitor.log"
set "WHITELIST_FILE=C:\ProgramData\USBThreat\whitelist.conf"

:: Create log directory if it doesn't exist
if not exist "C:\ProgramData\USBThreat" mkdir "C:\ProgramData\USBThreat"

:: Function to get ISO 8601 timestamp
:get_iso_timestamp
for /f "tokens=2 delims==" %%G in ('wmic os get localdatetime /value') do set datetime=%%G
if "%datetime%"=="" set datetime=19700101000000
set iso_date=%datetime:~0,4%-%datetime:~4,2%-%datetime:~6,2%T%datetime:~8,2%:%datetime:~10,2%:%datetime:~12,2%
exit /b

:: Function to log messages with ISO 8601 timestamp
:log
call :get_iso_timestamp
echo {"timestamp": "%iso_date%", "level": "INFO", "message": "%~1"} >> "%LOG_FILE%"
goto :eof

:: Function to get device info using PowerShell
:get_device_info_ps
powershell -Command "$device = Get-WmiObject Win32_USBHub -Filter \"DeviceID='%~1'\" | Select-Object -First 1; if ($device) { $device.DeviceID + ',' + $device.Description + ',' + $device.Manufacturer + ',' + $device.PNPDeviceID }"
goto :eof

:: Function to get device info using WMIC (fallback)
:get_device_info_wmic
wmic path Win32_USBHub where "DeviceID='%~1'" get DeviceID,Description,Manufacturer,PNPDeviceID /format:csv | findstr /v "Node"
goto :eof

:: Function to check if device is whitelisted
:check_whitelist
if exist "%WHITELIST_FILE%" (
    findstr /i /c:"%~1" "%WHITELIST_FILE%" >nul
    if not errorlevel 1 (
        call :log "Device %~1 is whitelisted"
        exit /b 0
    )
)
call :log "Device %~1 is not whitelisted"
exit /b 1

:: Main loop
:loop
for /f "tokens=*" %%a in ('wmic path Win32_USBHub get DeviceID /format:csv ^| findstr /v "Node"') do (
    set "device_id=%%a"
    set "device_id=!device_id:,=!"
    
    :: Try PowerShell first
    for /f "tokens=1-4 delims=," %%b in ('call :get_device_info_ps "!device_id!"') do (
        set "vid_pid=%%d"
        set "vid_pid=!vid_pid:VID_=!"
        set "vid_pid=!vid_pid:PID_=!"
        
        :: Check whitelist
        call :check_whitelist "!vid_pid!"
        if errorlevel 1 (
            call :log "Blocking unauthorized device: !device_id!"
            :: Add blocking logic here
        )
    )
    
    :: If PowerShell failed, try WMIC
    if errorlevel 1 (
        for /f "tokens=1-4 delims=," %%b in ('call :get_device_info_wmic "!device_id!"') do (
            set "vid_pid=%%d"
            set "vid_pid=!vid_pid:VID_=!"
            set "vid_pid=!vid_pid:PID_=!"
            
            :: Check whitelist
            call :check_whitelist "!vid_pid!"
            if errorlevel 1 (
                call :log "Blocking unauthorized device: !device_id!"
                :: Add blocking logic here
            )
        )
    )
)

timeout /t 5 /nobreak >nul
goto :loop