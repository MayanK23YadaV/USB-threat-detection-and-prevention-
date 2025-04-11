@echo off
setlocal enabledelayedexpansion

:: Set paths with environment variable overrides
set "BASE_DIR=%USB_THREAT_DIR%"
if "%BASE_DIR%"=="" set "BASE_DIR=C:\ProgramData\USBThreat"
set "LOG_FILE=%BASE_DIR%\usb_monitor.log"
set "WHITELIST_FILE=%BASE_DIR%\whitelist.conf"
set "QUARANTINE_DIR=%BASE_DIR%\quarantine"
set "LOCK_FILE=%BASE_DIR%\usb_analyzer.lock"
set "MAX_LOG_SIZE=10485760"
set "MAX_LOG_FILES=5"
set "QUARANTINE_RETENTION_DAYS=30"

:: Create directories if they don't exist
if not exist "%BASE_DIR%" mkdir "%BASE_DIR%"
if not exist "%QUARANTINE_DIR%" mkdir "%QUARANTINE_DIR%"

:: Set proper permissions on directories
icacls "%BASE_DIR%" /inheritance:r /grant:r Administrators:(OI)(CI)F /grant:r SYSTEM:(OI)(CI)F >nul 2>&1
icacls "%QUARANTINE_DIR%" /inheritance:r /grant:r Administrators:(OI)(CI)F /grant:r SYSTEM:(OI)(CI)F >nul 2>&1

:: Check for admin rights
net session >nul 2>&1 || (
    call :log "ERROR" "Admin rights required" "system"
    exit /b 1
)

:: Check for lock file
if exist "%LOCK_FILE%" (
    call :log "INFO" "usb_analyzer.py is running (lock file detected), exiting to avoid overlap" "system"
    exit /b 0
)

:: Check if Python script is running
tasklist /FI "IMAGENAME eq python.exe" /FI "WINDOWTITLE eq usb_analyzer.py" | find "python.exe" >nul
if %ERRORLEVEL% equ 0 (
    call :log "INFO" "usb_analyzer.py is running, exiting to avoid overlap" "system"
    exit /b 0
)

:: Function to get ISO 8601 timestamp
:get_iso_timestamp
for /f "tokens=2 delims==" %%G in ('wmic os get localdatetime /value') do set datetime=%%G
if "%datetime%"=="" set datetime=19700101000000
set iso_date=%datetime:~0,4%-%datetime:~4,2%-%datetime:~6,2%T%datetime:~8,2%:%datetime:~10,2%:%datetime:~12,2%
exit /b

:: Function to log messages with ISO 8601 timestamp
:log
call :get_iso_timestamp
echo {"timestamp": "%iso_date%", "level": "%~1", "message": "%~2", "device": "%~3"} >> "%LOG_FILE%"
goto :eof

:: Function to rotate logs if they get too large
:rotate_logs
if exist "%LOG_FILE%" (
    for /f "tokens=*" %%a in ('dir /b /a-d "%LOG_FILE%"') do (
        set "file_size=%%~za"
        if !file_size! gtr %MAX_LOG_SIZE% (
            if exist "%LOG_FILE%.1" del "%LOG_FILE%.1"
            if exist "%LOG_FILE%.2" ren "%LOG_FILE%.2" "%LOG_FILE%.1"
            if exist "%LOG_FILE%.3" ren "%LOG_FILE%.3" "%LOG_FILE%.2"
            if exist "%LOG_FILE%.4" ren "%LOG_FILE%.4" "%LOG_FILE%.3"
            ren "%LOG_FILE%" "%LOG_FILE%.4"
            echo. > "%LOG_FILE%"
            call :log "INFO" "Log file rotated due to size" "system"
        )
    )
)
goto :eof

:: Function to clean up old quarantined files
:cleanup_quarantine
forfiles /p "%QUARANTINE_DIR%" /s /m *.* /d -%QUARANTINE_RETENTION_DAYS% /c "cmd /c del @path" >nul 2>&1
goto :eof

:: Function to get device info using PowerShell with proper escaping
:get_device_info_ps
set "device_id=%~1"
set "device_id=!device_id:'=''!"
powershell -Command "$device = Get-WmiObject Win32_USBHub -Filter \"DeviceID='!device_id!'\" | Select-Object -First 1; if ($device) { $device.DeviceID + ',' + $device.Description + ',' + $device.Manufacturer + ',' + $device.PNPDeviceID }" 2>nul
goto :eof

:: Function to get device info using WMIC (fallback)
:get_device_info_wmic
set "device_id=%~1"
set "device_id=!device_id:'=''!"
wmic path Win32_USBHub where "DeviceID='!device_id!'" get DeviceID,Description,Manufacturer,PNPDeviceID /format:csv | findstr /v "Node"
goto :eof

:: Function to check if device is whitelisted
:check_whitelist
if exist "%WHITELIST_FILE%" (
    findstr /i /c:"%~1" "%WHITELIST_FILE%" >nul
    if not errorlevel 1 (
        call :log "INFO" "Device %~1 is whitelisted" "%~1"
        exit /b 0
    )
)
call :log "INFO" "Device %~1 is not whitelisted" "%~1"
exit /b 1

:: Function to block USB device with proper escaping
:block_device
set "device_id=%~1"
set "device_id=!device_id:'=''!"
powershell -Command "Get-PnpDevice -InstanceId '!device_id!' | Disable-PnpDevice -Confirm:$false" 2>nul
if !errorlevel! equ 0 (
    call :log "INFO" "Blocked USB device: !device_id!" "!device_id!"
) else (
    call :log "ERROR" "Failed to block USB device: !device_id!" "!device_id!"
)
goto :eof

:: Function to scan and quarantine files on USB device
:scan_files
set "mount_point=%~1"
set "device_id=%~2"
set "suspicious=0"

:: Check for suspicious file types
for %%f in ("%mount_point%\*.exe" "%mount_point%\*.bat" "%mount_point%\*.vbs" "%mount_point%\*.js" "%mount_point%\*.ps1" "%mount_point%\*.lnk" "%mount_point%\*.docm" "%mount_point%\*.xlsm" "%mount_point%\*.pdf" "%mount_point%\*.zip") do (
    if exist %%f (
        call :log "WARNING" "Suspicious file type detected: %%~nxf" "%device_id%"
        set "suspicious=1"
        
        :: Run Windows Defender scan
        powershell -Command "Start-MpScan -ScanType Custom -ScanPath '%%f'" 2>nul
        if !errorlevel! neq 0 (
            call :log "ERROR" "Windows Defender scan failed for %%~nxf" "%device_id%"
        ) else (
            call :log "INFO" "Windows Defender scan completed for %%~nxf" "%device_id%"
            
            :: Check if file is hidden and quarantine if needed
            attrib "%%f" | findstr /i "H" >nul && (
                call :quarantine_file "%%f" "%device_id%"
            )
        )
    )
)

if %suspicious% equ 1 (
    call :log "WARNING" "Suspicious files detected on device %device_id%" "%device_id%"
    call :block_device "%device_id%"
)

goto :eof

:: Function to quarantine a file
:quarantine_file
set "file_path=%~1"
set "device_id=%~2"
set "file_name=%~nx1"
set "timestamp=%iso_date::=.%"
set "quarantine_path=%QUARANTINE_DIR%\%file_name%.%timestamp%.quar"

:: Create a copy instead of moving to avoid issues with locked files
copy "%file_path%" "%quarantine_path%" >nul
if !errorlevel! equ 0 (
    :: Try to delete the original file
    del "%file_path%" >nul 2>&1
    call :log "INFO" "Quarantined file: %file_path% to %quarantine_path%" "%device_id%"
) else (
    call :log "ERROR" "Failed to quarantine file: %file_path%" "%device_id%"
)
goto :eof

:: Main loop (fallback mode)
:loop
call :log "INFO" "Running in fallback mode (usb_analyzer.py not detected)" "system"

:: Rotate logs if needed
call :rotate_logs

:: Clean up old quarantined files
call :cleanup_quarantine

:: Get list of USB devices
for /f "tokens=*" %%a in ('wmic path Win32_USBHub get DeviceID /format:csv ^| findstr /v "Node"') do (
    set "device_id=%%a"
    set "device_id=!device_id:,=!"

    set "vid_pid="
    for /f "tokens=1-4 delims=," %%b in ('call :get_device_info_ps "!device_id!"') do (
        set "vid_pid=%%d"
        set "vid_pid=!vid_pid:VID_=!"
        set "vid_pid=!vid_pid:PID_=!"
        
        call :check_whitelist "!vid_pid!"
        if errorlevel 1 (
            call :log "INFO" "Processing unauthorized device: !device_id!" "!device_id!"
            set "mount_point="
            for /f "tokens=*" %%m in ('powershell -Command "Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 2} | Select-Object -ExpandProperty DeviceID"') do (
                set "mount_point=%%m\"
                call :scan_files "!mount_point!" "!device_id!"
            )
            call :block_device "!device_id!"
        )
    )
    
    if not defined vid_pid (
        for /f "tokens=1-4 delims=," %%b in ('call :get_device_info_wmic "!device_id!"') do (
            set "vid_pid=%%d"
            set "vid_pid=!vid_pid:VID_=!"
            set "vid_pid=!vid_pid:PID_=!"
            
            call :check_whitelist "!vid_pid!"
            if errorlevel 1 (
                call :log "INFO" "Processing unauthorized device: !device_id!" "!device_id!"
                set "mount_point="
                for /f "tokens=*" %%m in ('powershell -Command "Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 2} | Select-Object -ExpandProperty DeviceID"') do (
                    set "mount_point=%%m\"
                    call :scan_files "!mount_point!" "!device_id!"
                )
                call :block_device "!device_id!"
            )
        )
    )
)

:: Adjust sleep time based on system load
for /f "tokens=2 delims=," %%a in ('wmic cpu get loadpercentage /format:csv ^| findstr /v "Node"') do (
    set "cpu_load=%%a"
    if !cpu_load! gtr 80 (
        timeout /t 60 /nobreak >nul
    ) else if !cpu_load! gtr 50 (
        timeout /t 45 /nobreak >nul
    ) else (
        timeout /t 30 /nobreak >nul
    )
)

goto :loop