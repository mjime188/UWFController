@echo off
set "command=%~1"
shift

if "%command%"=="enable_uwf" (
    uwfmgr filter enable
    if %errorlevel% equ 0 (
        echo UWF filter enabled successfully.
    ) else (
        echo Failed to enable UWF filter.
    )
    goto :eof
)

if "%command%"=="disable_uwf" (
    uwfmgr filter disable
    if %errorlevel% equ 0 (
        echo UWF filter disabled successfully.
    ) else (
        echo Failed to disable UWF filter.
    )
    goto :eof
)

if "%command%"=="get_uwf_status" (
    uwfmgr get-config
    goto :eof
)

if "%command%"=="set_uwf_startup" (
    uwfmgr filter enable-startup
    if %errorlevel% equ 0 (
        echo UWF startup configuration set successfully.
    ) else (
        echo Failed to set UWF startup configuration.
    )
    goto :eof
)

if "%command%"=="set_overlay_config" (
    uwfmgr overlay set-type %1
    uwfmgr overlay set-size %2
    uwfmgr overlay set-warning-threshold %3
    uwfmgr overlay set-critical-threshold %4
    if %errorlevel% equ 0 (
        echo Overlay settings updated successfully:
        echo Type: %1
        echo Size: %2 MB
        echo Warning Threshold: %3%%
        echo Critical Threshold: %4%%
    ) else (
        echo Failed to update overlay settings.
    )
    goto :eof
)

if "%command%"=="protect_volume" (
    uwfmgr volume protect %1
    if %errorlevel% equ 0 (
        echo Volume %1 protected successfully.
    ) else (
        echo Failed to protect volume %1.
    )
    goto :eof
)

if "%command%"=="unprotect_volume" (
    uwfmgr volume unprotect %1
    if %errorlevel% equ 0 (
        echo Volume %1 unprotected successfully.
    ) else (
        echo Failed to unprotect volume %1.
    )
    goto :eof
)

if "%command%"=="add_file_exclusion" (
    uwfmgr file add-exclusion %1
    if %errorlevel% equ 0 (
        echo File exclusion added successfully.
    ) else (
        echo Failed to add file exclusion.
    )
    goto :eof
)
if "%command%"=="get_exclusions" (
    echo File/Folder Exclusions:
    uwfmgr file get-exclusions
    echo.
    echo Registry Exclusions:
    uwfmgr registry get-exclusions
    goto :eof
)

if "%command%"=="add_folder_exclusion" (
    uwfmgr file add-exclusion %1
    if %errorlevel% equ 0 (
        echo Folder exclusion added successfully.
    ) else (
        echo Failed to add folder exclusion.
    )
    goto :eof
)

if "%command%"=="remove_file_exclusion" (
    uwfmgr file remove-exclusion %1
    if %errorlevel% equ 0 (
        echo File/folder exclusion removed successfully: %1
    ) else (
        echo Failed to remove file/folder exclusion: %1
    )
    goto :eof
)

if "%command%"=="add_registry_exclusion" (
    uwfmgr registry add-exclusion %1
    if %errorlevel% equ 0 (
        echo Registry exclusion added successfully.
    ) else (
        echo Failed to add registry exclusion.
    )
    goto :eof
)

if "%command%"=="remove_registry_exclusion" (
    uwfmgr registry remove-exclusion %1
    if %errorlevel% equ 0 (
        echo Registry exclusion removed successfully: %1
    ) else (
        echo Failed to remove registry exclusion: %1
    )
    goto :eof
)

if "%command%"=="create_restart_task" (
    schtasks /create /tn "%1" /tr "shutdown /r /t 0" /sc once /st %2
    if %errorlevel% equ 0 (
        echo Restart task created successfully.
    ) else (
        echo Failed to create restart task.
    )
    goto :eof
)

if "%command%"=="initialize_exclusions" (
    uwfmgr file add-exclusion C:\UWFConfiguration
    if %errorlevel% equ 0 (
        echo UWF Configuration folder exclusion added successfully.
    ) else (
        echo Failed to add UWF Configuration folder exclusion.
    )
    goto :eof
)

echo Unknown command: %command%
exit /b 1