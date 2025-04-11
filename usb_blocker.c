// usb_blocker.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devguid.h>
#include <lm.h>
#pragma comment(lib, "setupapi.lib")

BOOL IsAdmin() {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    BOOL b = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);
    if (b) {
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &b)) b = FALSE;
        FreeSid(AdministratorsGroup);
    }
    return b;
}

void block_usb_ports() {
    HKEY hKey;
    DWORD value = 4; // Disable service
    
    // Disable USB storage through registry
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        
        if (RegSetValueEx(hKey, "Start", 0, REG_DWORD, (BYTE*)&value, sizeof(DWORD)) != ERROR_SUCCESS) {
            printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Failed to set USBSTOR registry value\", \"device\": \"all\"}\n", time(NULL));
        }
        RegCloseKey(hKey);
    } else {
        printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Failed to open USBSTOR registry key\", \"device\": \"all\"}\n", time(NULL));
    }
    
    // Disable USB controllers
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\USB",
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        
        if (RegSetValueEx(hKey, "Start", 0, REG_DWORD, (BYTE*)&value, sizeof(DWORD)) != ERROR_SUCCESS) {
            printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Failed to set USB registry value\", \"device\": \"all\"}\n", time(NULL));
        }
        RegCloseKey(hKey);
    } else {
        printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Failed to open USB registry key\", \"device\": \"all\"}\n", time(NULL));
    }
    
    // Notify user (no forced reboot)
    printf("{\"timestamp\": \"%ld\", \"level\": \"INFO\", \"message\": \"USB ports blocked. Reboot required to apply changes.\", \"device\": \"all\"}\n", time(NULL));
}
#else
// Linux code
#include <libudev.h>
#include <sys/stat.h>
#include <fcntl.h>

void block_usb_device(const char *device) {
    struct udev *udev = udev_new();
    if (!udev) {
        printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Failed to initialize udev\", \"device\": \"%s\"}\n", time(NULL), device);
        return;
    }

    // Get device from sysname
    struct udev_device *dev = udev_device_new_from_subsystem_sysname(udev, "usb", device);
    if (!dev) {
        printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Device %s not found\", \"device\": \"%s\"}\n", time(NULL), device, device);
        udev_unref(udev);
        return;
    }

    // Get sysfs path
    const char *syspath = udev_device_get_syspath(dev);
    if (!syspath) {
        printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Failed to get syspath for %s\", \"device\": \"%s\"}\n", time(NULL), device, device);
        udev_device_unref(dev);
        udev_unref(udev);
        return;
    }

    // Construct authorized file path
    char auth_path[256];
    snprintf(auth_path, sizeof(auth_path), "%s/authorized", syspath);

    // Open and write 0 to authorized
    int fd = open(auth_path, O_WRONLY);
    if (fd < 0) {
        printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Failed to open %s\", \"device\": \"%s\"}\n", time(NULL), auth_path, device);
        udev_device_unref(dev);
        udev_unref(udev);
        return;
    }

    if (write(fd, "0", 1) != 1) {
        printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Failed to disable %s\", \"device\": \"%s\"}\n", time(NULL), device, device);
    } else {
        printf("{\"timestamp\": \"%ld\", \"level\": \"INFO\", \"message\": \"Blocked USB device: %s\", \"device\": \"%s\"}\n", time(NULL), device, device);
    }

    close(fd);
    udev_device_unref(dev);
    udev_unref(udev);
}
#endif

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Usage: %s <device>\", \"device\": \"all\"}\n", time(NULL), argv[0]);
        return 1;
    }

#ifdef _WIN32
    if (!IsAdmin()) {
        printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Admin rights required\", \"device\": \"all\"}\n", time(NULL));
        return 1;
    }
    block_usb_ports();
#else
    // Check for root privileges
    if (getuid() != 0) {
        printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Root privileges required\", \"device\": \"all\"}\n", time(NULL));
        return 1;
    }
    block_usb_device(argv[1]);
#endif
    return 0;
}