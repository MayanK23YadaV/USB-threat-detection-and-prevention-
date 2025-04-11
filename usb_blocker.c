// usb_blocker.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <setupapi.h>
#pragma comment(lib, "setupapi.lib")

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <device>\n", argv[0]);
        return 1;
    }

    HKEY hKey;
    DWORD startValue = 4; // Disable USBSTOR
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\USBSTOR", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, "Start", 0, REG_DWORD, (BYTE*)&startValue, sizeof(startValue));
        RegCloseKey(hKey);
        printf("{\"timestamp\": \"%ld\", \"level\": \"INFO\", \"message\": \"USB blocked via registry\", \"device\": \"all\"}\n", time(NULL));
    } else {
        printf("{\"timestamp\": \"%ld\", \"level\": \"ERROR\", \"message\": \"Failed to block USB via registry\", \"device\": \"all\"}\n", time(NULL));
    }
    return 0;
}
#else
int main(int argc, char *argv[]) {
    fprintf(stderr, "This program is Windows-only\n");
    return 1;
}
#endif