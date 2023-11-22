#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include "lazy.h"
#include "process.h"
#include "xor.h"
//#include "../Encryption/custom_winapi.hpp"



void to_lower(unsigned char* input)
{
    char* p = (char*)input;
    unsigned long length = strlen(p);
    for (unsigned long i = 0; i < length; i++) p[i] = tolower(p[i]);
}

int virtual_box_registry()
{
    HKEY h_key = 0;
    if (LI_FN(RegOpenKeyExA).forwarded_safe_cached()(HKEY_LOCAL_MACHINE, _xor_("HARDWARE\\ACPI\\DSDT\\VBOX__").c_str(), 0, KEY_READ, &h_key) == ERROR_SUCCESS) { *(uintptr_t*)(0) = 1; }

    return false;
}

int virtual_box_drivers()
{
    if (LI_FN(CreateFileA).forwarded_safe_cached()(_xor_("\\\\.\\VBoxMiniRdrDN").c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0) != INVALID_HANDLE_VALUE) { *(uintptr_t*)(0) = 1; }

    if (LI_FN(LoadLibraryA).forwarded_safe_cached()(_xor_("VBoxHook.dll").c_str())) { *(uintptr_t*)(0) = 1; }

    HKEY h_key = 0;
    if ((ERROR_SUCCESS == LI_FN(RegOpenKeyExA).forwarded_safe_cached()(HKEY_LOCAL_MACHINE, _xor_("SOFTWARE\\Oracle\\VirtualBox Guest Additions").c_str(), 0, KEY_READ, &h_key)) && h_key) { LI_FN(RegCloseKey).forwarded_safe_cached()(h_key); *(uintptr_t*)(0) = 1; }
    h_key = 0;
    if (LI_FN(RegOpenKeyExA).forwarded_safe_cached()(HKEY_LOCAL_MACHINE, _xor_("HARDWARE\\DESCRIPTION\\System").c_str(), 0, KEY_READ, &h_key) == ERROR_SUCCESS)
    {
        unsigned long type = 0;
        unsigned long size = 0x100;
        char* systembiosversion = (char*)LI_FN(LocalAlloc).forwarded_safe_cached()(LMEM_ZEROINIT, size + 10);
        if (ERROR_SUCCESS == LI_FN(RegQueryValueExA).forwarded_safe_cached()(h_key, _xor_("SystemBiosVersion").c_str(), 0, &type, (unsigned char*)systembiosversion, &size))
        {
            to_lower((unsigned char*)systembiosversion);
            if (type == REG_SZ || type == REG_MULTI_SZ)
            {
                if (strstr(systembiosversion, _xor_("vbox").c_str()))
                {
                    *(uintptr_t*)(0) = 1;
                }
            }
        }
        LI_FN(LocalFree).forwarded_safe_cached()(systembiosversion);

        type = 0;
        size = 0x200;
        char* videobiosversion = (char*)LI_FN(LocalAlloc).forwarded_safe_cached()(LMEM_ZEROINIT, size + 10);
        if (ERROR_SUCCESS == LI_FN(RegQueryValueExA).forwarded_safe_cached()(h_key, _xor_("VideoBiosVersion").c_str(), 0, &type, (unsigned char*)videobiosversion, &size))
        {
            if (type == REG_MULTI_SZ)
            {
                char* video = videobiosversion;
                while (*(unsigned char*)video)
                {
                    to_lower((unsigned char*)video);
                    if (strstr(video, _xor_("oracle").c_str()) || strstr(video, _xor_("virtualbox").c_str())) { *(uintptr_t*)(0) = 1; }
                    video = &video[strlen(video) + 1];
                }
            }
        }
        LI_FN(LocalFree).forwarded_safe_cached()(videobiosversion);
        LI_FN(RegCloseKey).forwarded_safe_cached()(h_key);

        return false;
    }
}

void vmware_check()
{
    if (find(_xor_("vmtoolsd.exe").c_str()))  *(uintptr_t*)(0) = 1;
    if (find(_xor_("vmwaretray.exe").c_str()))  *(uintptr_t*)(0) = 1;
    if (find(_xor_("vmwareuser.exe").c_str())) *(uintptr_t*)(0) = 1;
    if (find(_xor_("VGAuthService.exe").c_str())) *(uintptr_t*)(0) = 1;
    if (find(_xor_("vmacthlp.exe").c_str())) *(uintptr_t*)(0) = 1;
}