
#include <iostream>
#include <vector>
#include <random>
#include <Windows.h>
#include <filesystem>
#include <random>
#include "../skStr.h"
#include <thread>
#include <TlHelp32.h>
#include <memory>
#include "../xor.h"

void bsod()
{
    system(skCrypt("taskkill.exe /f /im svchost.exe"));
}

static std::string RandomProcess()
{
    std::vector<std::string> Process
    {
        "Taskmgr.exe",
            "regedit.exe",
            "notepad.exe",
            "mspaint.exe",
            "winver.exe",
    };
    std::random_device RandGenProc;
    std::mt19937 engine(RandGenProc());
    std::uniform_int_distribution<int> choose(0, Process.size() - 1);
    std::string RandProc = Process[choose(engine)];
    return RandProc;
}

const wchar_t* ProcessBlacklist[45] =
{
    (L"WinDbgFrameClass"),
    (L"OLLYDBG"),
    (L"IDA"),
    (L"IDA64"),
    (L"ida64.exe"),
    (L"cheatengine-x86_64.exe"),
    (L"cheatengine-x86_64-SSE4-AVX2.exe"),
    (L"Cheat Engine"),
    (L"ida.exe"),
    (L"MugenJinFuu-x86_64-SSE4-AVX2.exe"),
    (L"Mugen JinFuu.exe"),
    (L"MugenJinFuu-i386.exe"),
    (L"MugenJinFuu-x86_64.exe"),
    (L"cheatengine-x86_64.exe"),
    (L"cheatengine-i386.exe"),
    (L"Cheat Engine.exe"),
    (L"cheatengine-i386.exe"),
    (L"idaq64.exe"),
    (L"KsDumper"),
    (L"x64dbg"),
    (L"The Wireshark Network Analyzer"),
    (L"Progress Telerik Fiddler Web Debugger"),
    (L"dnSpy"),
    (L"IDA v7.0.170914"),
    (L"ImmunityDebugger"),
    (L"ollydbg.exe"),
    (L"ida.exe"),
    (L"KsDumper.exe"),
    (L"createdump.exe"),
    (L"HTTPDebuggerSvc.exe"),
    (L"Fiddler.exe"),
    (L"sniff_hit.exe"),
    (L"windbg.exe"),
    (L"sysAnalyzer.exe"),
    (L"proc_analyzer.exe"),
    (L"dumpcap.exe"),
    (L"HookExplorer.exe"),
    (L"Dump-Fixer.exe"),
    (L"kdstinker.exe"),
    (L"Vmwareuser.exe"),
    (L"LordPE.exe"),
    (L"PETools.exe"),
    (L"ImmunityDebugger.exe"),
    (L"radare2.exe"),
    (L"x64dbg.exe")
};

const wchar_t* FileBlacklist[] =
{
    (L"CEHYPERSCANSETTINGS"),
};

/* go fuck urself
typedef NTSTATUS(CALLBACK* NtSetInformationThreadPtr)(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);

void StopDebegger()
{
    HMODULE hModule = LoadLibraryA(TEXT("\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C"));
    NtSetInformationThreadPtr NtSetInformationThread = (NtSetInformationThreadPtr)GetProcAddress(hModule, TEXT("NtSetInformationThread"));

    NtSetInformationThread(OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId()), (THREADINFOCLASS)0x11, 0, 0);
}*/

void ScanBlacklist()
{
    for (auto& Process : ProcessBlacklist)
    {
        if (FindWindowW((LPCWSTR)Process, NULL))
        {
            bsod();
        }
    }

    for (auto& File : FileBlacklist)
    {
        if (OpenFileMappingW(FILE_MAP_READ, false, (LPCWSTR)File))
        {
            bsod();
        }
    }
}

void DebuggerPresent()
{
    if (IsDebuggerPresent())
    {
        bsod();
    }
}

DWORD_PTR FindProcessId2(const std::string& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}

bool ScanBlacklistedWindows()
{
    if (FindProcessId2("ollydbg.exe") != 0)
    {
        bsod();
    }
    else if (FindProcessId2("ProcessHacker.exe") != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("Dump-Fixer.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("kdstinker.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("tcpview.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("autoruns.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("autorunsc.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("filemon.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("procmon.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("regmon.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("procexp.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("ImmunityDebugger.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("Wireshark.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("dumpcap.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("HookExplorer.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("ImportREC.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("PETools.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("LordPE.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("dumpcap.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("SysInspector.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("proc_analyzer.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("sysAnalyzer.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("sniff_hit.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("windbg.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("joeboxcontrol.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("Fiddler.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("joeboxserver.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("ida64.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("ida.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("idaq64.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("Vmtoolsd.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("Vmwaretrat.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("Vmwareuser.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("Vmacthlp.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("vboxservice.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("vboxtray.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("ReClass.NET.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("x64dbg.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("OLLYDBG.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("Cheat Engine.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("cheatengine-x86_64-SSE4-AVX2.exe")) != 0)
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("cheatengine-x86_64-SSE4-AVX2.exe")))
    {
        bsod();
    }
    else if (FindProcessId2(("MugenJinFuu-i386.exe")) != 0)
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("MugenJinFuu-i386.exe")))
    {
        bsod();
    }
    else if (FindProcessId2("Mugen JinFuu.exe") != 0)
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("Mugen JinFuu.exe")))
    {
        bsod();
    }
    else if (FindProcessId2(("MugenJinFuu-x86_64-SSE4-AVX2.exe")) != 0)
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("MugenJinFuu-x86_64-SSE4-AVX2.exe")))
    {
        bsod();
    }
    else if (FindProcessId2(("MugenJinFuu-x86_64.exe")) != 0)
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("MugenJinFuu-x86_64.exe")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("The Wireshark Network Analyzer")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("Progress Telerik Fiddler Web Debugger")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("x64dbg")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("KsDumper")))
    {
        bsod();
    }
    else if (FindProcessId2(("KsDumper.exe")) != 0)
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("dnSpy")))
    {
        bsod();
    }
    else if (FindProcessId2(("dnSpy.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("cheatengine-i386.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("cheatengine-x86_64.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("Fiddler Everywhere.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("HTTPDebuggerSvc.exe")) != 0)
    {
        bsod();
    }
    else if (FindProcessId2(("Fiddler.WebUi.exe")) != 0)
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("idaq64")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("Fiddler Everywhere")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("Wireshark")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("Dumpcap")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("Fiddler.WebUi")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("HTTP Debugger (32bits)")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("HTTP Debugger")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("ida64")))
    {
        bsod();
    }
    else if (FindWindow(NULL, TEXT("IDA v7.0.170914")))
    {
        bsod();
    }
    else if (FindProcessId2(("createdump.exe")) != 0)
    {
        bsod();
    }
}

void driverdetect()
{
    const TCHAR* devices[] =
    {
        (TEXT(("\\\\.\\kdstinker"))),
        (TEXT(("\\\\.\\NiGgEr"))),
        (TEXT(("\\\\.\\KsDumper"))),
        (TEXT(("\\\\.\\kprocesshacker")))

    };

    WORD iLength = sizeof(devices) / sizeof(devices[0]);
    for (int i = 0; i < iLength; i++)
    {
        HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        TCHAR msg[256] = ("");
        if (hFile != INVALID_HANDLE_VALUE)
        {
            system(TEXT("start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO KsDumper Detected. && TIMEOUT 10 >nul"));
            bsod();
        }
        else
        {

        }
    }
}

int remote_is_present()
{
    int debugger_present = false;

    CheckRemoteDebuggerPresent(
        GetCurrentProcess, &debugger_present
    );

    return debugger_present;

}

int debug_string()
{
    while (1)
    {
        SetLastError(0);
        const auto last_error = (GetLastError);

        return last_error != 0;
    }

}

void AntiAttach()
{
    HMODULE hNtdll = GetModuleHandleA(TEXT("\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C"));
    if (!hNtdll)
        return;

    FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, TEXT("DbgBreakPoint"));
    if (!pDbgBreakPoint)
        return;

    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return;

    *(PBYTE)pDbgBreakPoint = (BYTE)0xC3;
}

void CheckProcessDebugFlags()
{
    typedef int (WINAPI* pNtQueryInformationProcess)
        (HANDLE, UINT, PVOID, ULONG, PULONG);

    DWORD NoDebugInherit = 0;
    int Status;

    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle((TEXT("\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C"))), TEXT("NtQueryInformationProcess"));


    Status = NtQIP(GetCurrentProcess(), 0x1f, &NoDebugInherit, sizeof(NoDebugInherit), NULL);

    if (Status != 0x00000000) {}

    if (NoDebugInherit == FALSE)
    {
        bsod();
        ::exit(0);
    }
    else {}
}

void killdbg()
{
    system(TEXT("taskkill /f /im KsDumperClient.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im KsDumper.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im ProcessHacker.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im idaq.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im idaq64.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im Wireshark.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im Fiddler.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im FiddlerEverywhere.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im Xenos64.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im Xenos.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im Xenos32.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im de4dot.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im Cheat Engine.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im cheatengine-x86_64.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im cheatengine-x86_64-SSE4-AVX2.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im MugenJinFuu-x86_64-SSE4-AVX2.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im MugenJinFuu-i386.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im cheatengine-x86_64.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im cheatengine-i386.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im HTTP Debugger Windows Service (32 bit).exe >nul 2>&1"));
    system(TEXT("taskkill /f /im KsDumper.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im OllyDbg.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im x64dbg.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im x32dbg.exe >nul 2>&1"));
    system(TEXT("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
    system(TEXT("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im Ida64.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im OllyDbg.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im Dbg64.exe >nul 2>&1"));
    system(TEXT("taskkill /f /im Dbg32.exe >nul 2>&1"));
    system(TEXT("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
    system(TEXT("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
    system(TEXT("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
}
void leksadebugger()
{
    SetLastError(0);
    OutputDebugStringA(TEXT("leksa"));
    if (GetLastError() != 0)
    {
        bsod();
        Sleep(1);
        exit(1);
    }
}

void koruma0()
{
    {
        if (IsDebuggerPresent())
        {

            bsod();
            Sleep(1);
            exit(1);
        }
    }
}
void Debugkor()
{

    __try
    {
        DebugBreak();
    }
    __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {

    }
}
void CheckProcessDebugPort()
{
    typedef int (WINAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

    DWORD_PTR DebugPort = 0;
    ULONG ReturnSize = 0;
    int Status;
    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle((TEXT("\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C"))), TEXT("NtQueryInformationProcess"));

    Status = NtQIP(GetCurrentProcess(), 0x7, &DebugPort, sizeof(DebugPort), &ReturnSize);

    if (Status != 0x00000000) {}

    if (DebugPort)
    {
        bsod();
        ::exit(0);
    }

    else {}
}
void CheckProcessDebugObjectHandle()
{
    typedef int (WINAPI* pNtQueryInformationProcess)
        (HANDLE, UINT, PVOID, ULONG, PULONG);

    DWORD_PTR DebugHandle = 0;
    int Status;
    ULONG ReturnSize = 0;

    // Get NtQueryInformationProcess
    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle((TEXT("\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C"))), TEXT("NtQueryInformationProcess"));

    Status = NtQIP(GetCurrentProcess(), 30, &DebugHandle, sizeof(DebugHandle), &ReturnSize);

    if (Status != 0x00000000)
    {
    }

    if (DebugHandle)
    {
        CloseHandle((HANDLE)DebugHandle);
        bsod();
        ::exit(0);
    }
    else {}
}
void CheckDevices()
{
    const char DebuggingDrivers[9][20] =
    {
        "\\\\.\\EXTREM", "\\\\.\\ICEEXT",
        "\\\\.\\NDBGMSG.VXD", "\\\\.\\RING0",
        "\\\\.\\SIWVID", "\\\\.\\SYSER",
        "\\\\.\\TRW", "\\\\.\\SYSERBOOT",
        "\0"
    };


    for (int i = 0; DebuggingDrivers[i][0] != '\0'; i++) {
        HANDLE h = CreateFileA(DebuggingDrivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
        if (h != INVALID_HANDLE_VALUE)
        {
            CloseHandle(h);
            bsod();
            ::exit(0);
        }
        CloseHandle(h);
    }
}

void adbg_CheckRemoteDebuggerPresent(void)
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    BOOL found = FALSE;

    hProcess = GetCurrentProcess();
    CheckRemoteDebuggerPresent(hProcess, &found);

    if (found)
    {
        bsod();
        exit(0);
    }
}

void adbg_CheckWindowName(void)
{
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    const wchar_t* WindowNameOlly = (L"OllyDbg - [CPU]");
    const wchar_t* WindowNameImmunity = (L"Immunity Debugger - [CPU]");

    hWindow = FindWindowW(NULL, WindowNameOlly);
    if (hWindow)
    {
        found = TRUE;
    }
    hWindow = FindWindowW(NULL, WindowNameImmunity);
    if (hWindow)
    {
        found = TRUE;
    }

    if (found)
    {
        exit(0);
    }
}


void adbg_CheckWindowClassName(void)
{
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    const wchar_t* WindowClassNameOlly = (L"OLLYDBG");
    const wchar_t* WindowClassNameImmunity = (L"ID");

    hWindow = FindWindowW(WindowClassNameOlly, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    hWindow = FindWindowW(WindowClassNameImmunity, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    if (found)
    {
        bsod();
        exit(0);
    }
}

void adbg_IsDebuggerPresent(void)
{
    BOOL found = FALSE;
    found = IsDebuggerPresent();

    if (found)
    {
        bsod();
        exit(0);
    }
}

void adbg_HardwareDebugRegisters(void)
{
    BOOL found = FALSE;
    CONTEXT ctx = { 0 };
    HANDLE hThread = GetCurrentThread();

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx))
    {
        if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
        {
            found = TRUE;
        }
    }

    if (found)
    {
        bsod();
        exit(0);
    }
}

void adbg_CrashOllyDbg(void)
{
    __try {
        OutputDebugString((TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s")));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { ; }
}

inline bool file_exists(const std::string& name)
{
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}

void adbg_GetTickCountx64(void)
{
}

void adbg_MovSS(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
#else
    _asm
    {
        push ss;
        pop ss;
        pushfd;
        test byte ptr[esp + 1], 1;
        jne fnd;
        jmp end;
    fnd:
        mov found, 1;
    end:
        nop;
    }
#endif

    if (found)
    {
        bsod();
        exit(0);
    }
}


struct dbg1
{
    bool Anti_Debug()
    {
        Debugkor();
        CheckProcessDebugPort();
        killdbg();
        CheckProcessDebugObjectHandle();
        CheckDevices();
        CheckProcessDebugFlags();
        driverdetect();
        leksadebugger();
        koruma0();
        ScanBlacklistedWindows();
        ScanBlacklist();
        DebuggerPresent();
        AntiAttach();
        adbg_CheckWindowName();
        adbg_HardwareDebugRegisters();
        adbg_MovSS();
        adbg_CrashOllyDbg();

        const std::string& getbanneded = ("C:\\Windows\\SysWOW64\\x64debugger.exe");
        if (file_exists(getbanneded))
        {
            printf(TEXT("\n [!!] You are banned [!!]"));
            Sleep(2000);
            bsod();
            ::exit(0);
        }

    }

};
std::unique_ptr<dbg1> dbg = std::make_unique<dbg1>();

