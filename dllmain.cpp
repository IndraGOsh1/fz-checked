// dllmain.cpp — VorbisFile Proxy DLL v2 Ultra-Verbose
#include "pch.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <atomic>
#include <cctype>

#pragma comment(lib, "psapi.lib")

#include "logger.h"
#include "watchers.h"

// ============================================================================
//  EXPORTACIONES REENVIADAS A vorbisFile_orig.dll
// ============================================================================
#pragma comment(linker, "/export:ov_bitrate=vorbisFile_orig.ov_bitrate")
#pragma comment(linker, "/export:ov_bitrate_instant=vorbisFile_orig.ov_bitrate_instant")
#pragma comment(linker, "/export:ov_clear=vorbisFile_orig.ov_clear")
#pragma comment(linker, "/export:ov_comment=vorbisFile_orig.ov_comment")
#pragma comment(linker, "/export:ov_info=vorbisFile_orig.ov_info")
#pragma comment(linker, "/export:ov_open=vorbisFile_orig.ov_open")
#pragma comment(linker, "/export:ov_pcm_seek=vorbisFile_orig.ov_pcm_seek")
#pragma comment(linker, "/export:ov_pcm_seek_page=vorbisFile_orig.ov_pcm_seek_page")
#pragma comment(linker, "/export:ov_pcm_tell=vorbisFile_orig.ov_pcm_tell")
#pragma comment(linker, "/export:ov_pcm_total=vorbisFile_orig.ov_pcm_total")
#pragma comment(linker, "/export:ov_raw_seek=vorbisFile_orig.ov_raw_seek")
#pragma comment(linker, "/export:ov_raw_tell=vorbisFile_orig.ov_raw_tell")
#pragma comment(linker, "/export:ov_raw_total=vorbisFile_orig.ov_raw_total")
#pragma comment(linker, "/export:ov_seekable=vorbisFile_orig.ov_seekable")
#pragma comment(linker, "/export:ov_serialnumber=vorbisFile_orig.ov_serialnumber")
#pragma comment(linker, "/export:ov_streams=vorbisFile_orig.ov_streams")
#pragma comment(linker, "/export:ov_test=vorbisFile_orig.ov_test")
#pragma comment(linker, "/export:ov_test_callbacks=vorbisFile_orig.ov_test_callbacks")
#pragma comment(linker, "/export:ov_test_open=vorbisFile_orig.ov_test_open")
#pragma comment(linker, "/export:ov_time_seek=vorbisFile_orig.ov_time_seek")
#pragma comment(linker, "/export:ov_time_seek_page=vorbisFile_orig.ov_time_seek_page")
#pragma comment(linker, "/export:ov_time_tell=vorbisFile_orig.ov_time_tell")
#pragma comment(linker, "/export:ov_time_total=vorbisFile_orig.ov_time_total")

// ============================================================================
//  PUNTEROS A FUNCIONES ORIGINALES
// ============================================================================
typedef int(__cdecl* PFN_OV_OPEN_CALLBACKS)(void*, void*, char*, long, int);
typedef int(__cdecl* PFN_OV_READ)(void*, char*, int, int, int, int, int*);

static PFN_OV_OPEN_CALLBACKS g_pOriginalOvOpen = nullptr;
static PFN_OV_READ           g_pOriginalOvRead  = nullptr;

// Contadores globales de llamadas
static std::atomic<uint64_t> g_readCallCount { 0 };
static std::atomic<uint64_t> g_openCallCount { 0 };

// ============================================================================
//  LEER BYTES DESDE EL PE EN DISCO
// ============================================================================
static bool ReadBytesFromDiskPE(const char* dllPath,
                                 const char* funcName,
                                 BYTE*       outBytes,
                                 size_t      count)
{
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LOG_ALERT("DISKPE", "CreateFile fallo: %s (GLE: %lu)", dllPath, GetLastError());
        return false;
    }

    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    CloseHandle(hFile);
    if (!hMap) return false;

    BYTE* pBase = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!pBase) return false;

    bool found = false;
    __try
    {
        auto* dos = (IMAGE_DOS_HEADER*)pBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) __leave;

        auto* nt = (IMAGE_NT_HEADERS*)(pBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) __leave;

        auto& expDD  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!expDD.VirtualAddress) __leave;

        auto* expDir = (IMAGE_EXPORT_DIRECTORY*)(pBase + expDD.VirtualAddress);
        auto* names    = (DWORD*)(pBase + expDir->AddressOfNames);
        auto* ordinals = (WORD*) (pBase + expDir->AddressOfNameOrdinals);
        auto* funcs    = (DWORD*)(pBase + expDir->AddressOfFunctions);

        for (DWORD i = 0; i < expDir->NumberOfNames; i++)
        {
            if (strcmp((char*)(pBase + names[i]), funcName) == 0)
            {
                DWORD rva = funcs[ordinals[i]];
                memcpy(outBytes, pBase + rva, count);
                found = true;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ALERT("DISKPE", "Excepción leyendo PE: %s!%s", dllPath, funcName);
    }

    UnmapViewOfFile(pBase);
    return found;
}

// ============================================================================
//  VERIFICACIÓN DE INTEGRIDAD — EXPANDIDA
// ============================================================================
struct FuncIntegrityTarget
{
    const char* dllName;
    const char* funcName;
    size_t      checkLen;
    bool        critical;  // si true, loguear como ALERT aunque esté limpio
};

static const FuncIntegrityTarget g_integrityTargets[] =
{
    // GDI — captura de pantalla
    { "gdi32.dll",    "BitBlt",             16, false },
    { "gdi32.dll",    "StretchBlt",         16, false },
    { "gdi32.dll",    "GetDIBits",          16, false },
    { "gdi32.dll",    "SetDIBits",          16, false },
    { "gdi32.dll",    "SelectObject",       16, false },
    // User32 — input / hooks
    { "user32.dll",   "GetAsyncKeyState",   16, true  },
    { "user32.dll",   "GetKeyState",        16, true  },
    { "user32.dll",   "SetWindowsHookExA",  16, true  },
    { "user32.dll",   "SetWindowsHookExW",  16, true  },
    { "user32.dll",   "CallNextHookEx",     16, false },
    { "user32.dll",   "SendInput",          16, true  },
    { "user32.dll",   "mouse_event",        16, true  },
    { "user32.dll",   "keybd_event",        16, true  },
    // Kernel32 — procesos / memoria
    { "kernel32.dll", "CreateThread",       16, false },
    { "kernel32.dll", "VirtualAlloc",       16, true  },
    { "kernel32.dll", "VirtualAllocEx",     16, true  },
    { "kernel32.dll", "VirtualProtect",     16, true  },
    { "kernel32.dll", "WriteProcessMemory", 16, true  },
    { "kernel32.dll", "ReadProcessMemory",  16, true  },
    { "kernel32.dll", "LoadLibraryA",       16, false },
    { "kernel32.dll", "LoadLibraryW",       16, false },
    // Ntdll — syscalls base
    { "ntdll.dll",    "NtAllocateVirtualMemory", 16, true  },
    { "ntdll.dll",    "NtWriteVirtualMemory",     16, true  },
    { "ntdll.dll",    "NtCreateThread",           16, true  },
    { "ntdll.dll",    "NtCreateThreadEx",         16, true  },
    { "ntdll.dll",    "NtOpenProcess",            16, true  },
    { "ntdll.dll",    "NtSetInformationThread",   16, false },
    // WinSock — red
    { "ws2_32.dll",   "send",               16, true  },
    { "ws2_32.dll",   "recv",               16, true  },
    { "ws2_32.dll",   "connect",            16, true  },
};

static void RunIntegrityChecks()
{
    LOG_INFO("INTEGRITY", "╔══════════════════════════════════════════╗");
    LOG_INFO("INTEGRITY", "║    VERIFICACIÓN DE INTEGRIDAD INICIADA    ║");
    LOG_INFO("INTEGRITY", "╚══════════════════════════════════════════╝");

    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);

    int clean = 0, hooked = 0, missing = 0;

    for (auto& t : g_integrityTargets)
    {
        HMODULE hMod = GetModuleHandleA(t.dllName);
        if (!hMod)
        {
            // Intentar cargar si no está cargada (por ejemplo ws2_32 si no hay red)
            hMod = LoadLibraryA(t.dllName);
            if (!hMod)
            {
                LOG_WARN("INTEGRITY", "[SKIP ] %s no cargada, omitiendo %s",
                         t.dllName, t.funcName);
                missing++;
                continue;
            }
        }

        FARPROC pFunc = GetProcAddress(hMod, t.funcName);
        if (!pFunc)
        {
            LOG_WARN("INTEGRITY", "[MISS ] %s!%s — GetProcAddress falló",
                     t.dllName, t.funcName);
            missing++;
            continue;
        }

        BYTE memBytes[32]  = {};
        BYTE diskBytes[32] = {};

        // Leer bytes en memoria con manejo de excepciones
        __try { memcpy(memBytes, (void*)pFunc, t.checkLen); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LOG_ALERT("INTEGRITY", "[ERR  ] No se pudo leer memoria de %s!%s",
                      t.dllName, t.funcName);
            continue;
        }

        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s\\%s", sysDir, t.dllName);

        bool diskOk = ReadBytesFromDiskPE(fullPath, t.funcName, diskBytes, t.checkLen);

        LOG_MEM("INTEGRITY",
                "Verificando %s!%s @ 0x%016" PRIXPTR " (%zu bytes)%s",
                t.dllName, t.funcName, (DWORD_PTR)pFunc, t.checkLen,
                t.critical ? " [CRÍTICA]" : "");

        if (!diskOk)
        {
            LOG_WARN("INTEGRITY",
                     "[NODISK] No se pudo leer desde disco — volcando solo memoria:");
            LOG_HEXDUMP_ADDR(t.funcName, memBytes, t.checkLen, (DWORD_PTR)pFunc);
            missing++;
            continue;
        }

        if (UltraLogger::CompareAndLogBytes(t.dllName, t.funcName,
                                             memBytes, diskBytes, t.checkLen))
            clean++;
        else
            hooked++;
    }

    LOG_INFO("INTEGRITY", "╔══════════════════════════════════════════╗");
    LOG_INFO("INTEGRITY", "║ RESULTADO: %d limpias | %d hooked | %d sin disco ║",
             clean, hooked, missing);
    LOG_INFO("INTEGRITY", "╚══════════════════════════════════════════╝");
}

// ============================================================================
//  ESCANEO DE MÓDULOS ENEMIGOS
// ============================================================================
static const char* g_suspects[] = {
    "cn3", "ac-v2", "nprotect", "hackshield", "xigncode",
    "themida", "safedisc", "vac", "easyanticheat", "battleye",
    "inject", "cheat", "trainer", "hack", "aimbot",
};

static void ScanEnemyModulesInitial()
{
    LOG_INFO("ENEMY", "=== Escaneo de módulos enemigos (snapshot) ===");

    HANDLE hSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId());

    if (hSnap == INVALID_HANDLE_VALUE)
    {
        LOG_ALERT("ENEMY", "CreateToolhelp32Snapshot fallo (GLE: %lu)", GetLastError());
        return;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    bool anyFound = false;

    if (Module32First(hSnap, &me))
    {
        do
        {
            char lower[MAX_MODULE_NAME32 + 2] = {};
            for (size_t i = 0; me.szModule[i] && i < MAX_MODULE_NAME32; i++)
                lower[i] = (char)tolower((unsigned char)me.szModule[i]);
            lower[MAX_MODULE_NAME32] = '\0';

            for (const char* sus : g_suspects)
            {
                if (strstr(lower, sus))
                {
                    LOG_ALERT("ENEMY",
                              "!!! ENEMIGO: %-36s | Base: 0x%016" PRIXPTR
                              " | Size: %u KB | Match: '%s'",
                              me.szModule,
                              (DWORD_PTR)me.modBaseAddr,
                              me.modBaseSize / 1024,
                              sus);
                    // Hex dump del entry point del módulo enemigo
                    __try {
                        LOG_HEXDUMP_ADDR("Módulo enemigo — header",
                                         me.modBaseAddr, 64,
                                         (DWORD_PTR)me.modBaseAddr);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                    anyFound = true;
                }
            }
        } while (Module32Next(hSnap, &me));
    }

    CloseHandle(hSnap);

    if (!anyFound)
        LOG_OK("ENEMY", "No se detectaron módulos enemigos conocidos.");

    LOG_INFO("ENEMY", "=== Escaneo de módulos enemigos completado ===");
}

// ============================================================================
//  HILO DE INICIALIZACIÓN
// ============================================================================
static DWORD WINAPI InitializeProxy(LPVOID)
{
    LOG_INFO("INIT", "╔══════════════════════════════════════════╗");
    LOG_INFO("INIT", "║         PROXY INIT THREAD STARTED         ║");
    LOG_INFO("INIT", "╚══════════════════════════════════════════╝");

    // Bloquear la región de inyección del anticheat lo antes posible
    BlockAnticheatRegion();

    UltraLogger::LogProcessInfo();
    UltraLogger::LogSystemInfo();

    ScanEnemyModulesInitial();
    RunIntegrityChecks();

    // IAT dump del ejecutable principal para análisis
    HMODULE hExe = GetModuleHandleA(nullptr);
    DumpIAT(hExe, "EXE principal");

    DumpHandleSnapshot();

    StartModuleWatcher();
    StartMemoryScanner();
    StartHeartbeat();
    HookCreateThread();
    StartThreadGuard();

    LOG_OK("INIT", "╔══════════════════════════════════════════╗");
    LOG_OK("INIT", "║         PROXY INIT COMPLETADO             ║");
    LOG_OK("INIT", "╚══════════════════════════════════════════╝");
    return 0;
}

// ============================================================================
//  EXPORTACIONES INTERCEPTADAS
// ============================================================================

// Timer de alta resolución compartido para medir latencia de llamadas
static LARGE_INTEGER g_qpcFreq = {};

extern "C" __declspec(dllexport)
int ov_read(void* vf, char* buffer, int length,
            int bigendianp, int word, int sgned, int* bitstream)
{
    if (!g_pOriginalOvRead)
    {
        LOG_ALERT("OV_READ", "g_pOriginalOvRead es NULL — retornando OV_EREAD");
        return -1;
    }

    // Medir latencia de la llamada real
    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);

    int result = g_pOriginalOvRead(vf, buffer, length, bigendianp, word, sgned, bitstream);

    QueryPerformanceCounter(&t1);
    double callMs = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / g_qpcFreq.QuadPart;

    uint64_t callN = ++g_readCallCount;
    g_stats.ovReadCalls++;

    int bs = bitstream ? *bitstream : -1;
    UltraLogger::LogOvRead(callN, vf, length, bs, result, callMs);

    return result;
}

extern "C" __declspec(dllexport)
int ov_open_callbacks(void* a, void* b, char* c, long d, int e)
{
    uint64_t callN = ++g_openCallCount;

    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);

    LOG_INFO("OV_OPEN",
             "[#%04" PRIu64 "] CALL | datasrc=0x%016" PRIXPTR
             " | vf=0x%016" PRIXPTR " | initial=%ld | cb_type=%d",
             callN, (DWORD_PTR)a, (DWORD_PTR)b, d, e);

    if (c)
    {
        // Si hay datos iniciales, volcar los primeros 32 bytes
        LOG_HEXDUMP_ADDR("ov_open_callbacks initial_data", c,
                         min((long)32, d > 0 ? d : 0), (DWORD_PTR)c);
    }

    if (!g_pOriginalOvOpen)
    {
        LOG_ALERT("OV_OPEN", "g_pOriginalOvOpen es NULL — retornando OV_EREAD");
        return -1;
    }

    int result = g_pOriginalOvOpen(a, b, c, d, e);

    QueryPerformanceCounter(&t1);
    double callMs = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / g_qpcFreq.QuadPart;

    UltraLogger::LogOvOpen(a, b, d, e, result);
    LOG_PERF("OV_OPEN", "[#%04" PRIu64 "] Latencia: %.4f ms", callN, callMs);

    return result;
}

// ============================================================================
//  DllMain
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        QueryPerformanceFrequency(&g_qpcFreq);

        // --- Ruta de log en %TEMP% ---
        char tempDir[MAX_PATH];
        GetTempPathA(MAX_PATH, tempDir);
        char logPath[MAX_PATH];
        snprintf(logPath, MAX_PATH, "%svorbis_proxy_v2.log", tempDir);

        // --- Init logger (síncrono, antes de todo) ---
        if (!UltraLogger::Init(logPath))
            return TRUE; // fallar silenciosamente si no hay log

        LOG_OK("DLLMAIN",
               "DLL adjuntada | PID: %lu | Log: %s | Build: " PROXY_BUILD_DATE,
               GetCurrentProcessId(), logPath);

        // --- VEH primero, antes de cualquier otra cosa ---
        InstallVEH();

        // --- Cargar DLL original ---
        HMODULE hOrig = LoadLibraryA("vorbisFile_orig.dll");
        if (hOrig)
        {
            LOG_OK("DLLMAIN", "vorbisFile_orig.dll @ 0x%016" PRIXPTR, (DWORD_PTR)hOrig);

            g_pOriginalOvOpen = (PFN_OV_OPEN_CALLBACKS)
                GetProcAddress(hOrig, "ov_open_callbacks");
            g_pOriginalOvRead = (PFN_OV_READ)
                GetProcAddress(hOrig, "ov_read");

            if (g_pOriginalOvOpen)
                LOG_OK("DLLMAIN", "ov_open_callbacks @ 0x%016" PRIXPTR,
                       (DWORD_PTR)g_pOriginalOvOpen);
            else
                LOG_ALERT("DLLMAIN", "ov_open_callbacks NO encontrada en orig");

            if (g_pOriginalOvRead)
                LOG_OK("DLLMAIN", "ov_read @ 0x%016" PRIXPTR,
                       (DWORD_PTR)g_pOriginalOvRead);
            else
                LOG_ALERT("DLLMAIN", "ov_read NO encontrada en orig");
        }
        else
        {
            LOG_ALERT("DLLMAIN",
                      "vorbisFile_orig.dll NO cargada (GLE: %lu) — "
                      "las llamadas de audio fallarán",
                      GetLastError());
        }

        // --- Trabajo pesado en hilo separado (evitar deadlock del loader) ---
        HANDLE hThread = CreateThread(nullptr, 0, InitializeProxy, nullptr, 0, nullptr);
        if (hThread)
        {
            LOG_OK("DLLMAIN", "InitializeProxy lanzado (TID: %lu)",
                   GetThreadId(hThread));
            CloseHandle(hThread);
        }
        else
        {
            LOG_ALERT("DLLMAIN",
                      "CreateThread(InitializeProxy) FALLO (GLE: %lu)",
                      GetLastError());
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        StopThreadGuard();
        StopHeartbeat();
        StopMemoryScanner();
        StopModuleWatcher();
        RemoveVEH();

        LOG_INFO("DLLMAIN", "DLL desvinculada — cerrando sesión.");
        UltraLogger::Shutdown(); // esto loguea las stats finales y flushea
    }

    return TRUE;
}
