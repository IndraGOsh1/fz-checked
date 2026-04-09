// watchers.cpp — Implementación completa de todos los watchers
// VEH + ModuleWatcher + MemoryScanner + IAT Hook + Heartbeat
#include "pch.h"
#include "watchers.h"
#include "logger.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <unordered_map>
#include <string>
#include <atomic>
#include <mutex>
#include <cinttypes>

// ============================================================================
//  VECTORED EXCEPTION HANDLER
// ============================================================================
static PVOID g_vehHandle = nullptr;

static LONG WINAPI VEH_Handler(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;

    DWORD code = ep->ExceptionRecord->ExceptionCode;

    // Filtrar excepciones de control de flujo normales
    if (code == 0xE06D7363 ||   // C++ throw
        code == 0x406D1388 ||   // SetThreadName (MSVC)
        code == EXCEPTION_BREAKPOINT ||
        code == EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD_PTR faultAddr = ep->ExceptionRecord->NumberParameters > 1
        ? (DWORD_PTR)ep->ExceptionRecord->ExceptionInformation[1]
        : (DWORD_PTR)ep->ExceptionRecord->ExceptionAddress;

    UltraLogger::LogExceptionContext(code, faultAddr, ep->ContextRecord);

    return EXCEPTION_CONTINUE_SEARCH;
}

void InstallVEH()
{
    g_vehHandle = AddVectoredExceptionHandler(1, VEH_Handler);
    if (g_vehHandle)
        LOG_OK("VEH", "VEH instalado @ 0x%016" PRIXPTR, (DWORD_PTR)g_vehHandle);
    else
        LOG_ALERT("VEH", "AddVectoredExceptionHandler FALLO (GLE: %lu)", GetLastError());
}

void RemoveVEH()
{
    if (g_vehHandle)
    {
        RemoveVectoredExceptionHandler(g_vehHandle);
        g_vehHandle = nullptr;
        LOG_INFO("VEH", "VEH removido.");
    }
}

// ============================================================================
//  MODULE WATCHER
// ============================================================================
static std::unordered_map<DWORD_PTR, std::string> g_knownModules;
static std::mutex                                  g_modMutex;
static std::atomic<bool>                           g_watcherRunning{ false };
static HANDLE                                      g_watcherThread = nullptr;

static void SnapshotModules(bool initialScan)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId());

    if (hSnap == INVALID_HANDLE_VALUE)
    {
        LOG_WARN("MODWATCH", "CreateToolhelp32Snapshot fallo (GLE: %lu)", GetLastError());
        return;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    std::unordered_map<DWORD_PTR, std::string> current;

    if (Module32First(hSnap, &me))
    {
        do {
            current[(DWORD_PTR)me.modBaseAddr] = me.szModule;
        } while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);

    std::lock_guard<std::mutex> lk(g_modMutex);

    // Nuevos módulos cargados
    for (auto& [base, name] : current)
    {
        if (g_knownModules.find(base) == g_knownModules.end())
        {
            MODULEINFO mi{};
            DWORD sz = 0;
            HMODULE hm = (HMODULE)base;
            if (GetModuleInformation(GetCurrentProcess(), hm, &mi, sizeof(mi)))
                sz = mi.SizeOfImage;

            if (!initialScan)
                UltraLogger::LogModuleEvent(true, name.c_str(), base, sz);
            else
            {
                // En el escaneo inicial, loguear igualmente con tamaño
                UltraLogger::LogModuleEvent(true, name.c_str(), base, sz);
            }
        }
    }

    // Módulos descargados
    for (auto& [base, name] : g_knownModules)
    {
        if (current.find(base) == current.end())
            UltraLogger::LogModuleEvent(false, name.c_str(), base, 0);
    }

    g_knownModules = std::move(current);
}

static DWORD WINAPI ModuleWatcherThread(LPVOID)
{
    LOG_INFO("MODWATCH", "Hilo ModuleWatcher iniciado (intervalo: 500ms)");

    // Primer escaneo para establecer baseline
    LOG_INFO("MODWATCH", "=== Escaneo inicial de módulos ===");
    SnapshotModules(true);
    LOG_INFO("MODWATCH", "=== Baseline: %zu módulos cargados ===", g_knownModules.size());

    while (g_watcherRunning.load())
    {
        Sleep(500);
        SnapshotModules(false);
    }

    LOG_INFO("MODWATCH", "Hilo ModuleWatcher terminado.");
    return 0;
}

void StartModuleWatcher()
{
    g_watcherRunning = true;
    g_watcherThread  = CreateThread(nullptr, 0, ModuleWatcherThread, nullptr, 0, nullptr);
    if (g_watcherThread)
        LOG_OK("MODWATCH", "ModuleWatcher iniciado (TID: %lu)", GetThreadId(g_watcherThread));
    else
        LOG_ALERT("MODWATCH", "CreateThread ModuleWatcher FALLO (GLE: %lu)", GetLastError());
}

void StopModuleWatcher()
{
    g_watcherRunning = false;
    if (g_watcherThread)
    {
        WaitForSingleObject(g_watcherThread, 2000);
        CloseHandle(g_watcherThread);
        g_watcherThread = nullptr;
    }
}

// ============================================================================
//  MEMORY SCANNER — escanea el espacio de memoria virtual del proceso
//  Detecta regiones RWX (shellcode), páginas guard modificadas,
//  y cambios en regiones conocidas entre ciclos.
// ============================================================================
static std::atomic<bool> g_memScanRunning{ false };
static HANDLE            g_memScanThread = nullptr;

// Protección de regiones conocidas (para detectar cambios entre ciclos)
struct RegionSnapshot
{
    DWORD   protect;
    DWORD   state;
    SIZE_T  size;
};
static std::unordered_map<DWORD_PTR, RegionSnapshot> g_knownRegions;
static std::mutex                                     g_regionMutex;

static void ScanMemoryFull(bool initialScan)
{
    g_stats.memScanCycles++;

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    BYTE* addr      = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* maxAddr   = (BYTE*)si.lpMaximumApplicationAddress;

    size_t totalCommit = 0, totalRWX = 0, totalPrivate = 0;
    size_t regionsScanned = 0;

    std::unordered_map<DWORD_PTR, RegionSnapshot> currentRegions;

    while (addr < maxAddr)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) break;

        regionsScanned++;
        DWORD_PTR base = (DWORD_PTR)mbi.BaseAddress;

        if (mbi.State == MEM_COMMIT)
        {
            totalCommit += mbi.RegionSize;

            RegionSnapshot snap;
            snap.protect = mbi.Protect;
            snap.state   = mbi.State;
            snap.size    = mbi.RegionSize;
            currentRegions[base] = snap;

            // ---- Detectar RWX privada (shellcode) ----------------------
            DWORD prot = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
            bool isRWX = (prot == PAGE_EXECUTE_READWRITE ||
                          prot == PAGE_EXECUTE_WRITECOPY);

            if (isRWX && mbi.Type == MEM_PRIVATE)
            {
                totalRWX++;
                g_stats.rxwRegions++;
                UltraLogger::LogMemoryRegion(mbi, true);

                // Hex dump de los primeros 128 bytes de la región sospechosa
                if (mbi.RegionSize >= 16)
                {
                    size_t dumpLen = min(mbi.RegionSize, (SIZE_T)128);
                    BYTE dumpBuf[128] = {};
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, dumpBuf, dumpLen, &bytesRead) && bytesRead > 0)
                    {
                        UltraLogger::HexDumpWithASCII("RWX privada — primeros bytes", dumpBuf, bytesRead, base);
                    }
                    else
                    {
                        LOG_WARN("MEMSCAN", "  No se pudo leer la región RWX @ 0x%016" PRIXPTR, base);
                    }
                }
            }

            // ---- Detectar cambio de protección respecto al ciclo anterior ----
            if (!initialScan)
            {
                std::lock_guard<std::mutex> lk(g_regionMutex);
                auto it = g_knownRegions.find(base);
                if (it != g_knownRegions.end())
                {
                    if (it->second.protect != mbi.Protect)
                    {
                        LOG_ALERT("MEMSCAN",
                                  "CAMBIO DE PROTECCIÓN @ 0x%016" PRIXPTR
                                  " | anterior=0x%04X → nuevo=0x%04X | Size: %zu KB",
                                  base,
                                  it->second.protect, mbi.Protect,
                                  mbi.RegionSize / 1024);
                    }
                }
                else if (mbi.Type == MEM_PRIVATE && !isRWX)
                {
                    // Nueva región privada que no es RWX (puede ser heap normal,
                    // pero loguear si tiene permisos de ejecución)
                    if (prot & PAGE_EXECUTE || prot & PAGE_EXECUTE_READ)
                    {
                        LOG_WARN("MEMSCAN",
                                 "Nueva región ejecutable @ 0x%016" PRIXPTR
                                 " | Prot=0x%04X | Size=%zu KB",
                                 base, mbi.Protect, mbi.RegionSize / 1024);
                    }
                }
            }

            if (mbi.Type == MEM_PRIVATE) totalPrivate += mbi.RegionSize;
        }

        addr += mbi.RegionSize;
    }

    // Actualizar snapshot de regiones
    {
        std::lock_guard<std::mutex> lk(g_regionMutex);
        g_knownRegions = std::move(currentRegions);
    }

    LOG_MEMSCAN("MEMSCAN",
                "Ciclo %s: %zu regiones | Commit: %zu MB | Private: %zu MB | RWX detectadas: %zu",
                initialScan ? "INICIAL" : "DELTA",
                regionsScanned,
                totalCommit / (1024*1024),
                totalPrivate / (1024*1024),
                totalRWX);
}

static DWORD WINAPI MemoryScannerThread(LPVOID)
{
    LOG_INFO("MEMSCAN", "Hilo MemoryScanner iniciado (intervalo: 2000ms)");

    // Primer ciclo completo como baseline
    ScanMemoryFull(true);

    while (g_memScanRunning.load())
    {
        Sleep(2000);
        ScanMemoryFull(false);
    }

    LOG_INFO("MEMSCAN", "Hilo MemoryScanner terminado.");
    return 0;
}

void StartMemoryScanner()
{
    g_memScanRunning = true;
    g_memScanThread  = CreateThread(nullptr, 0, MemoryScannerThread, nullptr, 0, nullptr);
    if (g_memScanThread)
        LOG_OK("MEMSCAN", "MemoryScanner iniciado (TID: %lu)", GetThreadId(g_memScanThread));
    else
        LOG_ALERT("MEMSCAN", "CreateThread MemoryScanner FALLO (GLE: %lu)", GetLastError());
}

void StopMemoryScanner()
{
    g_memScanRunning = false;
    if (g_memScanThread)
    {
        WaitForSingleObject(g_memScanThread, 5000);
        CloseHandle(g_memScanThread);
        g_memScanThread = nullptr;
    }
}

// ============================================================================
//  IAT HOOK — CreateThread
// ============================================================================
typedef HANDLE(WINAPI* PFN_CreateThread)(
    LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
    LPVOID, DWORD, LPDWORD);

static PFN_CreateThread g_origCreateThread = nullptr;

static HANDLE WINAPI Hooked_CreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId)
{
    HANDLE hThread = g_origCreateThread(
        lpThreadAttributes, dwStackSize, lpStartAddress,
        lpParameter, dwCreationFlags, lpThreadId);

    if (hThread)
    {
        DWORD tid = lpThreadId ? *lpThreadId : GetThreadId(hThread);
        UltraLogger::LogThreadCreation(tid, (DWORD_PTR)lpStartAddress, "IAT Hook");

        // Loguear stack size y flags
        LOG_THREAD("THREAD",
                   "  dwStackSize=%zu | CreationFlags=0x%08X | Suspendido=%s",
                   dwStackSize,
                   dwCreationFlags,
                   (dwCreationFlags & CREATE_SUSPENDED) ? "SI" : "NO");
    }
    return hThread;
}

bool HookCreateThread()
{
    HMODULE hSelf = nullptr;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&HookCreateThread, &hSelf);

    if (!hSelf)
    {
        LOG_ALERT("THREADHOOK", "No se pudo obtener handle del módulo propio");
        return false;
    }

    auto* dos    = (IMAGE_DOS_HEADER*)hSelf;
    auto* nt     = (IMAGE_NT_HEADERS*)((BYTE*)hSelf + dos->e_lfanew);
    auto& iatDD  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto* impDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hSelf + iatDD.VirtualAddress);

    int hooked = 0;

    for (; impDesc->Name; impDesc++)
    {
        const char* dllName = (const char*)((BYTE*)hSelf + impDesc->Name);
        if (_stricmp(dllName, "KERNEL32.DLL") != 0) continue;

        auto* thunk = (IMAGE_THUNK_DATA*)((BYTE*)hSelf + impDesc->FirstThunk);
        auto* orig  = (IMAGE_THUNK_DATA*)((BYTE*)hSelf + impDesc->OriginalFirstThunk);

        for (; thunk->u1.Function; thunk++, orig++)
        {
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;

            auto* nameEntry = (IMAGE_IMPORT_BY_NAME*)
                ((BYTE*)hSelf + orig->u1.AddressOfData);

            if (strcmp((char*)nameEntry->Name, "CreateThread") != 0) continue;

            g_origCreateThread = (PFN_CreateThread)thunk->u1.Function;

            DWORD oldProt;
            VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR),
                           PAGE_EXECUTE_READWRITE, &oldProt);
            thunk->u1.Function = (ULONG_PTR)Hooked_CreateThread;
            VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR),
                           oldProt, &oldProt);

            LOG_OK("THREADHOOK",
                   "CreateThread IAT patch OK | Original @ 0x%016" PRIXPTR,
                   (DWORD_PTR)g_origCreateThread);
            hooked++;
            break;
        }
    }

    if (!hooked)
        LOG_WARN("THREADHOOK", "CreateThread no encontrada en la IAT");

    return (hooked > 0);
}

// ============================================================================
//  HEARTBEAT — estadísticas y estado del sistema periódicamente
// ============================================================================
static std::atomic<bool> g_heartbeatRunning{ false };
static HANDLE            g_heartbeatThread = nullptr;
static constexpr DWORD   HEARTBEAT_INTERVAL_MS = 10000; // cada 10 segundos

static DWORD WINAPI HeartbeatThread(LPVOID)
{
    LOG_INFO("HEARTBEAT", "Hilo Heartbeat iniciado (intervalo: %lu ms)", HEARTBEAT_INTERVAL_MS);

    DWORD beat = 0;

    while (g_heartbeatRunning.load())
    {
        Sleep(HEARTBEAT_INTERVAL_MS);
        if (!g_heartbeatRunning.load()) break;

        beat++;

        // ---- Memoria del proceso ----------------------------------------
        PROCESS_MEMORY_COUNTERS_EX pmc = {};
        pmc.cb = sizeof(pmc);
        GetProcessMemoryInfo(GetCurrentProcess(),
                             (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));

        // ---- RAM del sistema --------------------------------------------
        MEMORYSTATUSEX ms = {};
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);

        LOG_PERF("HEARTBEAT",
                 "[Beat #%lu | T=%.1fs] "
                 "WS=%zu MB | PeakWS=%zu MB | Private=%zu MB | "
                 "SysRAM carga=%lu%% libre=%llu MB | "
                 "ov_read#=%" PRIu64 " bytes=%" PRIu64 " errs=%" PRIu64 " | "
                 "Threads=%" PRIu64 " Mods=%" PRIu64 " Hooks=%" PRIu64,
                 beat, UltraLogger::ElapsedMs() / 1000.0,
                 pmc.WorkingSetSize  / (1024*1024),
                 pmc.PeakWorkingSetSize / (1024*1024),
                 pmc.PrivateUsage    / (1024*1024),
                 ms.dwMemoryLoad,
                 ms.ullAvailPhys     / (1024*1024),
                 g_stats.ovReadCalls.load(),
                 g_stats.ovReadBytes.load(),
                 g_stats.ovReadErrors.load(),
                 g_stats.threadsDetected.load(),
                 g_stats.modulesLoaded.load(),
                 g_stats.hooksDetected.load());
    }

    LOG_INFO("HEARTBEAT", "Hilo Heartbeat terminado.");
    return 0;
}

void StartHeartbeat()
{
    g_heartbeatRunning = true;
    g_heartbeatThread  = CreateThread(nullptr, 0, HeartbeatThread, nullptr, 0, nullptr);
    if (g_heartbeatThread)
        LOG_OK("HEARTBEAT", "Heartbeat iniciado (TID: %lu)", GetThreadId(g_heartbeatThread));
    else
        LOG_ALERT("HEARTBEAT", "CreateThread Heartbeat FALLO (GLE: %lu)", GetLastError());
}

void StopHeartbeat()
{
    g_heartbeatRunning = false;
    if (g_heartbeatThread)
    {
        WaitForSingleObject(g_heartbeatThread, 2000);
        CloseHandle(g_heartbeatThread);
        g_heartbeatThread = nullptr;
    }
}

// ============================================================================
//  IAT DUMP — volcar toda la IAT de un módulo
// ============================================================================
void DumpIAT(HMODULE hModule, const char* label)
{
    if (!hModule) return;

    LOG_INFO("IAT", "=== IAT DUMP: %s | Base: 0x%016" PRIXPTR " ===",
             label, (DWORD_PTR)hModule);

    auto* dos    = (IMAGE_DOS_HEADER*)hModule;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    auto* nt     = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    auto& iatDD  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!iatDD.VirtualAddress) { LOG_WARN("IAT", "No hay directorio de importaciones."); return; }

    auto* impDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModule + iatDD.VirtualAddress);
    int totalFuncs = 0;

    for (; impDesc->Name; impDesc++)
    {
        const char* dllName = (const char*)((BYTE*)hModule + impDesc->Name);
        LOG_INFO("IAT", "  DLL: %s", dllName);

        auto* thunk = (IMAGE_THUNK_DATA*)((BYTE*)hModule + impDesc->FirstThunk);
        auto* orig  = (IMAGE_THUNK_DATA*)((BYTE*)hModule + impDesc->OriginalFirstThunk);

        for (int idx = 0; thunk->u1.Function; thunk++, orig++, idx++)
        {
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal))
            {
                LOG_TRACE("IAT", "    [%3d] Ordinal #%lu @ 0x%016" PRIXPTR,
                          idx,
                          (unsigned long)IMAGE_ORDINAL(orig->u1.Ordinal),
                          (DWORD_PTR)thunk->u1.Function);
            }
            else
            {
                auto* nameEntry = (IMAGE_IMPORT_BY_NAME*)
                    ((BYTE*)hModule + orig->u1.AddressOfData);
                LOG_TRACE("IAT", "    [%3d] %-40s @ 0x%016" PRIXPTR,
                          idx,
                          (char*)nameEntry->Name,
                          (DWORD_PTR)thunk->u1.Function);
            }
            totalFuncs++;
        }
    }

    LOG_INFO("IAT", "=== FIN IAT DUMP: %d funciones totales ===", totalFuncs);
}

// ============================================================================
//  HANDLE SNAPSHOT
// ============================================================================
void DumpHandleSnapshot()
{
    // Usar NtQuerySystemInformation si está disponible para un dump completo
    // Por ahora loguear el handle count del proceso via GetProcessHandleCount
    DWORD handleCount = 0;
    if (GetProcessHandleCount(GetCurrentProcess(), &handleCount))
        LOG_INFO("HANDLES", "Handles abiertos en el proceso: %lu", handleCount);
}
