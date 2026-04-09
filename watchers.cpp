// watchers.cpp — Implementación completa de todos los watchers
// VEH + ModuleWatcher + MemoryScanner + IAT Hook + Heartbeat
#include "pch.h"
#include "watchers.h"
#include "logger.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <cinttypes>

// ============================================================================
//  CONSTANTES GLOBALES — región fantasma del anticheat
// ============================================================================
// Dirección base del módulo MZ fantasma detectado en logs (inyectado por el AC)
static const DWORD_PTR GHOST_BASE  = 0x63480000ULL;
static const SIZE_T    GHOST_RANGE = 0x10000ULL; // 64 KB de margen

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

    // Si el anticheat intenta escribir en la región bloqueada, ignorar la
    // excepción silenciosamente para evitar que crashee el proceso.
    if (code == EXCEPTION_ACCESS_VIOLATION &&
        faultAddr >= GHOST_BASE &&
        faultAddr <  GHOST_BASE + GHOST_RANGE)
    {
        LOG_WARN("VEH",
                 "AV interceptado en región AC bloqueada @ 0x%016" PRIXPTR
                 " — ignorado (CONTINUE_EXECUTION)",
                 faultAddr);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

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

// ============================================================================
//  THREAD GUARD — detección y suspensión agresiva de hilos sospechosos
// ============================================================================

// NtQueryInformationThread cargada dinámicamente desde ntdll.dll
typedef LONG (NTAPI* PFN_NtQueryInformationThread)(
    HANDLE  ThreadHandle,
    ULONG   ThreadInformationClass,
    PVOID   ThreadInformation,
    ULONG   ThreadInformationLength,
    PULONG  ReturnLength);

// ThreadQuerySetWin32StartAddress — clase de información para obtener
// la dirección de inicio original (Win32 entry point) de un hilo
static const ULONG TH_WIN32_START_ADDR = 9;

static std::atomic<bool> g_threadGuardRunning{ false };
static HANDLE            g_threadGuardThread  = nullptr;
static DWORD             g_threadGuardTid     = 0;

static constexpr DWORD THREAD_GUARD_INTERVAL_MS        = 10;   // 10ms — escaneo agresivo
static constexpr DWORD THREAD_GUARD_STARTUP_DELAY_MS   = 2000; // deja estabilizar el loader
static constexpr DWORD THREAD_GUARD_SHUTDOWN_TIMEOUT_MS = 3000;

// Rango de un módulo cargado legalmente en el proceso
struct ModuleRange
{
    DWORD_PTR base;
    DWORD_PTR end;
};

// Construye la lista de rangos de todos los módulos cargados en este ciclo.
// Siempre incluye explícitamente nuestro proxy DLL y vorbisFile_orig.dll para
// evitar auto-suspensión incluso si el snapshot tiene una condición de carrera.
static std::vector<ModuleRange> BuildModuleRanges()
{
    std::vector<ModuleRange> ranges;

    HANDLE hSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId());

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 me;
        me.dwSize = sizeof(me);

        if (Module32First(hSnap, &me))
        {
            do {
                DWORD_PTR base = (DWORD_PTR)me.modBaseAddr;
                ranges.push_back({ base, base + me.modBaseSize });
            } while (Module32Next(hSnap, &me));
        }

        CloseHandle(hSnap);
    }

    // Helper: añade el rango de un módulo si su base no está ya en la lista.
    // Usa un set temporal de bases construido una sola vez para evitar O(n²).
    std::unordered_set<DWORD_PTR> knownBases;
    knownBases.reserve(ranges.size());
    for (const auto& r : ranges)
        knownBases.insert(r.base);

    auto AddModuleRange = [&](HMODULE hMod)
    {
        if (!hMod) return;
        MODULEINFO mi = {};
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) return;
        DWORD_PTR base = (DWORD_PTR)mi.lpBaseOfDll;
        if (knownBases.count(base)) return; // ya presente
        ranges.push_back({ base, base + mi.SizeOfImage });
        knownBases.insert(base);
    };

    // Siempre añadir nuestro propio proxy DLL (obtenido desde una dirección
    // de función interna para no depender del nombre en disco)
    {
        HMODULE hSelf = nullptr;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)&BuildModuleRanges,
            &hSelf);
        AddModuleRange(hSelf);
    }

    // Siempre añadir la DLL original a la que reenviamos las llamadas
    AddModuleRange(GetModuleHandleA("vorbisFile_orig.dll"));

    return ranges;
}

// Devuelve true si addr cae dentro del rango de algún módulo cargado
static bool IsAddressInKnownModule(DWORD_PTR addr,
                                    const std::vector<ModuleRange>& ranges)
{
    for (const auto& r : ranges)
    {
        if (addr >= r.base && addr < r.end)
            return true;
    }
    return false;
}

// Intenta bloquear la región de memoria donde el anticheat inyecta su módulo PE.
// Primero intenta reservar la región con MEM_RESERVE | PAGE_NOACCESS para que
// cualquier escritura del AC levante una excepción de acceso (capturada por el VEH).
// Si la región ya está comprometida, aplica VirtualProtect PAGE_NOACCESS.
void BlockAnticheatRegion()
{
    LPVOID reserved = VirtualAlloc(
        (LPVOID)GHOST_BASE,
        GHOST_RANGE,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_NOACCESS);

    if (reserved)
    {
        LOG_OK("PAGEBLOCK",
               "Región AC comprometida PAGE_NOACCESS @ 0x%016" PRIXPTR
               " (size: 0x%zX)",
               GHOST_BASE, GHOST_RANGE);
        return;
    }

    // La región ya está en uso — intentar re-proteger con PAGE_NOACCESS
    DWORD oldProt = 0;
    if (VirtualProtect((LPVOID)GHOST_BASE, GHOST_RANGE, PAGE_NOACCESS, &oldProt))
    {
        LOG_OK("PAGEBLOCK",
               "Región AC protegida PAGE_NOACCESS (era 0x%04X) @ 0x%016" PRIXPTR,
               oldProt, GHOST_BASE);
    }
    else
    {
        LOG_WARN("PAGEBLOCK",
                 "No se pudo bloquear la región AC @ 0x%016" PRIXPTR
                 " (VirtualProtect GLE: %lu)",
                 GHOST_BASE, GetLastError());
    }
}

// Escanea todos los hilos del proceso y suspende los sospechosos
static void MonitorAndFreezeThreads()
{
    // Resolución única de NtQueryInformationThread
    static PFN_NtQueryInformationThread pfnNtQIT   = nullptr;
    static bool                         s_resolved = false;

    if (!s_resolved)
    {
        s_resolved = true;
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll)
            pfnNtQIT = (PFN_NtQueryInformationThread)
                GetProcAddress(hNtdll, "NtQueryInformationThread");

        if (pfnNtQIT)
            LOG_OK("THREADGUARD",
                   "NtQueryInformationThread resuelta @ 0x%016" PRIXPTR,
                   (DWORD_PTR)pfnNtQIT);
        else
            LOG_WARN("THREADGUARD",
                     "NtQueryInformationThread no encontrada — ThreadGuard inactivo");
    }

    if (!pfnNtQIT) return;

    DWORD currentPid = GetCurrentProcessId();
    DWORD currentTid = GetCurrentThreadId(); // TID del propio hilo guard

    // Obtener el rango de nuestro propio proxy DLL para el chequeo de auto-suspensión.
    // Este rango siempre estará presente en modRanges también, pero lo resolvemos
    // explícitamente aquí como medida de seguridad adicional.
    DWORD_PTR selfBase = 0, selfEnd = 0;
    {
        HMODULE hSelf = nullptr;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)&MonitorAndFreezeThreads,
            &hSelf);
        if (hSelf)
        {
            MODULEINFO mi = {};
            if (GetModuleInformation(GetCurrentProcess(), hSelf, &mi, sizeof(mi)))
            {
                selfBase = (DWORD_PTR)mi.lpBaseOfDll;
                selfEnd  = selfBase + mi.SizeOfImage;
            }
        }
    }

    // Construir rangos de módulos legítimos para este ciclo
    std::vector<ModuleRange> modRanges = BuildModuleRanges();

    // Snapshot de todos los hilos del sistema
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        LOG_WARN("THREADGUARD",
                 "CreateToolhelp32Snapshot (hilos) fallo (GLE: %lu)", GetLastError());
        return;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (!Thread32First(hSnap, &te))
    {
        CloseHandle(hSnap);
        return;
    }

    do
    {
        // Filtrar: solo hilos de nuestro proceso y no los propios del guard
        if (te.th32OwnerProcessID != currentPid) continue;
        if (te.th32ThreadID == currentTid)        continue;
        if (te.th32ThreadID == g_threadGuardTid)  continue;

        HANDLE hThread = OpenThread(
            THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
            FALSE,
            te.th32ThreadID);

        if (!hThread) continue;

        // Stealth mode: descartar hilos que ya terminaron para no generar
        // errores innecesarios en el log al intentar suspenderlos.
        DWORD exitCode = 0;
        if (GetExitCodeThread(hThread, &exitCode) && exitCode != STILL_ACTIVE)
        {
            CloseHandle(hThread);
            continue;
        }

        // Obtener dirección de inicio Win32 del hilo
        DWORD_PTR startAddr = 0;
        LONG status = pfnNtQIT(
            hThread,
            TH_WIN32_START_ADDR,
            &startAddr,
            sizeof(startAddr),
            nullptr);

        if (status != 0L) // STATUS_SUCCESS == 0
        {
            CloseHandle(hThread);
            continue;
        }

        // Verificar también con VirtualQuery que el tipo de memoria sea privado
        MEMORY_BASIC_INFORMATION mbi = {};
        bool memPrivate = false;
        if (VirtualQuery((LPCVOID)startAddr, &mbi, sizeof(mbi)))
            memPrivate = (mbi.Type == MEM_PRIVATE);

        bool inGhostRange   = (startAddr >= GHOST_BASE &&
                               startAddr <  GHOST_BASE + GHOST_RANGE);
        bool inPrivateMem   = !IsAddressInKnownModule(startAddr, modRanges) && memPrivate;

        // Chequeo de auto-suspensión: nunca suspender un hilo cuya dirección de
        // inicio pertenece a nuestro propio proxy DLL, independientemente del
        // resultado de IsAddressInKnownModule (defensa en profundidad).
        bool isSelfThread = (selfBase && startAddr >= selfBase && startAddr < selfEnd);

        if (!isSelfThread && (inGhostRange || inPrivateMem))
        {
            const char* reason = inGhostRange
                ? "MODULO_FANTASMA_0x63480000"
                : "MEMORIA_PRIVADA_NO_MAPEADA";

            LOG_ALERT("THREADGUARD",
                      "!!! HILO SOSPECHOSO DETECTADO | TID=%lu"
                      " | StartAddr=0x%016" PRIXPTR
                      " | Motivo=%s | MemType=0x%X",
                      te.th32ThreadID,
                      startAddr,
                      reason,
                      mbi.Type);

            DWORD suspendCount = SuspendThread(hThread);
            if (suspendCount != (DWORD)-1)
            {
                LOG_ALERT("THREADGUARD",
                          "    TID=%lu SUSPENDIDO exitosamente"
                          " (SuspendCount previo: %lu)",
                          te.th32ThreadID, suspendCount);
                g_stats.threadsDetected++;
            }
            else
            {
                LOG_WARN("THREADGUARD",
                         "    SuspendThread(TID=%lu) FALLO (GLE: %lu)",
                         te.th32ThreadID, GetLastError());
            }
        }

        CloseHandle(hThread);

    } while (Thread32Next(hSnap, &te));

    CloseHandle(hSnap);
}

static DWORD WINAPI ThreadGuardThread(LPVOID)
{
    g_threadGuardTid = GetCurrentThreadId();
    LOG_INFO("THREADGUARD",
             "Hilo ThreadGuard iniciado (TID: %lu | intervalo: %lums)",
             g_threadGuardTid, THREAD_GUARD_INTERVAL_MS);

    // Espera inicial para que el sistema se estabilice tras la carga del DLL
    Sleep(THREAD_GUARD_STARTUP_DELAY_MS);

    while (g_threadGuardRunning.load())
    {
        MonitorAndFreezeThreads();
        Sleep(THREAD_GUARD_INTERVAL_MS);
    }

    LOG_INFO("THREADGUARD", "Hilo ThreadGuard terminado.");
    return 0;
}

void StartThreadGuard()
{
    g_threadGuardRunning = true;
    g_threadGuardThread  = CreateThread(nullptr, 0, ThreadGuardThread, nullptr, 0, nullptr);
    if (g_threadGuardThread)
        LOG_OK("THREADGUARD", "ThreadGuard iniciado (TID: %lu)",
               GetThreadId(g_threadGuardThread));
    else
        LOG_ALERT("THREADGUARD",
                  "CreateThread ThreadGuard FALLO (GLE: %lu)", GetLastError());
}

void StopThreadGuard()
{
    g_threadGuardRunning = false;
    if (g_threadGuardThread)
    {
        WaitForSingleObject(g_threadGuardThread, THREAD_GUARD_SHUTDOWN_TIMEOUT_MS);
        CloseHandle(g_threadGuardThread);
        g_threadGuardThread = nullptr;
    }
}
