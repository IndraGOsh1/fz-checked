// logger.cpp — UltraLogger v2 implementation
// Async dual-stream: Win32 console con color + archivo persistente
// Sub-milisecond timestamps via QueryPerformanceCounter
// Cola de escritura asíncrona para no bloquear rutas calientes
#include "pch.h"
#include "logger.h"
#include <cstdio>
#include <cstring>
#include <cinttypes>

// ============================================================================
//  GLOBAL STATS
// ============================================================================
SessionStats g_stats;

// ============================================================================
//  STATICS
// ============================================================================
HANDLE               UltraLogger::s_hConsole    = INVALID_HANDLE_VALUE;
FILE*                UltraLogger::s_logFile      = nullptr;
std::recursive_mutex UltraLogger::s_mutex;
bool                 UltraLogger::s_ready        = false;
char                 UltraLogger::s_logPath[MAX_PATH] = {};

LARGE_INTEGER        UltraLogger::s_freq         = {};
LARGE_INTEGER        UltraLogger::s_startTime    = {};

std::queue<LogEntry>     UltraLogger::s_queue;
std::mutex               UltraLogger::s_queueMutex;
std::condition_variable  UltraLogger::s_queueCV;
std::atomic<bool>        UltraLogger::s_writerRunning{ false };
HANDLE                   UltraLogger::s_writerThread  = nullptr;
std::atomic<uint64_t>    UltraLogger::s_logSeq        { 0 };

// ============================================================================
//  INIT
// ============================================================================
bool UltraLogger::Init(const char* logFilePath)
{
    std::lock_guard<std::recursive_mutex> lk(s_mutex);

    QueryPerformanceFrequency(&s_freq);
    QueryPerformanceCounter(&s_startTime);

    strncpy_s(s_logPath, logFilePath, _TRUNCATE);

    // ---- Consola Win32 --------------------------------------------------
    if (AllocConsole())
    {
        SetConsoleTitleA("[VorbisProxy v2] Ultra-Verbose Debug Console");
        s_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(s_hConsole, &csbi))
        {
            COORD size = csbi.dwSize;
            size.Y = 9999;
            size.X = 220;
            SetConsoleScreenBufferSize(s_hConsole, size);
        }

        // Activar ANSI/VT si está disponible (Win10+)
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(s_hConsole, &mode);
        SetConsoleMode(s_hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    else
    {
        s_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    }

    // ---- Archivo de log -------------------------------------------------
    if (fopen_s(&s_logFile, logFilePath, "w") != 0 || !s_logFile)
        return false;

    // Header CSV-friendly con separador para filtrado en Excel/grep
    const char* banner =
        "================================================================================\n"
        "  VorbisFile Proxy DLL v" PROXY_VERSION " — Ultra-Verbose Session Log\n"
        "  Build  : " PROXY_BUILD_DATE "\n"
        "  Format : [ELAPSED_MS] [TIMESTAMP] [TID] [TAG          ] [LEVEL  ] message\n"
        "================================================================================\n";

    fputs(banner, s_logFile);
    fflush(s_logFile);

    SetConsoleColor(CON_CYAN);
    DWORD w;
    if (s_hConsole != INVALID_HANDLE_VALUE)
        WriteConsoleA(s_hConsole, banner, (DWORD)strlen(banner), &w, nullptr);
    SetConsoleColor(CON_RESET);

    // ---- Arrancar hilo escritor asíncrono --------------------------------
    s_writerRunning = true;
    s_writerThread = CreateThread(nullptr, 0,
        [](LPVOID) -> DWORD {
            UltraLogger::AsyncWriterThread();
            return 0;
        }, nullptr, 0, nullptr);

    s_ready = true;
    return true;
}

// ============================================================================
//  SHUTDOWN
// ============================================================================
void UltraLogger::Shutdown()
{
    // Drenar cola pendiente
    s_writerRunning = false;
    s_queueCV.notify_all();

    if (s_writerThread)
    {
        WaitForSingleObject(s_writerThread, 3000);
        CloseHandle(s_writerThread);
        s_writerThread = nullptr;
    }

    LogSessionStats();

    std::lock_guard<std::recursive_mutex> lk(s_mutex);
    if (s_logFile)
    {
        fputs("\n[SESSION END]\n", s_logFile);
        fclose(s_logFile);
        s_logFile = nullptr;
    }
    s_ready = false;
}

// ============================================================================
//  WRITE — encola la entrada para escritura asíncrona
// ============================================================================
void UltraLogger::Write(LogLevel level, const char* tag, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    WriteV(level, tag, fmt, args);
    va_end(args);
}

void UltraLogger::WriteV(LogLevel level, const char* tag, const char* fmt, va_list args)
{
    if (!s_ready) return;

    LogEntry e;
    e.level     = level;
    e.threadId  = GetCurrentThreadId();
    e.processId = GetCurrentProcessId();
    e.elapsed_ms = ElapsedMs();

    strncpy_s(e.tag, tag ? tag : "???", _TRUNCATE);
    vsnprintf(e.msg, sizeof(e.msg), fmt, args);
    GetTimestampHR(e.timestamp, sizeof(e.timestamp));

    g_stats.totalLogs++;
    if (level == LVL_ALERT || level == LVL_EXCEPT) g_stats.alerts++;

    {
        std::lock_guard<std::mutex> lk(s_queueMutex);
        // Si la cola crece demasiado, dropeamos TRACE para proteger memoria
        if (s_queue.size() < 16384 || level >= LVL_WARNING)
            s_queue.push(e);
    }
    s_queueCV.notify_one();
}

// ============================================================================
//  ASYNC WRITER THREAD
// ============================================================================
void UltraLogger::AsyncWriterThread()
{
    while (true)
    {
        LogEntry e;
        bool got = false;

        {
            std::unique_lock<std::mutex> lk(s_queueMutex);
            s_queueCV.wait_for(lk, std::chrono::milliseconds(50),
                [&]{ return !s_queue.empty() || !s_writerRunning.load(); });

            if (!s_queue.empty())
            {
                e = s_queue.front();
                s_queue.pop();
                got = true;
            }
        }

        if (got) FlushEntry(e);
        else if (!s_writerRunning.load()) { DrainQueue(); break; }
    }
}

void UltraLogger::DrainQueue()
{
    std::lock_guard<std::mutex> lk(s_queueMutex);
    while (!s_queue.empty())
    {
        FlushEntry(s_queue.front());
        s_queue.pop();
    }
}

void UltraLogger::FlushEntry(const LogEntry& e)
{
    // Formato: [elapsed_ms] [HH:MM:SS.mmm] [TID:xxxxx] [TAG          ] [LEVEL  ] msg
    char line[4352];
    snprintf(line, sizeof(line),
             "[%13.3f] [%s] [TID:%05lu] [%-14s] [%-7s] %s\n",
             e.elapsed_ms,
             e.timestamp,
             (unsigned long)e.threadId,
             e.tag,
             LevelTag(e.level),
             e.msg);

    // ---- Archivo --------------------------------------------------------
    std::lock_guard<std::recursive_mutex> lk(s_mutex);
    if (s_logFile)
    {
        fputs(line, s_logFile);
        // Flush parcial cada 64 entradas para rendimiento
        static std::atomic<int> flushCounter{ 0 };
        if (++flushCounter % 64 == 0 || e.level >= LVL_ALERT)
            fflush(s_logFile);
    }

    // ---- Consola --------------------------------------------------------
    if (s_hConsole != INVALID_HANDLE_VALUE)
    {
        SetConsoleColor(LevelColor(e.level));
        DWORD written;
        WriteConsoleA(s_hConsole, line, (DWORD)strlen(line), &written, nullptr);
        SetConsoleColor(CON_RESET);
    }
}

// ============================================================================
//  HEX DUMP BÁSICO
// ============================================================================
void UltraLogger::HexDump(const char* label, const void* pData, size_t len)
{
    HexDumpWithASCII(label, pData, len, 0);
}

// ============================================================================
//  HEX DUMP CON DIRECCIÓN BASE Y ASCII
// ============================================================================
void UltraLogger::HexDumpWithASCII(const char* label, const void* pData,
                                    size_t len, DWORD_PTR baseAddr)
{
    if (!s_ready || !pData || len == 0) return;

    Write(LVL_HEXDUMP, "HEXDUMP",
          ">>> %s | Base: 0x%016" PRIXPTR " | %zu bytes <<<", label, baseAddr, len);

    const BYTE* p = static_cast<const BYTE*>(pData);

    for (size_t i = 0; i < len; i += 16)
    {
        size_t rowLen = (len - i < 16) ? (len - i) : 16;
        char hexPart[64] = {};
        char ascPart[17] = {};

        for (size_t j = 0; j < 16; j++)
        {
            if (j < rowLen)
            {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02X ", p[i + j]);
                strcat_s(hexPart, tmp);
                ascPart[j] = (p[i+j] >= 0x20 && p[i+j] < 0x7F) ? (char)p[i+j] : '.';
            }
            else
            {
                strcat_s(hexPart, "   ");
                ascPart[j] = ' ';
            }
            // Separador visual en el medio
            if (j == 7) strcat_s(hexPart, " ");
        }
        ascPart[16] = '\0';

        char row[256];
        snprintf(row, sizeof(row),
                 "  %016" PRIXPTR "  %-49s |%s|",
                 baseAddr + i, hexPart, ascPart);

        Write(LVL_HEXDUMP, "HEXDUMP", "%s", row);
    }

    Write(LVL_HEXDUMP, "HEXDUMP", "<<< END %s >>>", label);
}

// ============================================================================
//  COMPARE BYTES — memoria vs disco
// ============================================================================
bool UltraLogger::CompareAndLogBytes(const char* moduleName,
                                     const char* funcName,
                                     const BYTE* memBytes,
                                     const BYTE* diskBytes,
                                     size_t      count)
{
    bool match = (memcmp(memBytes, diskBytes, count) == 0);

    if (match)
    {
        Write(LVL_SUCCESS, "INTEGRITY",
              "[CLEAN ] %s!%s — %zu bytes coinciden con disco",
              moduleName, funcName, count);
        return true;
    }

    g_stats.hooksDetected++;

    Write(LVL_ALERT, "INTEGRITY",
          "[HOOK!] %s!%s — BYTES MODIFICADOS (%zu bytes comparados)",
          moduleName, funcName, count);

    // Mostrar las diferencias byte a byte
    char memStr[256]  = "  MEM : ";
    char diskStr[256] = "  DISK: ";
    char diffStr[256] = "  DIFF: ";

    for (size_t i = 0; i < count && i < 16; i++)
    {
        char tmp[8];
        snprintf(tmp, sizeof(tmp), "%02X ", memBytes[i]);   strcat_s(memStr,  tmp);
        snprintf(tmp, sizeof(tmp), "%02X ", diskBytes[i]);  strcat_s(diskStr, tmp);
        snprintf(tmp, sizeof(tmp), "%s ",   memBytes[i] != diskBytes[i] ? "^^" : "  ");
        strcat_s(diffStr, tmp);
    }

    Write(LVL_ALERT, "INTEGRITY", "%s", memStr);
    Write(LVL_ALERT, "INTEGRITY", "%s", diskStr);
    Write(LVL_ALERT, "INTEGRITY", "%s", diffStr);

    // Detectar tipo de hook por patrón
    if (memBytes[0] == 0xE9)
        Write(LVL_ALERT, "INTEGRITY",
              "  >>> JMP relativo detectado (trampolín clásico) — destino: 0x%08X",
              *(DWORD*)(memBytes + 1));
    else if (memBytes[0] == 0xFF && memBytes[1] == 0x25)
        Write(LVL_ALERT, "INTEGRITY",
              "  >>> JMP [mem] (FF 25) — hook indirecto de 64 bits");
    else if (memBytes[0] == 0x48 && memBytes[1] == 0xB8)
        Write(LVL_ALERT, "INTEGRITY",
              "  >>> MOV RAX, imm64 — posible hook de 64 bits con JMP RAX");

    char dumpLabel[256];
    snprintf(dumpLabel, sizeof(dumpLabel), "HOOKED %s!%s (memoria)", moduleName, funcName);
    HexDumpWithASCII(dumpLabel, memBytes, count, 0);

    return false;
}

// ============================================================================
//  PATTERN RESULT
// ============================================================================
void UltraLogger::LogPatternResult(const char* sigName,
                                   const BYTE* sig, size_t sigLen,
                                   bool found,
                                   DWORD_PTR address,
                                   DWORD_PTR baseOfModule,
                                   const char* moduleName)
{
    char sigStr[128] = {};
    for (size_t i = 0; i < sigLen && i < 20; i++)
    {
        char tmp[6];
        snprintf(tmp, sizeof(tmp), "%02X ", sig[i]);
        strcat_s(sigStr, tmp);
    }
    if (sigLen > 20) strcat_s(sigStr, "...");

    if (!found)
    {
        Write(LVL_PATTERN, "PATTERN",
              "[NOT FOUND] SIG %-24s | { %s} | Module: %s",
              sigName, sigStr, moduleName);
        return;
    }

    DWORD_PTR offset = address - baseOfModule;
    Write(LVL_PATTERN, "PATTERN",
          "[FOUND    ] SIG %-24s | { %s} | "
          "@ 0x%016" PRIXPTR " | Base: 0x%016" PRIXPTR
          " | +0x%08" PRIXPTR " | %s",
          sigName, sigStr, address, baseOfModule, offset, moduleName);
}

// ============================================================================
//  THREAD CREATION
// ============================================================================
void UltraLogger::LogThreadCreation(DWORD threadId, DWORD_PTR startAddress,
                                    const char* context)
{
    g_stats.threadsDetected++;

    char moduleName[MAX_PATH] = "<desconocido>";
    char moduleBase[64]       = "N/A";
    HMODULE hMod = nullptr;

    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)startAddress, &hMod) && hMod)
    {
        GetModuleFileNameA(hMod, moduleName, MAX_PATH);
        const char* slash = strrchr(moduleName, '\\');
        if (slash) memmove(moduleName, slash + 1, strlen(slash));
        snprintf(moduleBase, sizeof(moduleBase), "0x%016" PRIXPTR, (DWORD_PTR)hMod);
    }

    Write(LVL_THREAD, "THREAD",
          "[NEW ] TID: %05lu | StartAddr: 0x%016" PRIXPTR
          " | Base: %s | Module: %-30s | Ctx: %s",
          (unsigned long)threadId, startAddress,
          moduleBase, moduleName,
          context ? context : "N/A");
}

// ============================================================================
//  MODULE EVENT
// ============================================================================
void UltraLogger::LogModuleEvent(bool loaded,
                                 const char* moduleName,
                                 DWORD_PTR   baseAddress,
                                 DWORD       moduleSize)
{
    g_stats.modulesLoaded++;

    static const char* suspects[] = {
        "cn3", "ac-v2", "nprotect", "hackshield", "xigncode",
        "themida", "safedisc", "vac", "easyanticheat", "battleye",
        "anticheats", "anti_cheat", "inject", "cheat", "trainer",
    };

    char lower[MAX_PATH];
    strncpy_s(lower, moduleName, _TRUNCATE);
    for (char& c : lower) c = (char)tolower((unsigned char)c);

    bool isSuspect = false;
    const char* matchedSus = "";
    for (const char* s : suspects)
        if (strstr(lower, s)) { isSuspect = true; matchedSus = s; break; }

    LogLevel lvl = loaded
        ? (isSuspect ? LVL_ALERT : LVL_INFO)
        : LVL_WARNING;

    const char* action = loaded ? "LOAD  " : "UNLOAD";

    Write(lvl, "MODULE",
          "[%s] %-45s | Base: 0x%016" PRIXPTR " | Size: %6u KB%s%s",
          action, moduleName, baseAddress, moduleSize / 1024,
          isSuspect ? " | <<< SOSPECHOSO: " : "",
          isSuspect ? matchedSus : "");

    // Si es un módulo nuevo cargado, hacer verificación básica de su header
    if (loaded && baseAddress)
    {
        __try
        {
            auto* dos = (IMAGE_DOS_HEADER*)baseAddress;
            auto* nt  = (IMAGE_NT_HEADERS*)(baseAddress + dos->e_lfanew);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && nt->Signature == IMAGE_NT_SIGNATURE)
            {
                Write(LVL_INFO, "MODULE",
                      "         PE: Machine=%04X | Subsystem=%u | Characteristics=%04X | "
                      "EntryPoint=0x%08X | SizeOfImage=%u KB",
                      nt->FileHeader.Machine,
                      nt->OptionalHeader.Subsystem,
                      nt->FileHeader.Characteristics,
                      nt->OptionalHeader.AddressOfEntryPoint,
                      nt->OptionalHeader.SizeOfImage / 1024);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

// ============================================================================
//  MEMORY REGION
// ============================================================================
void UltraLogger::LogMemoryRegion(const MEMORY_BASIC_INFORMATION& mbi,
                                  bool flagSuspicious)
{
    const char* stateStr = "?";
    switch (mbi.State)
    {
    case MEM_COMMIT:  stateStr = "COMMIT "; break;
    case MEM_FREE:    stateStr = "FREE   "; break;
    case MEM_RESERVE: stateStr = "RESERVE"; break;
    }

    const char* typeStr = "?";
    switch (mbi.Type)
    {
    case MEM_IMAGE:   typeStr = "IMAGE  "; break;
    case MEM_MAPPED:  typeStr = "MAPPED "; break;
    case MEM_PRIVATE: typeStr = "PRIVATE"; break;
    }

    char protStr[32] = {};
    DWORD p = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    switch (p)
    {
    case PAGE_NOACCESS:          strcat_s(protStr, "---"); break;
    case PAGE_READONLY:          strcat_s(protStr, "R--"); break;
    case PAGE_READWRITE:         strcat_s(protStr, "RW-"); break;
    case PAGE_WRITECOPY:         strcat_s(protStr, "RWC"); break;
    case PAGE_EXECUTE:           strcat_s(protStr, "--X"); break;
    case PAGE_EXECUTE_READ:      strcat_s(protStr, "R-X"); break;
    case PAGE_EXECUTE_READWRITE: strcat_s(protStr, "RWX"); break;
    case PAGE_EXECUTE_WRITECOPY: strcat_s(protStr, "RWX(WC)"); break;
    default:                     snprintf(protStr, sizeof(protStr), "0x%04X", p); break;
    }
    if (mbi.Protect & PAGE_GUARD)   strcat_s(protStr, "|GUARD");

    LogLevel lvl = flagSuspicious ? LVL_ALERT : LVL_MEMSCAN;

    Write(lvl, "MEMSCAN",
          "%s Base: 0x%016" PRIXPTR " | Size: %7zu KB | State: %s | Type: %s | Prot: %-10s%s",
          flagSuspicious ? ">>>" : "   ",
          (DWORD_PTR)mbi.BaseAddress,
          mbi.RegionSize / 1024,
          stateStr, typeStr, protStr,
          flagSuspicious ? " <<< RWX PRIVADA — POSIBLE SHELLCODE" : "");
}

// ============================================================================
//  EXCEPTION CONTEXT
// ============================================================================
void UltraLogger::LogExceptionContext(DWORD exceptionCode,
                                      DWORD_PTR faultAddress,
                                      const CONTEXT* ctx)
{
    g_stats.exceptionsVEH++;

    // Nombre descriptivo del código de excepción
    const char* codeName = "UNKNOWN";
    switch (exceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION:         codeName = "ACCESS_VIOLATION";         break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    codeName = "ARRAY_BOUNDS_EXCEEDED";    break;
    case EXCEPTION_BREAKPOINT:               codeName = "BREAKPOINT";               break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:    codeName = "DATATYPE_MISALIGNMENT";    break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       codeName = "FLT_DIVIDE_BY_ZERO";       break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:      codeName = "ILLEGAL_INSTRUCTION";      break;
    case EXCEPTION_IN_PAGE_ERROR:            codeName = "IN_PAGE_ERROR";            break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       codeName = "INT_DIVIDE_BY_ZERO";       break;
    case EXCEPTION_PRIV_INSTRUCTION:         codeName = "PRIV_INSTRUCTION";         break;
    case EXCEPTION_SINGLE_STEP:              codeName = "SINGLE_STEP";              break;
    case EXCEPTION_STACK_OVERFLOW:           codeName = "STACK_OVERFLOW";           break;
    case EXCEPTION_GUARD_PAGE:               codeName = "GUARD_PAGE";               break;
    case STATUS_HEAP_CORRUPTION:             codeName = "HEAP_CORRUPTION";          break;
    }

    Write(LVL_EXCEPT, "VEH", "══════════════════ EXCEPCIÓN VEH ══════════════════");
    Write(LVL_EXCEPT, "VEH",
          "Código : 0x%08X (%s)", exceptionCode, codeName);
    Write(LVL_EXCEPT, "VEH",
          "Fallo  : 0x%016" PRIXPTR, faultAddress);

    if (!ctx) { Write(LVL_EXCEPT, "VEH", "No hay CONTEXT disponible."); return; }

#ifdef _WIN64
    Write(LVL_EXCEPT, "VEH", "── Registros (x64) ──────────────────────────────");
    Write(LVL_EXCEPT, "VEH",
          "RAX=%016llX  RBX=%016llX  RCX=%016llX",
          ctx->Rax, ctx->Rbx, ctx->Rcx);
    Write(LVL_EXCEPT, "VEH",
          "RDX=%016llX  RSI=%016llX  RDI=%016llX",
          ctx->Rdx, ctx->Rsi, ctx->Rdi);
    Write(LVL_EXCEPT, "VEH",
          "RSP=%016llX  RBP=%016llX  RIP=%016llX",
          ctx->Rsp, ctx->Rbp, ctx->Rip);
    Write(LVL_EXCEPT, "VEH",
          " R8=%016llX   R9=%016llX  R10=%016llX",
          ctx->R8, ctx->R9, ctx->R10);
    Write(LVL_EXCEPT, "VEH",
          "R11=%016llX  R12=%016llX  R13=%016llX",
          ctx->R11, ctx->R12, ctx->R13);
    Write(LVL_EXCEPT, "VEH",
          "R14=%016llX  R15=%016llX  EFL=%08X",
          ctx->R14, ctx->R15, ctx->EFlags);

    // Stack backtrace con CaptureStackBackTrace
    void* frames[24];
    USHORT count = CaptureStackBackTrace(0, 24, frames, nullptr);
    Write(LVL_EXCEPT, "VEH", "── Stack Backtrace (%u frames) ──────────────────", count);
    for (USHORT i = 0; i < count; i++)
    {
        char frameMod[MAX_PATH] = "<?>"; 
        HMODULE hMod = nullptr;
        if (GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                (LPCSTR)frames[i], &hMod) && hMod)
        {
            GetModuleFileNameA(hMod, frameMod, MAX_PATH);
            const char* sl = strrchr(frameMod, '\\');
            if (sl) memmove(frameMod, sl + 1, strlen(sl));
        }
        Write(LVL_EXCEPT, "VEH",
              "  [%02u] 0x%016" PRIXPTR "  (%s)", i, (DWORD_PTR)frames[i], frameMod);
    }

    if (ctx->Rsp)
        HexDumpWithASCII("Stack en RSP (128 bytes)", (void*)ctx->Rsp, 128, ctx->Rsp);
#else
    Write(LVL_EXCEPT, "VEH", "── Registros (x86) ──────────────────────────────");
    Write(LVL_EXCEPT, "VEH",
          "EAX=%08X  EBX=%08X  ECX=%08X  EDX=%08X",
          ctx->Eax, ctx->Ebx, ctx->Ecx, ctx->Edx);
    Write(LVL_EXCEPT, "VEH",
          "ESI=%08X  EDI=%08X  ESP=%08X  EBP=%08X",
          ctx->Esi, ctx->Edi, ctx->Esp, ctx->Ebp);
    Write(LVL_EXCEPT, "VEH",
          "EIP=%08X  EFL=%08X",
          ctx->Eip, ctx->EFlags);

    void* frames[16];
    USHORT count = CaptureStackBackTrace(0, 16, frames, nullptr);
    Write(LVL_EXCEPT, "VEH", "── Stack Backtrace (%u frames) ──", count);
    for (USHORT i = 0; i < count; i++)
        Write(LVL_EXCEPT, "VEH",
              "  [%02u] 0x%08" PRIXPTR, i, (DWORD_PTR)frames[i]);

    if (ctx->Esp)
        HexDumpWithASCII("Stack en EIP (64 bytes)", (void*)ctx->Esp, 64, ctx->Esp);
#endif

    Write(LVL_EXCEPT, "VEH", "════════════════════════════════════════════════");
}

// ============================================================================
//  PROCESS INFO
// ============================================================================
void UltraLogger::LogProcessInfo()
{
    Write(LVL_INFO, "PROCINFO", "══════════════ INFORMACIÓN DEL PROCESO ══════════════");

    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    Write(LVL_INFO, "PROCINFO", "EXE      : %s", exePath);
    Write(LVL_INFO, "PROCINFO", "PID      : %lu", GetCurrentProcessId());
    Write(LVL_INFO, "PROCINFO", "TID main : %lu", GetCurrentThreadId());

    // Información de memoria del proceso
    PROCESS_MEMORY_COUNTERS_EX pmc = {};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc)))
    {
        Write(LVL_INFO, "PROCINFO",
              "WorkingSet: %zu MB | PeakWS: %zu MB | PrivateBytes: %zu MB",
              pmc.WorkingSetSize / (1024*1024),
              pmc.PeakWorkingSetSize / (1024*1024),
              pmc.PrivateUsage / (1024*1024));
    }

    // DEP/NX status
    DWORD depFlags = 0; BOOL depPermanent = FALSE;
    if (GetProcessDEPPolicy(GetCurrentProcess(), &depFlags, &depPermanent))
        Write(LVL_INFO, "PROCINFO",
              "DEP      : flags=0x%X | permanent=%s",
              depFlags, depPermanent ? "YES" : "NO");

    Write(LVL_INFO, "PROCINFO", "═════════════════════════════════════════════════════");
}

// ============================================================================
//  SYSTEM INFO
// ============================================================================
void UltraLogger::LogSystemInfo()
{
    Write(LVL_INFO, "SYSINFO", "══════════════ INFORMACIÓN DEL SISTEMA ══════════════");

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    Write(LVL_INFO, "SYSINFO",
          "CPU: arch=%u | cores=%u | pageSize=%u | minApp=0x%016" PRIXPTR
          " | maxApp=0x%016" PRIXPTR,
          si.wProcessorArchitecture,
          si.dwNumberOfProcessors,
          si.dwPageSize,
          (DWORD_PTR)si.lpMinimumApplicationAddress,
          (DWORD_PTR)si.lpMaximumApplicationAddress);

    MEMORYSTATUSEX ms = {};
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    Write(LVL_INFO, "SYSINFO",
          "RAM: carga=%lu%% | total=%llu MB | disponible=%llu MB",
          ms.dwMemoryLoad,
          ms.ullTotalPhys / (1024*1024),
          ms.ullAvailPhys / (1024*1024));

    OSVERSIONINFOEXW ovi = {};
    ovi.dwOSVersionInfoSize = sizeof(ovi);
#pragma warning(suppress: 4996)
    GetVersionExW((OSVERSIONINFOW*)&ovi);
    Write(LVL_INFO, "SYSINFO",
          "OS: %lu.%lu.%lu | SP: %lu.%lu",
          ovi.dwMajorVersion, ovi.dwMinorVersion, ovi.dwBuildNumber,
          ovi.wServicePackMajor, ovi.wServicePackMinor);

    Write(LVL_INFO, "SYSINFO", "═════════════════════════════════════════════════════");
}

// ============================================================================
//  SESSION STATS
// ============================================================================
void UltraLogger::LogSessionStats()
{
    Write(LVL_INFO, "STATS", "══════════════ ESTADÍSTICAS DE SESIÓN ══════════════");
    Write(LVL_INFO, "STATS", "Total logs     : %" PRIu64, g_stats.totalLogs.load());
    Write(LVL_INFO, "STATS", "Alertas        : %" PRIu64, g_stats.alerts.load());
    Write(LVL_INFO, "STATS", "Hooks detect.  : %" PRIu64, g_stats.hooksDetected.load());
    Write(LVL_INFO, "STATS", "Módulos        : %" PRIu64, g_stats.modulesLoaded.load());
    Write(LVL_INFO, "STATS", "Hilos detect.  : %" PRIu64, g_stats.threadsDetected.load());
    Write(LVL_INFO, "STATS", "Excepciones VEH: %" PRIu64, g_stats.exceptionsVEH.load());
    Write(LVL_INFO, "STATS", "ov_read calls  : %" PRIu64, g_stats.ovReadCalls.load());
    Write(LVL_INFO, "STATS", "ov_read errors : %" PRIu64, g_stats.ovReadErrors.load());
    Write(LVL_INFO, "STATS", "ov_read bytes  : %" PRIu64, g_stats.ovReadBytes.load());
    Write(LVL_INFO, "STATS", "Regiones RWX   : %" PRIu64, g_stats.rxwRegions.load());
    Write(LVL_INFO, "STATS", "MemScan ciclos : %" PRIu64, g_stats.memScanCycles.load());
    Write(LVL_INFO, "STATS", "Elapsed total  : %.3f ms", ElapsedMs());
    Write(LVL_INFO, "STATS", "═════════════════════════════════════════════════════");
}

// ============================================================================
//  OV_READ LOG ESPECIALIZADO
// ============================================================================
void UltraLogger::LogOvRead(uint64_t callN, void* vf, int length,
                             int bitstream, int result, double callMs)
{
    if (result < 0)
    {
        g_stats.ovReadErrors++;
        Write(LVL_ALERT, "OV_READ",
              "[#%08" PRIu64 "] ERROR=%d | vf=0x%016" PRIXPTR
              " | len=%d | bs=%d | t=%.4f ms",
              callN, result, (DWORD_PTR)vf, length, bitstream, callMs);
    }
    else
    {
        g_stats.ovReadBytes += (uint64_t)result;

        // Log normal cada 500 llamadas exitosas; siempre si hay latencia alta
        bool highLatency = (callMs > 5.0);
        if (callN % 500 == 0 || highLatency)
        {
            Write(highLatency ? LVL_WARNING : LVL_AUDIO, "OV_READ",
                  "[#%08" PRIu64 "] OK=%d bytes | vf=0x%016" PRIXPTR
                  " | req=%d | bs=%d | t=%.4f ms%s",
                  callN, result, (DWORD_PTR)vf, length, bitstream, callMs,
                  highLatency ? "  <<< LATENCIA ALTA" : "");
        }
    }
}

// ============================================================================
//  OV_OPEN_CALLBACKS LOG
// ============================================================================
void UltraLogger::LogOvOpen(void* a, void* b, long d, int e, int result)
{
    if (result == 0)
        Write(LVL_SUCCESS, "OV_OPEN",
              "OK | vf=0x%016" PRIXPTR " | datasrc=0x%016" PRIXPTR
              " | initial=%ld | callbacks_type=%d",
              (DWORD_PTR)b, (DWORD_PTR)a, d, e);
    else
        Write(LVL_ALERT, "OV_OPEN",
              "ERROR=%d | a=0x%016" PRIXPTR " | b=0x%016" PRIXPTR
              " | initial=%ld | callbacks_type=%d",
              result, (DWORD_PTR)a, (DWORD_PTR)b, d, e);
}

// ============================================================================
//  HELPERS
// ============================================================================
double UltraLogger::ElapsedMs()
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (double)(now.QuadPart - s_startTime.QuadPart)
           * 1000.0 / s_freq.QuadPart;
}

void UltraLogger::GetTimestamp(char* buf, size_t sz)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buf, sz, "%02d:%02d:%02d.%03d",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void UltraLogger::GetTimestampHR(char* buf, size_t sz)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    // Microsegundos estimados via QPC
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    LONGLONG us = ((now.QuadPart - s_startTime.QuadPart) * 1000000LL) / s_freq.QuadPart;
    LONGLONG us_part = us % 1000;
    snprintf(buf, sz, "%02d:%02d:%02d.%03d.%03lld",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, us_part);
}

const char* UltraLogger::LevelTag(LogLevel lvl)
{
    switch (lvl)
    {
    case LVL_TRACE:   return "TRACE";
    case LVL_INFO:    return "INFO";
    case LVL_SUCCESS: return "OK";
    case LVL_WARNING: return "WARNING";
    case LVL_ALERT:   return "ALERT";
    case LVL_MEMORY:  return "MEMORY";
    case LVL_THREAD:  return "THREAD";
    case LVL_EXCEPT:  return "EXCEPT";
    case LVL_PATTERN: return "PATTERN";
    case LVL_HEXDUMP: return "HEXDUMP";
    case LVL_AUDIO:   return "AUDIO";
    case LVL_SYSCALL: return "SYSCALL";
    case LVL_MEMSCAN: return "MEMSCAN";
    case LVL_PERF:    return "PERF";
    default:          return "???";
    }
}

WORD UltraLogger::LevelColor(LogLevel lvl)
{
    switch (lvl)
    {
    case LVL_TRACE:   return CON_DARK_GREEN;
    case LVL_SUCCESS: return CON_GREEN;
    case LVL_ALERT:   return CON_RED;
    case LVL_EXCEPT:  return CON_RED;
    case LVL_MEMORY:  return CON_CYAN;
    case LVL_PATTERN: return CON_CYAN;
    case LVL_THREAD:  return CON_MAGENTA;
    case LVL_HEXDUMP: return CON_WHITE;
    case LVL_WARNING: return CON_YELLOW;
    case LVL_AUDIO:   return CON_DARK_GREEN;
    case LVL_SYSCALL: return CON_MAGENTA;
    case LVL_MEMSCAN: return CON_DARK_CYAN;
    case LVL_PERF:    return CON_WHITE;
    default:          return CON_YELLOW;
    }
}

void UltraLogger::SetConsoleColor(WORD color)
{
    if (s_hConsole != INVALID_HANDLE_VALUE)
        SetConsoleTextAttribute(s_hConsole, color);
}
