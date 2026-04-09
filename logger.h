#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdarg>
#include <cctype>
#include <mutex>
#include <atomic>
#include <string>
#include <vector>
#include <queue>
#include <thread>
#include <condition_variable>
#include <functional>

// ============================================================================
//  VERSION / BUILD INFO
// ============================================================================
#define PROXY_VERSION       "2.0.0"
#define PROXY_BUILD_DATE    __DATE__ " " __TIME__

// ============================================================================
//  CONSTANTES DE COLOR PARA CONSOLA Win32
// ============================================================================
#define CON_RESET       (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
#define CON_GREEN       (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define CON_RED         (FOREGROUND_RED   | FOREGROUND_INTENSITY)
#define CON_YELLOW      (FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define CON_CYAN        (FOREGROUND_GREEN | FOREGROUND_BLUE  | FOREGROUND_INTENSITY)
#define CON_WHITE       (FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define CON_MAGENTA     (FOREGROUND_RED   | FOREGROUND_BLUE  | FOREGROUND_INTENSITY)
#define CON_DARK_CYAN   (FOREGROUND_GREEN | FOREGROUND_BLUE)
#define CON_DARK_RED    (FOREGROUND_RED)
#define CON_DARK_GREEN  (FOREGROUND_GREEN)

// ============================================================================
//  NIVELES DE LOG
// ============================================================================
enum LogLevel : BYTE
{
    LVL_TRACE   = 0,   // Gris      — trazas de altísima frecuencia
    LVL_INFO    = 1,   // Amarillo  — información general
    LVL_SUCCESS = 2,   // Verde     — operación completada OK
    LVL_WARNING = 3,   // Amarillo intenso — anomalía no crítica
    LVL_ALERT   = 4,   // Rojo      — hook / módulo enemigo / manipulación
    LVL_MEMORY  = 5,   // Cian      — operaciones de memoria / bytes
    LVL_THREAD  = 6,   // Magenta   — creación / destrucción de hilos
    LVL_EXCEPT  = 7,   // Rojo intenso — excepción / crash capturado
    LVL_PATTERN = 8,   // Cian      — resultado de búsqueda de firma (SIG)
    LVL_HEXDUMP = 9,   // Blanco    — volcado hexadecimal
    LVL_AUDIO   = 10,  // Verde oscuro — llamadas de audio
    LVL_SYSCALL = 11,  // Magenta oscuro — syscalls interceptadas
    LVL_MEMSCAN = 12,  // Cian oscuro — scanner de regiones
    LVL_PERF    = 13,  // Blanco    — métricas de rendimiento
};

// ============================================================================
//  ENTRADA DE LOG (para cola asíncrona)
// ============================================================================
struct LogEntry
{
    LogLevel    level;
    char        tag[32];
    char        msg[4096];
    char        timestamp[32];      // HH:MM:SS.mmm
    double      elapsed_ms;         // ms desde inicio del proceso
    DWORD       threadId;
    DWORD       processId;
};

// ============================================================================
//  ESTADÍSTICAS DE SESIÓN
// ============================================================================
struct SessionStats
{
    std::atomic<uint64_t> totalLogs       { 0 };
    std::atomic<uint64_t> alerts          { 0 };
    std::atomic<uint64_t> hooksDetected   { 0 };
    std::atomic<uint64_t> modulesLoaded   { 0 };
    std::atomic<uint64_t> threadsDetected { 0 };
    std::atomic<uint64_t> exceptionsVEH   { 0 };
    std::atomic<uint64_t> ovReadCalls     { 0 };
    std::atomic<uint64_t> ovReadErrors    { 0 };
    std::atomic<uint64_t> ovReadBytes     { 0 };
    std::atomic<uint64_t> rxwRegions      { 0 };
    std::atomic<uint64_t> memScanCycles   { 0 };
};

extern SessionStats g_stats;

// ============================================================================
//  ULTRA LOGGER
// ============================================================================
class UltraLogger
{
public:
    // ---- Ciclo de vida ---------------------------------------------------
    static bool Init(const char* logFilePath);
    static void Shutdown();

    // ---- Log principal ---------------------------------------------------
    static void Write(LogLevel level, const char* tag, const char* fmt, ...);
    static void WriteV(LogLevel level, const char* tag, const char* fmt, va_list args);

    // ---- Herramientas especializadas -------------------------------------
    static void HexDump(const char* label, const void* pData, size_t len);
    static void HexDumpWithASCII(const char* label, const void* pData,
                                 size_t len, DWORD_PTR baseAddr);

    static bool CompareAndLogBytes(const char* moduleName,
                                   const char* funcName,
                                   const BYTE* memBytes,
                                   const BYTE* diskBytes,
                                   size_t      count);

    static void LogPatternResult(const char* sigName,
                                 const BYTE* sig, size_t sigLen,
                                 bool found,
                                 DWORD_PTR address,
                                 DWORD_PTR baseOfModule,
                                 const char* moduleName);

    static void LogThreadCreation(DWORD threadId, DWORD_PTR startAddress,
                                  const char* context);

    static void LogModuleEvent(bool loaded, const char* moduleName,
                               DWORD_PTR baseAddress, DWORD moduleSize);

    static void LogExceptionContext(DWORD exceptionCode,
                                    DWORD_PTR faultAddress,
                                    const CONTEXT* ctx);

    static void LogMemoryRegion(const MEMORY_BASIC_INFORMATION& mbi,
                                bool flagSuspicious);

    static void LogProcessInfo();
    static void LogSystemInfo();
    static void LogSessionStats();

    static void LogOvRead(uint64_t callN, void* vf, int length,
                          int bitstream, int result, double callMs);
    static void LogOvOpen(void* a, void* b, long d, int e, int result);

    // ---- Helpers públicos -----------------------------------------------
    static double ElapsedMs();
    static void   GetTimestamp(char* buf, size_t sz);
    static void   GetTimestampHR(char* buf, size_t sz); // sub-ms

private:
    // ---- Async writer thread --------------------------------------------
    static void  AsyncWriterThread();
    static void  FlushEntry(const LogEntry& e);
    static void  DrainQueue();

    // ---- Console helpers ------------------------------------------------
    static void  SetConsoleColor(WORD color);
    static WORD  LevelColor(LogLevel lvl);
    static const char* LevelTag(LogLevel lvl);

    // ---- Members --------------------------------------------------------
    static HANDLE               s_hConsole;
    static FILE*                s_logFile;
    static std::recursive_mutex s_mutex;       // recursive para VEH dentro de Write
    static bool                 s_ready;
    static char                 s_logPath[MAX_PATH];

    // High-resolution timer
    static LARGE_INTEGER        s_freq;
    static LARGE_INTEGER        s_startTime;

    // Async queue
    static std::queue<LogEntry>        s_queue;
    static std::mutex                  s_queueMutex;
    static std::condition_variable     s_queueCV;
    static std::atomic<bool>           s_writerRunning;
    static HANDLE                      s_writerThread;

    // Flood control per-tag
    static std::atomic<uint64_t>       s_logSeq;
};

// ============================================================================
//  MACROS — sintaxis limpia, zero-cost cuando no está listo
// ============================================================================
#define LOG_TRACE(tag, fmt, ...)    UltraLogger::Write(LVL_TRACE,   tag, fmt, ##__VA_ARGS__)
#define LOG_INFO(tag, fmt, ...)     UltraLogger::Write(LVL_INFO,    tag, fmt, ##__VA_ARGS__)
#define LOG_OK(tag, fmt, ...)       UltraLogger::Write(LVL_SUCCESS, tag, fmt, ##__VA_ARGS__)
#define LOG_WARN(tag, fmt, ...)     UltraLogger::Write(LVL_WARNING, tag, fmt, ##__VA_ARGS__)
#define LOG_ALERT(tag, fmt, ...)    UltraLogger::Write(LVL_ALERT,   tag, fmt, ##__VA_ARGS__)
#define LOG_MEM(tag, fmt, ...)      UltraLogger::Write(LVL_MEMORY,  tag, fmt, ##__VA_ARGS__)
#define LOG_THREAD(tag, fmt, ...)   UltraLogger::Write(LVL_THREAD,  tag, fmt, ##__VA_ARGS__)
#define LOG_EXCEPT(tag, fmt, ...)   UltraLogger::Write(LVL_EXCEPT,  tag, fmt, ##__VA_ARGS__)
#define LOG_AUDIO(tag, fmt, ...)    UltraLogger::Write(LVL_AUDIO,   tag, fmt, ##__VA_ARGS__)
#define LOG_SYSCALL(tag, fmt, ...)  UltraLogger::Write(LVL_SYSCALL, tag, fmt, ##__VA_ARGS__)
#define LOG_MEMSCAN(tag, fmt, ...)  UltraLogger::Write(LVL_MEMSCAN, tag, fmt, ##__VA_ARGS__)
#define LOG_PERF(tag, fmt, ...)     UltraLogger::Write(LVL_PERF,    tag, fmt, ##__VA_ARGS__)
#define LOG_HEXDUMP(label, ptr, sz) UltraLogger::HexDump(label, ptr, sz)
#define LOG_HEXDUMP_ADDR(label, ptr, sz, base) \
    UltraLogger::HexDumpWithASCII(label, ptr, sz, base)

// Macro para medir tiempo de una llamada
#define LOG_TIMED_CALL(tag, expr)                                       \
    do {                                                                \
        LARGE_INTEGER _t0, _t1, _f;                                    \
        QueryPerformanceFrequency(&_f);                                 \
        QueryPerformanceCounter(&_t0);                                  \
        expr;                                                           \
        QueryPerformanceCounter(&_t1);                                  \
        double _ms = (double)(_t1.QuadPart - _t0.QuadPart)            \
                     * 1000.0 / _f.QuadPart;                           \
        LOG_PERF(tag, "TIMED [" #expr "] => %.4f ms", _ms);           \
    } while(0)
