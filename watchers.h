// watchers.h — Declaraciones de watchers
// La implementación pesada va en watchers.cpp
#pragma once
#include "logger.h"

// ---- VEH ----------------------------------------------------------------
void InstallVEH();
void RemoveVEH();

// ---- Module Watcher -----------------------------------------------------
void StartModuleWatcher();
void StopModuleWatcher();

// ---- Memory Scanner -----------------------------------------------------
void StartMemoryScanner();
void StopMemoryScanner();

// ---- IAT Hook -----------------------------------------------------------
bool HookCreateThread();

// ---- Heartbeat (stats periódicas) ---------------------------------------
void StartHeartbeat();
void StopHeartbeat();

// ---- Full IAT dump del módulo principal ---------------------------------
void DumpIAT(HMODULE hModule, const char* label);

// ---- Snapshot de todos los handles del proceso --------------------------
void DumpHandleSnapshot();

// ---- Thread Guard — suspende hilos que arrancan en memoria sospechosa --
void StartThreadGuard();
void StopThreadGuard();

// ---- Page Blocker — reserva/protege la región de inyección del anticheat --
void BlockAnticheatRegion();
