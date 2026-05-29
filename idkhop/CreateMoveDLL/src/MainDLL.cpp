#include <Windows.h>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>

#include "../rcs/MinHook/MinHook.h"
#include "../rcs/SDK.h"

static const char* SIG_CREATE_MOVE = "48 8B C4 4C 89 40 ?? 48 89 48 ?? 55 53 41 54";

constexpr uint32_t FJ_PRESS   = 65537; // 0x10001
constexpr uint32_t FJ_RELEASE = 256;   // 0x100
constexpr uint64_t CMD_IN_JUMP = 1ull << 1;

FILE*   g_console = nullptr;
FILE*   g_logFile = nullptr; // duplicate of console output, survives fullscreen hiding it
HMODULE g_hMod    = nullptr;

void Log(const char* fmt, ...) {
	va_list a;
	if (g_console) {
		va_start(a, fmt);
		vfprintf(g_console, fmt, a);
		va_end(a);
		fflush(g_console);
	}
	if (g_logFile) {
		va_start(a, fmt);
		vfprintf(g_logFile, fmt, a);
		va_end(a);
		fflush(g_logFile);
	}
}

// opens bhop.log next to the dll. called once during init. lets us see logs
// even when cs2 fullscreen has the console window buried.
static void OpenLogFile() {
	char        path[MAX_PATH] = {};
	const char* logName        = "bhop.log";
	if (g_hMod && GetModuleFileNameA(g_hMod, path, MAX_PATH)) {
		if (char* slash = strrchr(path, '\\'); slash && (slash + 1 - path) + strlen(logName) < MAX_PATH)
			strcpy_s(slash + 1, MAX_PATH - (slash + 1 - path), logName);
		else
			strcpy_s(path, MAX_PATH, logName);
	} else {
		strcpy_s(path, MAX_PATH, logName);
	}
	fopen_s(&g_logFile, path, "w");
}

// dumps the last error to a file next to the dll. overwrites every call,
// only keep the most recent one. still there after the console closes.
static void LogError(const char* fmt, ...) {
	va_list a;
	va_start(a, fmt);
	if (g_console) {
		vfprintf(g_console, fmt, a);
		fflush(g_console);
	}
	va_end(a);

	char        path[MAX_PATH] = {};
	const char* logName        = "bhop_error.log";
	if (g_hMod && GetModuleFileNameA(g_hMod, path, MAX_PATH)) {
		if (char* slash = strrchr(path, '\\'); slash && (slash + 1 - path) + strlen(logName) < MAX_PATH)
			strcpy_s(slash + 1, MAX_PATH - (slash + 1 - path), logName);
		else
			strcpy_s(path, MAX_PATH, logName);
	} else {
		strcpy_s(path, MAX_PATH, logName);
	}

	FILE* f = nullptr;
	fopen_s(&f, path, "w");
	if (!f)
		return;
	va_start(a, fmt);
	vfprintf(f, fmt, a);
	va_end(a);
	fclose(f);
}

static uintptr_t PatternScan(const uintptr_t base, const size_t size, const char* sig) {
	constexpr size_t MAX_TOKENS = 256;
	uint8_t          bytes[MAX_TOKENS];
	bool             wild[MAX_TOKENS];
	size_t           n = 0;

	auto isHex = [](const char c) -> bool {
		return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
	};
	auto hex = [](const char c) -> uint8_t {
		if (c >= '0' && c <= '9')
			return c - '0';
		if (c >= 'A' && c <= 'F')
			return c - 'A' + 10;
		if (c >= 'a' && c <= 'f')
			return c - 'a' + 10;
		return 0;
	};

	for (const char* p = sig; *p;) {
		if (n >= MAX_TOKENS) {
			LogError("[!] PatternScan: sig exceeds %zu-byte limit, truncated at '%s'\n", MAX_TOKENS, p);
			return 0;
		}
		if (*p == ' ') {
			++p;
			continue;
		}
		if (*p == '?') {
			wild[n]  = true;
			bytes[n] = 0;
			++n;
			++p;
			if (*p == '?')
				++p;
			continue;
		}
		if (!isHex(p[0]) || !isHex(p[1])) {
			LogError("[!] PatternScan: odd-length or non-hex token at offset %td ('%c%c')\n", p - sig,
			         p[0] ? p[0] : '?', p[1] ? p[1] : '?');
			return 0;
		}
		wild[n]    = false;
		bytes[n++] = static_cast<uint8_t>(hex(p[0]) << 4 | hex(p[1]));
		p += 2;
	}
	if (n == 0) {
		LogError("[!] PatternScan: empty pattern\n");
		return 0;
	}

	const auto* mem = reinterpret_cast<uint8_t*>(base);
	for (size_t i = 0; i + n <= size; ++i) {
		bool ok = true;
		for (size_t j = 0; j < n; ++j)
			if (!wild[j] && mem[i + j] != bytes[j]) {
				ok = false;
				break;
			}
		if (ok)
			return base + i;
	}
	return 0;
}

size_t ModuleSize(const uintptr_t base) {
	const auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	const auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
	return nt->OptionalHeader.SizeOfImage;
}

using fnCreateMove = void(__fastcall*)(uintptr_t, unsigned, uintptr_t);

uintptr_t    g_clientBase = 0;
uintptr_t    g_engineBase = 0;
fnCreateMove oCreateMove  = nullptr;
uint32_t*    g_pForceJump = nullptr;
void**       g_pNGC       = nullptr; // &CNetworkGameClient*

// two ways we can unload: user hit END, or DllMain got DETACH'd.
// DETACH runs under the loader lock so FreeConsole/fclose/FreeLibrary
// will deadlock. gotta skip cleanup in that case.
enum UnloadReason : int {
	UNLOAD_NONE   = 0,
	UNLOAD_USER   = 1,
	UNLOAD_DETACH = 2
};

volatile long g_unloadReason = UNLOAD_NONE;

// tick-based bookkeeping (diag, airtime estimation). command generation itself
// must still run on every CreateMove because landing can become visible on a
// later CreateMove within the same server tick.
static int  g_lastBhopTick = -1;
static int  g_phaseTick    = -1;
// fallback toggle when pawn/ground can't be resolved (warmup, respawn, etc).
// keeps us at old-tick-flip behavior instead of going silent.
static bool g_tickFlip = false;
static LARGE_INTEGER g_qpcFreq       = {};
static bool          g_qpcReady      = false;
static long long     g_tickStartQpc  = 0;
static double        g_tickSpanQpc   = 0.0;
static float         g_bestJumpScore = -1000000.0f;
static float         g_bestJumpPhase = 0.0f;
static bool          g_groundRetryPress = false;
static int           g_tickQuantum   = 2;
static int           g_landBiasTicks = 0;
static int g_lastValidTick  = -1;
static int g_lastAirStartTick = -1;
static int g_predictedLandTick = -1;
static int g_estimatedAirTicks = 48;
static int           g_lastPredictPressTick = -1;
static int           g_groundSuppressUntilTick = -1;
static bool          g_strictGroundLock = false;
static int           g_airSamples[6] = {};
static int           g_airSampleCount = 0;
static int           g_airSampleWrite = 0;
static bool          g_initialJumpArmed = false;
static bool          g_landJumpArmed = false;
static void* g_cachedPawn = nullptr;
static void* g_cachedMvs  = nullptr;

// tunables.
// STAMINA_CAP set very high (off) until we know the real scale from logs.
// YAW_DEADZONE / CMD_MAX_MOVE kept for the stashed cmd-move autostrafe path.
// AUTOSTRAFE_* drive the experimental view-yaw override which writes to the
// pawn's m_angEyeAngles pre-CreateMove hoping the cmd-builder sources its
// viewangle from there. If it propagates we get a "free" airstrafe bypass of
// the landing velocity clamp since the engine naturally applies air accel.
static constexpr float STAMINA_CAP    = 200.0f;
static constexpr float STRICT_GROUND_SPEED = 200.0f;
static constexpr float GROUND_RECOVERY_SPEED = 125.0f;
static constexpr int   SNAPSHOT_STALE_TICKS = 16;
static constexpr int   LAND_PREDICT_WINDOW  = 1;
static constexpr int   FALLBACK_PULSE_PERIOD = 3;
static constexpr float JUMP_SCORE_FIRE = 75.0f;
static constexpr float JUMP_SCORE_STEP = 18.0f;
static constexpr float YAW_DEADZONE   = 0.25f;
static constexpr float CMD_MAX_MOVE   = 450.0f;
static constexpr bool  AUTOSTRAFE_ON  = true;  // master switch for the view override
static constexpr float AS_MIN_SPEED   = 60.0f; // don't strafe if we're barely moving
static constexpr float AS_STEP_DEG    = 1.6f;  // max yaw rotation per hook call (deg)
static constexpr float AS_PI          = 3.14159265358979f;
static constexpr int   VEL_MUL_HOLD_TICKS = 4;

// diagnostic state. heartbeat prints a few times at startup regardless of
// anything else so we know the hook is alive; after that, throttled to every
// ~10 ticks while bhop is active. state-edges (space down/up, ground/air)
// log immediately.
static int  g_lastDiagTick     = -1;
static int  g_heartbeatCount   = 0;
static bool g_prevHeld         = false;
static bool g_prevOnGround     = false;
static bool g_prevSnapValid    = false;
static int  g_lastCmdClearTick = -1;
static int  g_lastCmdClearCount = 0;
static int  g_lastCmdSetTick = -1;
static int  g_lastCmdSetCount = 0;

template <typename T>
static bool TryRead(const uintptr_t addr, T& out) {
	__try {
		out = *reinterpret_cast<const T*>(addr);
		return true;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		std::memset(&out, 0, sizeof(out));
		return false;
	}
}

template <typename T>
static bool TryWrite(const uintptr_t addr, const T& value) {
	__try {
		*reinterpret_cast<T*>(addr) = value;
		return true;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

static bool IsProbablyUserPtr(const uintptr_t ptr) {
	return ptr >= 0x10000 && ptr < 0x0000800000000000ull;
}

static int ClearJumpBitAt(const uintptr_t addr) {
	uint64_t value = 0;
	if (!TryRead(addr, value) || (value & CMD_IN_JUMP) == 0)
		return 0;

	const uint64_t cleared = value & ~CMD_IN_JUMP;
	return TryWrite(addr, cleared) ? 1 : 0;
}

static int SetJumpBitAt(const uintptr_t addr) {
	uint64_t value = 0;
	if (!TryRead(addr, value) || (value & CMD_IN_JUMP) != 0)
		return 0;

	const uint64_t pressed = value | CMD_IN_JUMP;
	return TryWrite(addr, pressed) ? 1 : 0;
}

static int ClearJumpFromUserCmd(const uintptr_t cmd) {
	if (!IsProbablyUserPtr(cmd))
		return 0;

	int cleared = 0;

	// c_user_cmd::m_button_state style bunnyhop: scrub only the three
	// button-state lanes from the real usercmd. Do not chase guessed base-cmd
	// pointers here; broad writes were the part that made bhop unstable.
	static constexpr uintptr_t kButtonOffsets[] = {0x58, 0x60, 0x68};
	for (const uintptr_t offset : kButtonOffsets)
		cleared += ClearJumpBitAt(cmd + offset);

	return cleared;
}

static int SetJumpFromUserCmd(const uintptr_t cmd) {
	if (!IsProbablyUserPtr(cmd))
		return 0;

	int set = 0;

	static constexpr uintptr_t kButtonOffsets[] = {0x58, 0x60, 0x68};
	for (const uintptr_t offset : kButtonOffsets)
		set += SetJumpBitAt(cmd + offset);

	return set;
}

static int ReadClientTick() {
	if (!g_pNGC)
		return -1;

	void* ngc = nullptr;
	if (!TryRead(reinterpret_cast<uintptr_t>(g_pNGC), ngc) || !ngc)
		return -1;

	int tick = -1;
	if (!TryRead(reinterpret_cast<uintptr_t>(ngc) + offsets::dwNetworkGameClient_clientTick, tick))
		return -1;

	return tick;
}

static long long ReadQpc() {
	LARGE_INTEGER now{};
	QueryPerformanceCounter(&now);
	return now.QuadPart;
}

static void EnsureQpcReady() {
	if (g_qpcReady)
		return;

	QueryPerformanceFrequency(&g_qpcFreq);
	if (g_qpcFreq.QuadPart <= 0)
		g_qpcFreq.QuadPart = 1;
	g_tickSpanQpc = static_cast<double>(g_qpcFreq.QuadPart) / 64.0;
	g_qpcReady    = true;
}

static void UpdateTickTiming(const int tick, const long long nowQpc) {
	if (tick < 0)
		return;

	EnsureQpcReady();
	if (g_phaseTick == tick)
		return;

	if (g_tickStartQpc > 0) {
		const double observed = static_cast<double>(nowQpc - g_tickStartQpc);
		const double minSpan  = static_cast<double>(g_qpcFreq.QuadPart) / 360.0;
		const double maxSpan  = static_cast<double>(g_qpcFreq.QuadPart) / 20.0;
		if (observed >= minSpan && observed <= maxSpan)
			g_tickSpanQpc = g_tickSpanQpc * 0.82 + observed * 0.18;
	}

	g_phaseTick     = tick;
	g_tickStartQpc  = nowQpc;
	g_bestJumpScore = -1000000.0f;
	g_bestJumpPhase = 0.0f;
}

static float GetTickPhase01(const int tick, const long long nowQpc) {
	if (!g_qpcReady || tick < 0 || g_phaseTick != tick || g_tickSpanQpc <= 1.0)
		return 0.0f;

	float phase = static_cast<float>((nowQpc - g_tickStartQpc) / g_tickSpanQpc);
	if (phase < 0.0f)
		phase = 0.0f;
	if (phase > 1.0f)
		phase = 1.0f;
	return phase;
}

static void* ResolveEntityFromHandlePageTable(const uint32_t handle) {
	uintptr_t pageTable = 0;
	if (!TryRead(g_clientBase + offsets::dwEntityPageTable, pageTable) || !pageTable)
		return nullptr;

	const uint32_t  pageIdx = (handle & 0x7FFF) >> 9;
	uintptr_t       page    = 0;
	if (!TryRead(pageTable + offsets::ENT_PAGE_STRIDE * pageIdx, page) || !page)
		return nullptr;

	const uintptr_t slot = page + offsets::ENT_SLOT_STRIDE * (handle & 0x1FF);
	uint32_t        slotHandle = 0;
	void*           ent = nullptr;
	if (!TryRead(slot + offsets::ENT_SLOT_HANDLE, slotHandle) || slotHandle != handle)
		return nullptr;
	if (!TryRead(slot, ent))
		return nullptr;
	return ent;
}

static void* ResolveEntityFromHandleEntityList(const uint32_t handle) {
	const uint32_t listIndex = (handle & 0x7FFF) >> 9;
	const uint32_t slotIndex = (handle & 0x1FF);
	const uintptr_t rawBase = g_clientBase + offsets::dwEntityList;

	uintptr_t candidates[2] = {rawBase, 0};
	TryRead(rawBase, candidates[1]);

	for (const uintptr_t entityList : candidates) {
		if (!entityList)
			continue;

		uintptr_t listChunk = 0;
		if (!TryRead(entityList + 0x10 * listIndex + 0x8, listChunk) || !listChunk)
			continue;

		void* ent = nullptr;
		if (TryRead(listChunk + 120ull * slotIndex, ent) && ent)
			return ent;
	}

	return nullptr;
}

// local pawn resolution, matching the engine's own GetLocalPlayerPawn (IDA
// sub_1808E0090 on current build). stale dumper says dwLocalPlayerPawn but
// that address has zero xrefs in the live binary - the real path is:
//   controller = dwLocalPlayerController[slot]
//   handle     = controller + m_hPawn (0x6BC)
//   pawn       = entityPageTable[handle pagebits][handle slotbits] (with
//                serial check at slot+0x10)
static void* ResolveLocalPawn(const unsigned slot) {
	void* controller = nullptr;
	const uintptr_t controllerBase = g_clientBase + offsets::dwLocalPlayerController;
	if (!TryRead(controllerBase + sizeof(void*) * slot, controller) || !controller) {
		// normal client uses slot 0; keep the old path as fallback.
		TryRead(controllerBase, controller);
	}

	if (controller) {
		uint32_t handle = UINT32_MAX;
		if (TryRead(reinterpret_cast<uintptr_t>(controller) + offsets::m_hPawn, handle) && handle != UINT32_MAX) {
			if (void* pawn = ResolveEntityFromHandlePageTable(handle))
				return pawn;
			if (void* pawn = ResolveEntityFromHandleEntityList(handle))
				return pawn;
		}
	}

	// direct local pawn path came back in current dumps; keep it as a fallback
	// so we still resolve even if controller/handle traversal shifts again.
	void* pawn = nullptr;
	if (TryRead(g_clientBase + offsets::dwLocalPlayerPawn, pawn) && pawn)
		return pawn;

	return nullptr;
}

// don't intercept while alt-tabbed or typing in the console / menu.
static bool GameHasFocus() {
	const HWND fg  = GetForegroundWindow();
	DWORD      pid = 0;
	GetWindowThreadProcessId(fg, &pid);
	return pid == GetCurrentProcessId();
}

// gather everything we read off the pawn/mvs once per hook call so pre- and
// post-phase share the same snapshot instead of re-walking the entity table.
struct TickSnapshot {
	void*    pawn     = nullptr;
	void*    mvs      = nullptr;
	bool     onGround = false;
	bool     valid    = false;
	bool     cached   = false;
	float    speed2d  = 0.0f;
	float    yawVel   = 0.0f;
	float    stamina  = 0.0f;
	float    velMul   = 0.0f;
	float    velocityModifier = 0.0f;
	float    velZ     = 0.0f;
	int      lastJumpTick = -1;
	int      lastLandedTick = -1;
	float    lastLandedFrac = 0.0f;
	float    lastLandedSpeed = 0.0f;
	uint32_t groundHandle = UINT32_MAX;
	uint32_t flags    = 0;
};

struct Vec3 {
	float x, y, z;
};

struct QAngle3 {
	float pitch, yaw, roll;
};

static bool BuildSnapshotFromPawn(void* pawn, TickSnapshot& s) {
	if (!pawn)
		return false;

	auto* pawnB = static_cast<uint8_t*>(pawn);
	uint32_t flags = 0;
	uint32_t hGround = UINT32_MAX;
	Vec3 vel{};
	QAngle3 angVel{};
	void* mvs = nullptr;

	if (!TryRead(reinterpret_cast<uintptr_t>(pawnB) + offsets::m_fFlags, flags)
	    || !TryRead(reinterpret_cast<uintptr_t>(pawnB) + offsets::m_hGroundEntity, hGround)
	    || !TryRead(reinterpret_cast<uintptr_t>(pawnB) + offsets::m_vecVelocity, vel)
	    || !TryRead(reinterpret_cast<uintptr_t>(pawnB) + offsets::m_angEyeAnglesVelocity, angVel))
		return false;

	TryRead(reinterpret_cast<uintptr_t>(pawnB) + offsets::m_pMovementServices, mvs);

	s.pawn     = pawn;
	s.mvs      = mvs;
	s.flags    = flags;
	s.groundHandle = hGround;
	s.onGround = (flags & offsets::FL_ONGROUND) != 0 || hGround != UINT32_MAX;
	s.speed2d  = std::sqrt(vel.x * vel.x + vel.y * vel.y);
	s.velZ     = vel.z;
	s.yawVel   = angVel.yaw;
	TryRead(reinterpret_cast<uintptr_t>(pawnB) + offsets::m_flVelocityModifier, s.velocityModifier);
	if (mvs) {
		TryRead(reinterpret_cast<uintptr_t>(mvs) + offsets::m_flStamina, s.stamina);
		TryRead(reinterpret_cast<uintptr_t>(mvs) + offsets::m_flVelMulAtJumpStart, s.velMul);
		TryRead(reinterpret_cast<uintptr_t>(mvs) + offsets::m_nLastJumpTick, s.lastJumpTick);

		const uintptr_t modernJump = reinterpret_cast<uintptr_t>(mvs) + offsets::m_ModernJump;
		float landedVelX = 0.0f;
		float landedVelY = 0.0f;
		TryRead(modernJump + offsets::m_nLastLandedTick, s.lastLandedTick);
		TryRead(modernJump + offsets::m_flLastLandedFrac, s.lastLandedFrac);
		TryRead(modernJump + offsets::m_flLastLandedVelocityX, landedVelX);
		TryRead(modernJump + offsets::m_flLastLandedVelocityY, landedVelY);
		s.lastLandedSpeed = std::sqrt(landedVelX * landedVelX + landedVelY * landedVelY);
	}
	s.valid = true;
	return true;
}

static TickSnapshot ReadTickSnapshot(const unsigned slot, const int tick) {
	TickSnapshot s{};
	if (BuildSnapshotFromPawn(ResolveLocalPawn(slot), s)) {
		g_cachedPawn = s.pawn;
		g_cachedMvs  = s.mvs;
		g_lastValidTick = tick;
		return s;
	}

	// Transient local-player resolve misses happen around respawn/round state.
	// Keep using the last good pawn pointer for a short window instead of
	// immediately dropping to blind force-jump pulses.
	if (g_cachedPawn && tick >= 0 && g_lastValidTick >= 0 && tick - g_lastValidTick <= SNAPSHOT_STALE_TICKS) {
		if (BuildSnapshotFromPawn(g_cachedPawn, s)) {
			s.cached = true;
			if (!s.mvs)
				s.mvs = g_cachedMvs;
			return s;
		}
	}

	return s;
}

// autostrafe: while airborne and player is turning their view, write the
// matching strafe direction into the cmd's move fields so the engine applies
// optimal air-accel. perpendicular wishdir maxes air-acceleration since the
// dot(vel, wish) term goes to zero and add_speed hits the airaccel cap.
//
// driven by m_angEyeAnglesVelocity.y so it tracks actual mouse movement rather
// than auto-zigzagging (which would look obviously bot-like). no mouse input
// -> no override, original move values pass through.
//
// run BEFORE oCreateMove so our values are what the cmd-builder reads. the
// cmd ships to the server with our sidemove, server applies the same airaccel
// we predict client-side, so no prediction desync + no CRC issue (we're not
// mutating the cmd itself, just the pre-cmd inputs the builder pulls from).
static void ApplyAutostrafe(const TickSnapshot& s) {
	if (!s.valid || !s.mvs || s.onGround)
		return;

	float side = 0.0f;
	if (s.yawVel > YAW_DEADZONE)
		side = +CMD_MAX_MOVE; // turning right
	else if (s.yawVel < -YAW_DEADZONE)
		side = -CMD_MAX_MOVE; // turning left
	else
		return; // player isn't steering -> leave their input alone

	auto* mvsB = static_cast<uint8_t*>(s.mvs);
	// write BOTH the cmd-staging value (read by the builder for cmd.sidemove)
	// AND the physics-consumed value so any immediate prediction step lines up.
	*reinterpret_cast<float*>(mvsB + offsets::m_flCmdLeftMove) = side;
	*reinterpret_cast<float*>(mvsB + offsets::m_flLeftMove)    = side;
}

// normalize an angle to [-180, 180].
static float WrapAngle(float a) {
	while (a > 180.0f)
		a -= 360.0f;
	while (a < -180.0f)
		a += 360.0f;
	return a;
}

static int ClampInt(const int value, const int lo, const int hi) {
	if (value < lo)
		return lo;
	if (value > hi)
		return hi;
	return value;
}

static void PushAirSample(const int airTicks) {
	g_airSamples[g_airSampleWrite] = airTicks;
	g_airSampleWrite = (g_airSampleWrite + 1) % static_cast<int>(sizeof(g_airSamples) / sizeof(g_airSamples[0]));
	if (g_airSampleCount < static_cast<int>(sizeof(g_airSamples) / sizeof(g_airSamples[0])))
		++g_airSampleCount;
}

static int ComputeAirEstimate() {
	if (g_airSampleCount <= 0)
		return g_estimatedAirTicks;

	int sorted[sizeof(g_airSamples) / sizeof(g_airSamples[0])] = {};
	for (int i = 0; i < g_airSampleCount; ++i)
		sorted[i] = g_airSamples[i];

	for (int i = 0; i < g_airSampleCount; ++i) {
		for (int j = i + 1; j < g_airSampleCount; ++j) {
			if (sorted[j] < sorted[i]) {
				const int tmp = sorted[i];
				sorted[i] = sorted[j];
				sorted[j] = tmp;
			}
		}
	}

	const int mid = g_airSampleCount / 2;
	if ((g_airSampleCount & 1) != 0)
		return sorted[mid];
	return (sorted[mid - 1] + sorted[mid] + 1) / 2;
}

// experimental: rotate the pawn's view yaw toward the optimal airstrafe
// heading. if the cmd-builder sources its viewangle from m_angEyeAngles the
// cmd ships with our rotated yaw, CRC matches (we modified before CRC runs),
// and the engine naturally applies air-accel with forward-held-wishdir now
// perpendicular to velocity -> airspeed climbs past run cap -> even after
// CS2's ~0.65 jump clamp we launch well above 165 u/s.
//
// if the cmd-builder pulls viewangles from elsewhere (separate input cache),
// writing here changes nothing about the shipped cmd and we'll just see the
// view twitch with no speed gain. either way it's not a cmd mutation so no
// CRC kick risk.
static void ApplyViewAutostrafe(const TickSnapshot& s) {
	if (!AUTOSTRAFE_ON || !s.valid || s.onGround)
		return;

	// velocity too low -> can't compute a stable direction, and nothing to
	// accelerate anyway. idle-air-strafing just looks like a drunk bot.
	if (s.speed2d < AS_MIN_SPEED)
		return;

	auto*        pawnB    = static_cast<uint8_t*>(s.pawn);
	const float* vel      = reinterpret_cast<const float*>(pawnB + offsets::m_vecVelocity);
	const float  velYaw   = std::atan2(vel[1], vel[0]) * (180.0f / AS_PI); // [-180, 180]
	float*       angles   = reinterpret_cast<float*>(pawnB + offsets::m_angEyeAngles);
	const float  curYaw   = angles[1];

	// optimal airstrafe heading: perpendicular to velocity. pick whichever side
	// is closer to where the player is currently looking, so the view only has
	// to drift a little per tick instead of snapping 180 deg.
	const float perpA  = velYaw + 90.0f;
	const float perpB  = velYaw - 90.0f;
	const float deltaA = fabsf(WrapAngle(perpA - curYaw));
	const float deltaB = fabsf(WrapAngle(perpB - curYaw));
	const float target = (deltaA < deltaB) ? perpA : perpB;

	// smooth step toward target, capped per tick so the view drifts rather
	// than snapping. AS_STEP_DEG ~= a tick worth at ~100 deg/sec which is
	// comparable to a human flicking slightly while bhopping.
	const float need      = WrapAngle(target - curYaw);
	const float stepMag   = fabsf(need) < AS_STEP_DEG ? fabsf(need) : AS_STEP_DEG;
	const float step      = (need > 0.0f ? 1.0f : -1.0f) * stepMag;
	angles[1]             = WrapAngle(curYaw + step);
}

static float ScoreJumpCandidate(const TickSnapshot& snap, const int tick, const float phase) {
	if (tick < 0)
		return -1000000.0f;

	const int quantum = g_tickQuantum > 0 ? g_tickQuantum : 1;

	if (snap.valid) {
		if (snap.stamina > STAMINA_CAP || snap.lastJumpTick == tick)
			return -1000000.0f;
		if (snap.onGround)
			return -1000000.0f;
	}

	const int delta = g_predictedLandTick - tick;
	if (delta > 0 && delta <= quantum * 3) {
		const float deltaPenalty = static_cast<float>(abs(delta - quantum)) * 52.0f;
		return 1000.0f - deltaPenalty - fabsf(phase - 0.995f) * 20.0f;
	}
	if (delta == 0)
		return 920.0f - fabsf(phase - 0.01f) * 48.0f;
	if (delta < 0 && delta >= -quantum)
		return 740.0f - static_cast<float>(-delta) * 110.0f - fabsf(phase - 0.02f) * 56.0f;
	return -1000000.0f;
}

static float ChooseForcedJumpWhen(const TickSnapshot& snap, const int tick, const float phase) {
	if (snap.valid && snap.onGround)
		return 0.0f;

	float when = phase;
	const int quantum = g_tickQuantum > 0 ? g_tickQuantum : 1;
	const int delta   = g_predictedLandTick - tick;
	if (delta > quantum && delta <= quantum * 2)
		when = 0.999f;
	else if (delta > 0 && delta <= quantum * 2)
		when = 0.995f;
	else if (delta < 0 && delta >= -quantum)
		when = 0.0f;
	else if (delta == 0)
		when = 0.0f;

	if (when < 0.0f)
		when = 0.0f;
	if (when > 0.999f)
		when = 0.999f;
	return when;
}

static bool ShouldHoldVelMul(const TickSnapshot& snap, const int tick) {
	return snap.valid && snap.mvs && tick >= 0 && snap.lastJumpTick >= 0
	    && tick - snap.lastJumpTick >= 0 && tick - snap.lastJumpTick <= VEL_MUL_HOLD_TICKS;
}

static void ForceFullVelocityState(const TickSnapshot& snap) {
	const float fullVelocityMul = 1.0f;
	if (snap.pawn)
		TryWrite(reinterpret_cast<uintptr_t>(snap.pawn) + offsets::m_flVelocityModifier, fullVelocityMul);
	if (snap.mvs)
		TryWrite(reinterpret_cast<uintptr_t>(snap.mvs) + offsets::m_flVelMulAtJumpStart, fullVelocityMul);
}

static void __fastcall hkCreateMove(const uintptr_t pThis, const unsigned slot, const uintptr_t cmd) {
	const bool focused = GameHasFocus();
	const bool held    = focused && (GetAsyncKeyState(VK_SPACE) & 0x8000) != 0;
	const int  tick    = ReadClientTick();
	const TickSnapshot snap = ReadTickSnapshot(slot, tick);
	const bool newTick = tick >= 0 && tick != g_lastBhopTick;

	if (g_heartbeatCount < 5) {
		g_heartbeatCount++;
		Log("[bhop] hook#%d pawn=%p mvs=%p valid=%d held=%d\n",
		    g_heartbeatCount, snap.pawn, snap.mvs, (int)snap.valid, (int)held);
	}

	if (held != g_prevHeld) {
		Log("[bhop] space %s  spd=%.1f stam=%.1f %s\n",
		    held ? "DOWN" : "UP", snap.speed2d, snap.stamina,
		    snap.valid ? (snap.onGround ? "GND" : "AIR") : "NO-PAWN");
		g_prevHeld = held;
	}

	if (snap.valid && held && snap.onGround != g_prevOnGround) {
		Log("[bhop] %s  spd=%.1f stam=%.1f\n",
		    snap.onGround ? "LAND" : "JUMP", snap.speed2d, snap.stamina);
		g_prevOnGround = snap.onGround;
	}

	bool jumpDown = held && snap.valid && snap.onGround;
	const bool recentlyJumpedPre = held && ShouldHoldVelMul(snap, tick);
	if ((jumpDown || recentlyJumpedPre) && snap.mvs) {
		float* arr = reinterpret_cast<float*>(static_cast<uint8_t*>(snap.mvs) +
		                                     offsets::m_arrForceSubtickMoveWhen);
		arr[0] = arr[1] = arr[2] = arr[3] = 0.0f;

		ForceFullVelocityState(snap);
	}

	*g_pForceJump = jumpDown ? FJ_PRESS : FJ_RELEASE;

	if (!held) {
		g_lastBhopTick = -1;
		if (snap.valid)
			g_prevOnGround = snap.onGround;
		oCreateMove(pThis, slot, cmd);
		return;
	}

	oCreateMove(pThis, slot, cmd);
	const TickSnapshot postSnap = ReadTickSnapshot(slot, tick);

	if ((jumpDown || recentlyJumpedPre) && snap.mvs) {
		ForceFullVelocityState(snap);
	}
	if (held && ShouldHoldVelMul(postSnap, tick)) {
		ForceFullVelocityState(postSnap);
	}

	if (snap.valid && snap.onGround) {
		const int set = SetJumpFromUserCmd(cmd);
		if (set > 0) {
			g_lastCmdSetTick = tick;
			g_lastCmdSetCount = set;
		}
	} else if (snap.valid && !snap.onGround && tick != g_lastCmdSetTick && snap.lastJumpTick != tick) {
		const int cleared = ClearJumpFromUserCmd(cmd);
		if (cleared > 0) {
			g_lastCmdClearTick = tick;
			g_lastCmdClearCount = cleared;
		}
	}

	if (newTick) {
		g_lastBhopTick = tick;
		if (snap.valid && (tick - g_lastDiagTick >= 10 || g_lastDiagTick < 0)) {
			g_lastDiagTick = tick;
			Log("[bhop] t=%d spd=%5.1f vz=%6.1f stam=%5.1f vm=%4.2f pvm=%4.2f lj=%d land=%d/%.2f/%5.1f %s fl=0x%X gh=0x%X fj=0x%X set=%d/%d clr=%d/%d\n",
			    tick, snap.speed2d, snap.velZ, snap.stamina, snap.velMul, snap.velocityModifier, snap.lastJumpTick,
			    snap.lastLandedTick, snap.lastLandedFrac, snap.lastLandedSpeed,
			    snap.onGround ? "GND" : "AIR", snap.flags, snap.groundHandle, *g_pForceJump,
			    g_lastCmdSetTick, g_lastCmdSetCount, g_lastCmdClearTick, g_lastCmdClearCount);
		} else if (!snap.valid && (tick - g_lastDiagTick >= 128 || g_lastDiagTick < 0)) {
			g_lastDiagTick = tick;
			Log("[bhop] t=%d NO-PAWN fj=0x%X\n", tick, *g_pForceJump);
		}
	}
}

static DWORD WINAPI MainThread(const LPVOID hMod) {
	AllocConsole();
	freopen_s(&g_console, "CONOUT$", "w", stdout);
	OpenLogFile();
	Log("[bhop] loaded\n");

	HMODULE client;
	while (!((client = GetModuleHandleA("client.dll"))))
		Sleep(100);
	HMODULE engine;
	while (!((engine = GetModuleHandleA("engine2.dll"))))
		Sleep(100);

	g_clientBase      = reinterpret_cast<uintptr_t>(client);
	g_engineBase      = reinterpret_cast<uintptr_t>(engine);
	const size_t size = ModuleSize(g_clientBase);

	Log("[bhop] modules resolved\n");

	g_pForceJump = reinterpret_cast<uint32_t*>(g_clientBase + offsets::dwForceJump);
	g_pNGC       = reinterpret_cast<void**>(g_engineBase + offsets::dwNetworkGameClient);

	const uintptr_t cmAddr = PatternScan(g_clientBase, size, SIG_CREATE_MOVE);
	if (!cmAddr) {
		LogError("[!] CreateMove sig miss\n");
		return 1;
	}
	Log("[bhop] CreateMove @ client+0x%llx\n", static_cast<unsigned long long>(cmAddr - g_clientBase));

	if (MH_Initialize() != MH_OK) {
		Log("[!] MH_Initialize\n");
		return 1;
	}
	if (MH_CreateHook(reinterpret_cast<LPVOID>(cmAddr), &hkCreateMove, reinterpret_cast<LPVOID*>(&oCreateMove)) !=
	    MH_OK) {
		Log("[!] MH_CreateHook\n");
		return 1;
	}
	if (MH_EnableHook(reinterpret_cast<LPVOID>(cmAddr)) != MH_OK) {
		Log("[!] MH_EnableHook\n");
		return 1;
	}
	Log("[bhop] hook ON, SPACE=bhop, END=unload\n");

	while (g_unloadReason == UNLOAD_NONE && !(GetAsyncKeyState(VK_END) & 0x8000))
		Sleep(50);

	// if END got us out, mark it USER. if DllMain already flagged DETACH,
	// don't touch it.
	InterlockedCompareExchange(&g_unloadReason, UNLOAD_USER, UNLOAD_NONE);

	MH_DisableHook(reinterpret_cast<LPVOID>(cmAddr));
	// give any in-flight hkCreateMove a moment to finish before we nuke
	// the trampoline pages
	Sleep(250);
	MH_Uninitialize();

	if (g_unloadReason == UNLOAD_DETACH) {
		// loader lock is held, anything fancy here deadlocks.
		// FreeLibraryAndExitThread is pointless too since we're already going away.
		// client.dll might be gone already so don't touch g_pForceJump either.
		return 0;
	}

	*g_pForceJump = FJ_RELEASE;
	Log("[bhop] unloaded\n");
	if (g_console)
		fclose(g_console);
	if (g_logFile) {
		fclose(g_logFile);
		g_logFile = nullptr;
	}
	FreeConsole();
	FreeLibraryAndExitThread(static_cast<HMODULE>(hMod), 0);
}

BOOL APIENTRY DllMain(const HMODULE hMod, const DWORD reason, LPVOID) {
	if (reason == DLL_PROCESS_ATTACH) {
		g_hMod = hMod;
		DisableThreadLibraryCalls(hMod);
		CreateThread(nullptr, 0, MainThread, hMod, 0, nullptr);
	} else if (reason == DLL_PROCESS_DETACH) {
		// loader lock is held here. bare minimum, get out.
		// MainThread checks this flag and skips the stuff that would hang.
		InterlockedExchange(&g_unloadReason, UNLOAD_DETACH);
	}
	return TRUE;
}
