#include <stdio.h>
#include <stdlib.h>
#define _WIN32_WINNT 0x500
#include <windows.h>
#include "dbg/dbg.h"
#include "MemProc/MemProc.h"
#include "Scanner/Scanner.h"
#include "Keyboard/KeyState.h"
#include "HookEngine/HookEngine.h"

#pragma pack(push, 1)
typedef struct _Unit
{
  int field_0;
  char gap_4[80];
  float posX;
  float posZ;
  float posY;
  int field_19;
  int field_23;
  int field_28;
  char gap_6C[44];
  char field_33;
  char gap_99[11];
  int field_34;
  char gap_A8[24];
  int field_35;
  int isHero;
  char gap_C8[168];
  int field_38;
  int field_39;
  int field_40;
  char gap_17C[12];
  int isNotMovable;
} Unit;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _Position
{
	float x, z, y;
} Position;
#pragma pack(pop)

void doPatch (DWORD addr, char *patch, int sizePatch, unsigned char *original, int sizeOriginal, bool enable)
{
	int size;
	unsigned char * code;
	DWORD oldProtect;

	if (enable) {
		size = sizePatch;
		code = patch;
	} else {
		size = sizeOriginal;
		code = original;
	}

	VirtualProtect ((LPVOID) addr, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy ((unsigned char *) addr, code, size);
}

bool Unit_is_hero (Unit *unit)
{
	DWORD globalContainer = 0x11CAD218;

	if (globalContainer) {
		if ( *(DWORD *)(globalContainer + 960) > 0 ) {
			DWORD v17 = *(DWORD *)(**(DWORD **)(globalContainer + 956) + 64);
			if (v17) {
				if (*(Unit **)(v17 + 496) == unit) {
					return true;
				}
			}
		}
	}

	return false;
}

int offsetY = 0;
BbQueue units;

EXPORT_FUNCTION
signed int __thiscall updateUnitPosition (void *this, Unit *unit, Position *offset, int a4, char a5, int a6)
{
	signed int __thiscall (*original_updateUnitPosition) (void *this, Unit *unit, Position *offset, int a4, char a5, int a6);
	original_updateUnitPosition = (void *) HookEngine_get_original_function ((ULONG_PTR) updateUnitPosition);

	//if (Unit_is_hero (unit))
	{
		if (offsetY != 0) {
			if (!bb_queue_exists(&units, unit)) {
				bb_queue_add (&units, unit);
				unit->posY += offsetY;
			} else {
				bb_queue_clear(&units);
				offsetY = 0;
			}
		}
	}

	return original_updateUnitPosition (this, unit, offset, a4, a5, a6);
}

/*
 * Description :	Function called when the DLL in injected or the executable is launched
 */
EXPORT_FUNCTION void startInjection (void)
{
	char *path = get_module_path ("BladeAndSoulHack.dll");
	FILE * debugOutput = file_open (str_dup_printf("%s/Log.txt", path), "w+");
	dbg_set_output (debugOutput);

	struct tm now = *localtime ((time_t[]) {time(NULL)});
	dbg ("====== Injection started at %d-%d-%d %02d:%02d:%02d ======",
		now.tm_year + 1900, now.tm_mon + 1, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec);

	if (!HookEngine_new (str_dup_printf("%s/NtHookEngine.dll", path))) {
		fail ("HookEngine not found.");
		return;
	}

	bb_queue_init (&units);
	// HookEngine_hook ((ULONG_PTR) 0x10532F10, (ULONG_PTR) &updateUnitPosition);
	/*
		105336C7     F30F1043 5C       movss xmm0, [dword ds:ebx+5C]
		105336CC     F30F584424 68     addss xmm0, [dword ss:esp+68]
		105336D2     F30F1143 5C       movss [dword ds:ebx+5C], xmm0
		105336D7     8B10              mov edx, [dword ds:eax]
		105336D9     8953 60           mov [dword ds:ebx+60], edx
	*/
	static unsigned char pattern [21] = {
		0xF3, 0x0F, 0x10, 0x43, 0x5C,
		0xF3, 0x0F, 0x58, 0x44, 0x24, 0x68,
		0xF3, 0x0F, 0x11, 0x43, 0x5C,
		0x8B, 0x10,
		0x89, 0x53, 0x60
	};

	static unsigned char patch [21] = {
		0xF3, 0x0F, 0x10, 0x43, 0x5C,
		0xF3, 0x0F, 0x58, 0x44, 0x24, 0x68,
		0x90, 0x90, 0x90, 0x90, 0x90,
		0x8B, 0x10,
		0x89, 0x53, 0x60
	};

	DWORD bsEngineBaseAddress = 0x10000000;
	DWORD bsEngineEnd         = 0x11402FFE;

	DWORD HeroPositionAddress = memscan_buffer (
		"HeroPosition",
		bsEngineBaseAddress, bsEngineEnd - bsEngineBaseAddress,
		pattern, sizeof(pattern)
	);

	if (!HeroPositionAddress) {
		// Maybe already patched ?
		HeroPositionAddress = memscan_buffer (
			"HeroPosition",
			bsEngineBaseAddress, bsEngineEnd - bsEngineBaseAddress,
			patch, sizeof(patch)
		);
		if (!HeroPositionAddress) {
			fail ("Nothing found.");
			return;
		}
	}

	dbg (".text patch address found : %x", HeroPositionAddress);

	bool activated = false;
	bool running = true;
	while (running) {
		Sleep (10);

		if (is_key_typed (VK_XBUTTON1)) {
			activated = !activated;
			doPatch (HeroPositionAddress, patch, sizeof(patch), pattern, sizeof(pattern), activated);
		}

		if (is_key_typed (VK_ADD)) {
			offsetY += 100;
		}

		if (is_key_typed (VK_SUBTRACT)) {
			offsetY -= 100;
		}

		if (is_key_typed(VK_F11)) {
			HookEngine_unhook_all();
			doPatch (HeroPositionAddress, patch, sizeof(patch), pattern, sizeof(pattern), false);
			running = false;
		}
	}
}


/*
 * Description :	Function called when the DLL in ejected.
 */
EXPORT_FUNCTION void endInjection (void)
{
}


/*
 * Description :	DLL entry point.
 */
bool WINAPI DllMain (HMODULE dll, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
			CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE) startInjection, NULL, 0, NULL);
		break;

		case DLL_PROCESS_DETACH:
			endInjection ();
		break;
	}

	return true;
}

int main()
{

}
