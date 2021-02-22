#include <MinHook.h>

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
	if (reason != DLL_PROCESS_ATTACH)
		return TRUE;

	DisableThreadLibraryCalls(module);

	MH_Initialize();
	MH_CreateHookApi(L"ntdll.dll", "RtlMultiByteToUnicodeN", (LPVOID) +[]
		(PWCH UnicodeString, ULONG MaxBytesInUnicodeString, PULONG BytesInUnicodeString, const CHAR* MultiByteString, ULONG BytesInMultiByteString)
	{
		auto length = MultiByteToWideChar(932, 0, MultiByteString, BytesInMultiByteString, UnicodeString, MaxBytesInUnicodeString);

		if (length == 0 && GetLastError() != 0)
			return 1L;

		if (BytesInUnicodeString != nullptr)
			*BytesInUnicodeString = length * sizeof(wchar_t);

		return 0L;
	}, nullptr);
	MH_EnableHook(MH_ALL_HOOKS);

	return TRUE;
}