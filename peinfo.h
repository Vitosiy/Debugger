#include <Windows.h>
#include <stdio.h>
#include <malloc.h>

typedef struct _PeHeaders {
	char* filename;

	HANDLE fd;
	HANDLE mapd;
	PBYTE mem;
	DWORD filesize;

	IMAGE_DOS_HEADER* doshead;
	IMAGE_NT_HEADERS* nthead;

	IMAGE_IMPORT_DESCRIPTOR* impdir;
	DWORD sizeImpdir;
	DWORD countImpdes;
	IMAGE_EXPORT_DIRECTORY* expdir;
	DWORD sizeExpdir;

	IMAGE_SECTION_HEADER* sections;
	DWORD countSec;

	IMAGE_BASE_RELOCATION* relocs_directory;
	DWORD reloc_directory_size;

	BYTE pe32plus;

} PeHeaders;

ULONG_PTR RvaToOffset(ULONG_PTR rva, PeHeaders* pe);

BOOL LoadPeFile(const DWORD addr, PeHeaders* pe);

BOOL FileSize(const char* filename, PeHeaders* pe);
