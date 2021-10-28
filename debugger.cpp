#include "debugger.h"

#define BUFSIZE 512


bool Debugger::Target(const std::wstring& path) {
	bool ret;

	if (!std::filesystem::exists(path)) {
		std::cout << "File does not exists" << std::endl;
		return false;
	}

	STARTUPINFO startup_info = {0};
	PROCESS_INFORMATION process_info = {0};

	startup_info.cb = sizeof(startup_info);
	startup_info.dwFlags = STARTF_USESHOWWINDOW;
	startup_info.wShowWindow = SW_SHOWNORMAL;

	ret = CreateProcess(path.c_str(),
		NULL,
		NULL,
		NULL,
		TRUE,
		DEBUG_ONLY_THIS_PROCESS,
		NULL,
		NULL,
		&startup_info,
		&process_info);

	if (!ret) {
		std::cout << "CreateProcess did not create process" << std::endl;
		return false;
	}

	this->debugee_handle = process_info.hProcess;
	CloseHandle(process_info.hThread);

	return true;
}

bool Debugger::Target(const DWORD pid) {
	debugee_handle = (HANDLE)pid;

	try {
		if (!DebugActiveProcess(pid)) {
			throw std::exception("DebugActiveProcess failed");
		}
		return true;
	}
	catch (const std::exception&) {
		DWORD error = GetLastError();
		if (error == 5) {
			std::cout << "You can not debug this process (Access denied)" << std::endl;
		}
		else if (error == 87) {
			std::cout << "Probably you are trying to debug wrong arch of the pid. x64 != x32 or the process does not exists" << std::endl;
		}
		return false;
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////---������� ������---/////////////////////////////////////////////////////////////

void Debugger::Debug() {
	bool completed = false;
	bool attached = false;

	while (!completed) {
		CONTEXT ctx = {0};
		DEBUG_EVENT event = {0};
		DWORD continueFlag = DBG_CONTINUE;

		ctx.ContextFlags = CONTEXT_ALL;

		if (!WaitForDebugEvent(&event, INFINITE)) {
			break;
		}

		switch (event.dwDebugEventCode) {
		case CREATE_PROCESS_DEBUG_EVENT:
			EventCreateProcess(event.dwProcessId, event.dwThreadId, &event.u.CreateProcessInfo);
			//if (tracing) {
			//	GetThreadContext(event.u.CreateProcessInfo.hThread, &ctx);
			//	ctx.EFlags |= 0x100;
			//	SetThreadContext(event.u.CreateProcessInfo.hThread, &ctx);
			//}
			if (fun_tracing) {
				SetTracingFunctionsBreakpoints();
			}
#if _WIN64
			SetBreakpoint((char*)event.u.CreateProcessInfo.lpStartAddress, INITIAL_BREAKPOINT, nullptr);
#else
			SetBreakpoint((char*)event.u.CreateProcessInfo.lpStartAddress - 0x29e, INITIAL_BREAKPOINT, nullptr);
#endif // _WIN64

			break;

		case EXCEPTION_DEBUG_EVENT:
			continueFlag = EventException(event.dwProcessId, event.dwThreadId, &event.u.Exception);
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			EventExitProcess(event.dwProcessId, event.dwThreadId, &event.u.ExitProcess);
			completed = true;
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			EventCreateThread(event.dwProcessId, event.dwThreadId, &event.u.CreateThread);
			//if (tracing) {
			//	GetThreadContext(event.u.CreateThread.hThread, &ctx);
			//	ctx.EFlags |= 0x100;
			//	SetThreadContext(event.u.CreateThread.hThread, &ctx);
			//}
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			EventExitThread(event.dwProcessId, event.dwThreadId, &event.u.ExitThread);
			break;

		case LOAD_DLL_DEBUG_EVENT:
			EventLoadDll(event.dwProcessId, event.dwThreadId, &event.u.LoadDll);
			break;

		case UNLOAD_DLL_DEBUG_EVENT:
			EventUnloadDll(event.dwProcessId, event.dwThreadId, &event.u.UnloadDll);
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			EventOutputDebugString(event.dwProcessId, event.dwThreadId, &event.u.DebugString);
			break;

		case (DWORD)EXCEPTION_GUARD_PAGE:
			std::cout << "Exception guard page" << std::endl;
			break;

		default:
			std::cout << "Unexpected debug event: " << event.dwDebugEventCode << std::endl;
		}

		if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueFlag)) {
			std::cout << "Error at continuing debug event!" << std::endl;
		}
	}

	CloseHandle(this->debugee_handle);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////---����� �����������---//////////////////////////////////////////////////////////

void Debugger::Tracing(const bool tracing) {
	this->tracing = tracing;
}

void Debugger::Libs(const bool tracing) {
	this->lib_tracing = tracing;
}

void Debugger::Functions(const bool tracing) {
	this->fun_tracing = tracing;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////---�������� ��� ����� �� ������---///////////////////////////////////////////////

//https://docs.microsoft.com/en-us/windows/win32/memory/obtaining-a-file-name-from-a-file-handle <- ������� ����� ������
std::wstring GetFileNameFromHandle(HANDLE hFile) {
	BOOL bSuccess = FALSE;
	TCHAR pszFilename[MAX_PATH + 1];
	HANDLE hFileMap;

	DWORD dwFileSizeHi = 0;
	DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

	if (dwFileSizeLo == 0 && dwFileSizeHi == 0) {
		return L"";
	}

	// Create a file mapping object.
	hFileMap = CreateFileMapping(hFile,
		NULL,
		PAGE_READONLY,
		0,
		1,
		NULL);

	if (hFileMap) {
		// Create a file mapping to get the file name.
		void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

		if (pMem) {
			if (GetMappedFileName(GetCurrentProcess(),
				pMem,
				pszFilename,
				MAX_PATH)) {

				// Translate path with device name to drive letters.
				TCHAR szTemp[BUFSIZE];
				szTemp[0] = '\0';

				if (GetLogicalDriveStrings(BUFSIZE - 1, szTemp)) {
					TCHAR szName[MAX_PATH];
					TCHAR szDrive[3] = TEXT(" :");
					BOOL bFound = FALSE;
					TCHAR* p = szTemp;

					do {
						// Copy the drive letter to the template string
						*szDrive = *p;

						// Look up each device name
						if (QueryDosDevice(szDrive, szName, MAX_PATH)) {
							size_t uNameLen = _tcslen(szName);

							if (uNameLen < MAX_PATH) {
								bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
									&& *(pszFilename + uNameLen) == _T('\\');

								if (bFound) {
									// Reconstruct pszFilename using szTempFile
									// Replace device path with DOS path
									TCHAR szTempFile[MAX_PATH];
									StringCchPrintf(szTempFile,
										MAX_PATH,
										TEXT("%s%s"),
										szDrive,
										pszFilename + uNameLen);
									StringCchCopyN(pszFilename, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
								}
							}
						}

						// Go to the next NULL character.
						while (*p++);
					} while (!bFound && *p); // end of string
				}
			}
			bSuccess = TRUE;
			UnmapViewOfFile(pMem);
		}

		CloseHandle(hFileMap);
	}

	return pszFilename;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////---�������---///////////////////////////////////////////////////////

void Debugger::EventCreateProcess(const Dword& pid, const Dword& tid, LPCREATE_PROCESS_DEBUG_INFO info) {
	std::cout << "CreateProcess @ " << info->lpBaseOfImage << "!" << std::endl;
	std::cout << "PID: " << pid << std::endl;
	std::cout << "TID: " << tid << std::endl;
	if (info->lpImageName) {
		std::cout << "Name: " << info->lpImageName << std::endl;
	}

	this->threads.push_back(tid);
}

void Debugger::EventExitProcess(const Dword& pid, const Dword& tid, LPEXIT_PROCESS_DEBUG_INFO info) {
	std::cout << "ExitProcess with code " << info->dwExitCode << "!" << std::endl;
	std::cout << "PID: " << pid << std::endl;
	std::cout << "TID: " << tid << std::endl;

	//TODO: ������� �������?
}

void Debugger::EventCreateThread(const Dword& pid, const Dword& tid, LPCREATE_THREAD_DEBUG_INFO info) {
	std::cout << "CreateThread @ " << info->lpStartAddress << "!" << std::endl;
	std::cout << "PID: " << pid << std::endl;
	std::cout << "TID: " << tid << std::endl;

	this->threads.push_back(tid);
}

void Debugger::EventExitThread(const Dword& pid, const Dword& tid, LPEXIT_THREAD_DEBUG_INFO info) {
	auto found = std::find(this->threads.begin(), this->threads.end(), tid);

	std::cout << "ExitThread with code " << info->dwExitCode << "!" << std::endl;
	std::cout << "PID: " << pid << std::endl;
	std::cout << "TID: " << tid << std::endl;

	if (found != this->threads.end()) {
		this->threads.erase(found);
	}
}

void Debugger::EventLoadDll(const Dword& pid, const Dword& tid, LPLOAD_DLL_DEBUG_INFO info) {
	const std::wstring dll = GetFileNameFromHandle(info->hFile);

	std::cout << "LoadDLL @ " << info->lpBaseOfDll << "!" << std::endl;
	std::cout << "PID: " << pid << std::endl;
	std::cout << "TID: " << tid << std::endl;

	std::wcout << "Name: " << dll << std::endl;

	InsertDLL(info->lpBaseOfDll, dll);

	if (lib_tracing) {
		IMAGE_DOS_HEADER doshead;
		ReadProcessMemory(this->debugee_handle,
			info->lpBaseOfDll,
			&doshead,
			sizeof(IMAGE_DOS_HEADER),
			nullptr);
		if (doshead.e_magic != IMAGE_DOS_SIGNATURE) {
			return;
		}

		IMAGE_NT_HEADERS nthead;
		ReadProcessMemory(this->debugee_handle,
			(void*)((size_t)info->lpBaseOfDll + doshead.e_lfanew),
			&nthead,
			sizeof(IMAGE_NT_HEADERS),
			nullptr);
		if (nthead.Signature != IMAGE_NT_SIGNATURE || nthead.OptionalHeader.NumberOfRvaAndSizes <= 0) {
			return;
		}

		IMAGE_EXPORT_DIRECTORY expdir;
		ReadProcessMemory(this->debugee_handle,
			(void*)((size_t)info->lpBaseOfDll + nthead.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
			&expdir,
			sizeof(IMAGE_EXPORT_DIRECTORY),
			nullptr);

		if (expdir.AddressOfNames == 0) {
			return;
		}

		void* base = info->lpBaseOfDll;
		WORD* ord_buffer = new WORD[expdir.NumberOfNames];
		DWORD* func_buffer = new DWORD[expdir.NumberOfFunctions];
		DWORD* name_buffer = new DWORD[expdir.NumberOfNames];
		ReadProcessMemory(this->debugee_handle, (LPCVOID)((size_t)base + expdir.AddressOfNameOrdinals),
			ord_buffer, expdir.NumberOfNames * sizeof(WORD), nullptr);
		ReadProcessMemory(this->debugee_handle, (LPCVOID)((size_t)base + expdir.AddressOfFunctions),
			func_buffer, expdir.NumberOfFunctions * sizeof(DWORD), nullptr);
		ReadProcessMemory(this->debugee_handle, (LPCVOID)((size_t)base + expdir.AddressOfNames),
			name_buffer, expdir.NumberOfNames * sizeof(DWORD), nullptr);
		
		for (DWORD i = 0; i < expdir.NumberOfNames; ++i) {
			char s[128] = {0};

			ReadProcessMemory(this->debugee_handle, (LPCVOID)((size_t)base + name_buffer[i]), s, 128, nullptr);
			auto function_address = (void*)((size_t)base + func_buffer[ord_buffer[i]]);
			std::cout << s << " -> " << function_address << std::endl;

			SetBreakpoint(function_address, LIB_FUNCTION_BREAKPOINT, nullptr);
			this->lib_breakpoints[function_address] = LibFunctionBreakpoint{dll, s, function_address};
		}

		delete[] func_buffer;
		delete[] ord_buffer;
		delete[] name_buffer;
	}
}

void Debugger::EventUnloadDll(const Dword& pid, const Dword& tid, LPUNLOAD_DLL_DEBUG_INFO info) {
	std::cout << "UnloadDLL @ " << info->lpBaseOfDll << "!" << std::endl;
	std::cout << "PID: " << pid << std::endl;
	std::cout << "TID: " << tid << std::endl;

	if (lib_tracing) {
		for (const auto bp : lib_breakpoints) {
			if (bp.second.lib_name == this->dll[info->lpBaseOfDll]) {
				auto b = this->breakpoints[bp.second.addr];
				WriteProcessMemory(this->debugee_handle, b.addr, &b.saved_byte, 1, nullptr);
				FlushInstructionCache(this->debugee_handle, b.addr, 1);
				this->breakpoints.erase(bp.second.addr);
			}
		}
	}

	DeleteDLL(info->lpBaseOfDll);
}

void Debugger::EventOutputDebugString(const Dword& pid, const Dword& tid, LPOUTPUT_DEBUG_STRING_INFO info) {
	std::string info_string = std::string(info->nDebugStringLength, 0);
	ReadProcessMemory(this->debugee_handle, info->lpDebugStringData, &info_string, info->nDebugStringLength, nullptr);
	std::cout << "Debug string: " << info_string << std::endl;
	std::cout << "PID: " << pid << std::endl;
	std::cout << "TID: " << tid << std::endl;
}

//////////////////////////////////////////////---��������� ����������---////////////////////////////////////////////////

Dword Debugger::EventException(const Dword& pid, const Dword& tid, LPEXCEPTION_DEBUG_INFO info) {
	//TODO: �������� createfilea ����
	if (info->ExceptionRecord.ExceptionAddress == (PVOID)0x759B88E0) {
		std::cout << "123" << std::endl;
	}
	if (info->ExceptionRecord.ExceptionAddress == (PVOID)0x759D2D90) {
		std::cout << "123" << std::endl;
	}

	HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
	CONTEXT ctx = {0};
	char* buf;
	char assembly_buffer[128] = {0};
	char hex_buffer[128] = {0};
	std::string assembly_string;
	switch (info->ExceptionRecord.ExceptionCode) {
	case (DWORD)EXCEPTION_BREAKPOINT:
#ifdef _WIN64
	case STATUS_WX86_BREAKPOINT:
#endif
	{
		auto found = this->breakpoints.find(info->ExceptionRecord.ExceptionAddress);
		if (lib_tracing) {
			if (found != this->breakpoints.end() && found->second.type == LIB_FUNCTION_BREAKPOINT) {
				for (auto it = this->threads.begin(); it != this->threads.end(); ++it) {
					if ((*it) != tid) {
						HANDLE thr = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
						SuspendThread(thr);
						CloseHandle(thr);
					}
				}

				std::cout << "DLL's function @ " << info->ExceptionRecord.ExceptionAddress << std::endl;
				std::cout << "PID: " << pid << std::endl;
				std::cout << "TID: " << tid << std::endl;
				std::cout << "Function name: " << lib_breakpoints[info->ExceptionRecord.ExceptionAddress].function_name.c_str() << std::endl;
				std::cout << "DLL name: " << lib_breakpoints[info->ExceptionRecord.ExceptionAddress].lib_name.c_str() << std::endl;

				CONTEXT ctx = {0};
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(thread, &ctx);
				ctx.EFlags |= 0x100;
				ctx.EIP--;

				SetThreadContext(thread, &ctx);
				WriteProcessMemory(this->debugee_handle, (PVOID)info->ExceptionRecord.ExceptionAddress, &found->second.saved_byte, 1, nullptr);
				FlushInstructionCache(this->debugee_handle, (PVOID)info->ExceptionRecord.ExceptionAddress, 1);

				buf = new char[16];
				size_t bytesRead = 0;
				ReadProcessMemory(this->debugee_handle, info->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
				bytesRead = DisasInstruction((unsigned char*)buf, 16, (unsigned int)info->ExceptionRecord.ExceptionAddress, assembly_buffer, hex_buffer);
				SetBreakpoint((void*)((size_t)(info->ExceptionRecord.ExceptionAddress) + bytesRead), SAVE_BREAKPOINT, &found->second);
				delete[] buf;
			}
		}

		if (!this->debugging) {
			auto found = this->breakpoints.find(info->ExceptionRecord.ExceptionAddress);
			if (found == this->breakpoints.end() || found->second.type != INITIAL_BREAKPOINT) {
				break;
			}

			CONTEXT ctx = {0};
			ctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(thread, &ctx);
			ctx.EFlags |= 0x100;
			ctx.EIP--;
			SetThreadContext(thread, &ctx);
			WriteProcessMemory(this->debugee_handle, (PVOID)info->ExceptionRecord.ExceptionAddress, &found->second.saved_byte, 1, nullptr);
			FlushInstructionCache(this->debugee_handle, (PVOID)info->ExceptionRecord.ExceptionAddress, 1);
			this->breakpoints.erase(found);

			if (tracing) {
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(thread, &ctx);
				ctx.EFlags |= 0x100;
				SetThreadContext(thread, &ctx);
			}
			this->debugging = true;
		}
		break;
	}

	case (DWORD)EXCEPTION_SINGLE_STEP:
#ifdef _WIN64 
	case STATUS_WX86_SINGLE_STEP:
#endif
	{
		auto found = this->breakpoints.find(info->ExceptionRecord.ExceptionAddress);

		if (found != this->breakpoints.end() && found->second.type == TRACING_FUNCTION_BREAKPOINT) {
			std::cout << "Exception breakpoint @ " << info->ExceptionRecord.ExceptionAddress << std::endl;
			std::cout << "PID: " << pid << std::endl;
			std::cout << "TID: " << tid << std::endl;
			std::cout << "Function name: " << tracing_functions[info->ExceptionRecord.ExceptionAddress].c_str() << std::endl;

			//����� ����� ���������� ���������
			this->ParseArgumentsOfMyTracingFunctions(tid, tracing_functions[info->ExceptionRecord.ExceptionAddress]);
			//this->ParseArguments(tid, tracing_functions[info->ExceptionRecord.ExceptionAddress]);

			for (auto it = this->threads.begin(); it != this->threads.end(); ++it) {
				if ((*it) == tid) {
					HANDLE thr = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
					SuspendThread(thr);
					CloseHandle(thr);
				}
			}

			CONTEXT ctx = {0};
			ctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(thread, &ctx);
			ctx.EFlags |= 0x100;
			ctx.EIP--;
			SetThreadContext(thread, &ctx);
			WriteProcessMemory(this->debugee_handle, (PVOID)info->ExceptionRecord.ExceptionAddress, &found->second.saved_byte, 1, nullptr);
			FlushInstructionCache(this->debugee_handle, (PVOID)info->ExceptionRecord.ExceptionAddress, 1);

			buf = new char[16];
			size_t bytesRead = 0;
			ReadProcessMemory(this->debugee_handle, info->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
			bytesRead = DisasInstruction((unsigned char*)buf, 16, (unsigned int)info->ExceptionRecord.ExceptionAddress, assembly_buffer, hex_buffer);
			SetBreakpoint((void*)((size_t)(info->ExceptionRecord.ExceptionAddress) + bytesRead), SAVE_BREAKPOINT, &found->second);
			delete[] buf;
		}
		else if (found != this->breakpoints.end() && found->second.type == FUNCTION_RETURN_BREAKPOINT) {
			CONTEXT ctx = {0};
			ctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(thread, &ctx);
			ctx.EIP--;
			SetThreadContext(thread, &ctx);
			WriteProcessMemory(this->debugee_handle, (PVOID)info->ExceptionRecord.ExceptionAddress, &found->second.saved_byte, 1, nullptr);
			FlushInstructionCache(this->debugee_handle, (PVOID)info->ExceptionRecord.ExceptionAddress, 1);

			size_t functionResult = ctx.EAX;
			PrintFunctionCall(this->function_calls[info->ExceptionRecord.ExceptionAddress].name, this->function_calls[info->ExceptionRecord.ExceptionAddress].arguments, functionResult);
		}

		if (tracing) {
			ctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(thread, &ctx);
			ctx.EFlags |= 0x100;
			SetThreadContext(thread, &ctx);
		}

		if (found != this->breakpoints.end() && found->second.type == SAVE_BREAKPOINT) {
			// ���������� 0xCC
			WriteProcessMemory(this->debugee_handle, found->second.prev->addr, "\xCC", 1, nullptr);
			FlushInstructionCache(this->debugee_handle, found->second.prev->addr, 1);

			// ��������������� ���� ��� SAVE_BREAKPOINT
			WriteProcessMemory(this->debugee_handle, (PVOID)info->ExceptionRecord.ExceptionAddress, &found->second.saved_byte, 1, nullptr);
			FlushInstructionCache(this->debugee_handle, (PVOID)info->ExceptionRecord.ExceptionAddress, 1);

			this->breakpoints.erase(found);

			for (auto it = this->threads.begin(); it != this->threads.end(); ++it) {
				HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
				auto val = ResumeThread(thread);
				CloseHandle(thread);
			}
		}

		if (tracing) {
			buf = new char[16];
			ReadProcessMemory(this->debugee_handle, info->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
			DisasInstruction((unsigned char*)buf, 16, (size_t)info->ExceptionRecord.ExceptionAddress, assembly_buffer, hex_buffer);

			assembly_string = assembly_buffer;
			std::transform(assembly_string.begin(), assembly_string.end(), assembly_string.begin(), ::toupper);

			_debug_stream << assembly_buffer << ":" << std::hex << info->ExceptionRecord.ExceptionAddress << ":" << tid << std::endl;

			if (!this->call_stack.empty()) {
				Command cmd(assembly_string);
				auto& current_call_from_stack = this->call_stack.top();
				const auto offset = cmd.get_ebp_offset();
				if (offset) {
					if (offset.value() > current_call_from_stack.current_max_ebp_offset) {
						current_call_from_stack.current_max_ebp_offset = offset.value();
					}
					if (offset < 8 && !current_call_from_stack.current_call_accessed_less_than_8_bytes_ebp) {
						current_call_from_stack.current_call_accessed_less_than_8_bytes_ebp = true;
					}

					if (offset > 0) {
#ifdef _WIN64
						ReadProcessMemory(this->debugee_handle, (LPCVOID)(ctx.Rbp + offset.value()), buf, 16, nullptr);
#else
						ReadProcessMemory(this->debugee_handle, (LPCVOID)(ctx.Ebp + offset.value()), buf, 16, nullptr);
#endif
						current_call_from_stack.values_on_ebp_offsets[offset.value()] = (Dword)buf;
					}
				}

				const auto dst_used_registers = cmd.dst_used_registers();
				const auto src_used_registers = cmd.src_used_registers();

				//�������, �� ����� ��������� ����� ������
				//���� �� ������-�� �������� ����� ������, � �� �� ��� ������������������ ��, �� ������ ��� ��������
				//��������������������� ������� - �������, ������� ����������� � dst

				for (const auto& src_used_register : src_used_registers) {
					if (current_call_from_stack.initialized_registers.find(src_used_register) == current_call_from_stack.initialized_registers.end()) {
						std::optional<double> value;
						try {
							value = get_variable_from_string(src_used_register, &ctx);
							if (value) {
								current_call_from_stack.used_registers_before_initialization[src_used_register] = std::to_string((int)value.value());
							}
							else {
								current_call_from_stack.used_registers_before_initialization[src_used_register] = "could not get value";
							}
						}
						catch (const std::exception&) {
							current_call_from_stack.used_registers_before_initialization[src_used_register] = "could not get value";
						}

					}
				}

				for (const auto& dst_used_register : dst_used_registers) {
					current_call_from_stack.initialized_registers.insert(dst_used_register);
				}
			}

			//��������� call � ������� ������� � ��� ����
			//�� ������
			if (this->passed_return) {
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(thread, &ctx);

				std::cout << "<RET> value: " << ctx.EAX << std::endl;
				std::cout << "PID: " << pid << " TID: " << tid << std::endl;
				if (this->call_stack.empty()) {
					std::cout << "Tried to pop empty stack!" << std::endl;
				}
				else {
					auto& current_call_from_stack = this->call_stack.top();
#ifdef _WIN64
					current_call_from_stack.returned_value = std::to_string(ctx.Rax);
#else
					current_call_from_stack.returned_value = std::to_string(ctx.Eax);
#endif
					this->PrintTopItemStackInfo();
					this->call_stack.pop();
				}
				this->passed_return = false;
			}

			if (assembly_string.rfind("CALL", 0) == 0) {
				std::cout << "PID: " << pid << " TID: " << tid << std::endl;
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(thread, &ctx);
				this->AddCallingStackItem(assembly_string, (Dword)info->ExceptionRecord.ExceptionAddress);
				PrintCallInstruction(ctx, (void*)info->ExceptionRecord.ExceptionAddress, assembly_string);
			}

			if (assembly_string.rfind("RET", 0) == 0) {
				std::cout << "PID: " << pid << " TID: " << tid << std::endl;
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(thread, &ctx);
				this->passed_return = true;
				PrintRetInstruction(ctx, (void*)info->ExceptionRecord.ExceptionAddress, assembly_string);
			}

			if (assembly_string.rfind("DIV", 0) == 0 || assembly_string.rfind("IDIV", 0) == 0) {
				std::cout << "PID: " << pid << " TID: " << tid << std::endl;
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(thread, &ctx);
				PrintDiv(assembly_string, &ctx);
				PrintRegisterContext(&ctx);
			}
			delete[] buf;
		}

		break;
	}

	default:
	{
		std::cout << "Unhandled exception @ " << info->ExceptionRecord.ExceptionAddress << std::endl;

		buf = new char[16];
		ReadProcessMemory(this->debugee_handle, info->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
		DisasInstruction((unsigned char*)buf, 16, (unsigned int)info->ExceptionRecord.ExceptionAddress, assembly_buffer, hex_buffer);
		std::cout << "Instruction: " << assembly_buffer << std::endl;

		delete[] buf;
		CloseHandle(thread);
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	}
	CloseHandle(thread);
	return DBG_EXCEPTION_HANDLED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Debugger::InsertDLL(void* addr, std::wstring name) {
	this->dll[addr] = name;
}

void Debugger::DeleteDLL(void* addr) {
	this->dll.erase(addr);
}

void Debugger::SetBreakpoint(void* addr, BreakPointType type, BreakPoint* prev) {
	if (this->breakpoints.find(addr) != this->breakpoints.end()) {
		return;
	}

	char saveByte = 0;
	ReadProcessMemory(this->debugee_handle, (PVOID)addr, &saveByte, 1, NULL);
	WriteProcessMemory(this->debugee_handle, (PVOID)addr, "\xCC", 1, NULL);
	FlushInstructionCache(this->debugee_handle, (PVOID)addr, 1);
	this->breakpoints[addr] = BreakPoint{addr, type, saveByte, prev};
}

void Debugger::SetTracingFunctionsBreakpoints() {
	for (const auto& [name, _] : tracing_functions_with_args) {
		FARPROC address = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), name.c_str());
		SetBreakpoint((void*)address, TRACING_FUNCTION_BREAKPOINT, nullptr);
		tracing_functions[address] = name;
		std::cout << "Found function " << name << " @ " << address << std::endl;
		std::cout << "Breakpoint set!" << std::endl;
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////---������ � �������---///////////////////////////////////////////////////

void Debugger::PrintRegisterContext(CONTEXT* ctx) {
#ifdef _WIN64
	std::cout << "RAX: " << ctx->Rax << std::endl;
	std::cout << "RBX: " << ctx->Rbx << std::endl;
	std::cout << "RCX: " << ctx->Rcx << std::endl;
	std::cout << "RDX: " << ctx->Rdx << std::endl;
	std::cout << "RSI: " << ctx->Rsi << std::endl;
	std::cout << "RDI: " << ctx->Rdi << std::endl;
	std::cout << "RSP: " << ctx->Rsp << std::endl;
	std::cout << "RBP: " << ctx->Rbp << std::endl;
	std::cout << "RIP: " << ctx->Rip << std::endl;
	std::cout << "R8: " << ctx->R8 << std::endl;
	std::cout << "R9: " << ctx->R9 << std::endl;
	std::cout << "R10: " << ctx->R10 << std::endl;
	std::cout << "R11: " << ctx->R11 << std::endl;
	std::cout << "R12: " << ctx->R12 << std::endl;
	std::cout << "R13: " << ctx->R13 << std::endl;
	std::cout << "R14: " << ctx->R14 << std::endl;
	std::cout << "R15: " << ctx->R15 << std::endl;
#else
	std::cout << "EAX: " << ctx->Eax << std::endl;
	std::cout << "EBX: " << ctx->Ebx << std::endl;
	std::cout << "ECX: " << ctx->Ecx << std::endl;
	std::cout << "EDX: " << ctx->Edx << std::endl;
	std::cout << "ESI: " << ctx->Esi << std::endl;
	std::cout << "EDI: " << ctx->Edi << std::endl;
	std::cout << "ESP: " << ctx->Esp << std::endl;
	std::cout << "EBP: " << ctx->Ebp << std::endl;
	std::cout << "EIP: " << ctx->Eip << std::endl;
#endif
}

void Debugger::PrintFunctionCall(const std::string& name, std::vector<size_t> arguments, size_t result) {
	std::cout << "Traced function called: " << name.c_str() << std::endl;
	std::vector<std::string> formatted_args;

	auto format = [](std::string name, std::string value) {
		std::stringstream s;
		s << name << "\tValue: " << value;
		return s.str();
	};

	const auto args = tracing_functions_with_args.find(name);
	if (args != tracing_functions_with_args.end()) {
		unsigned int i = 0;
		for (const auto arg : args->second) {
			formatted_args.push_back(format(arg, std::to_string(arguments[i])));
			i++;
		}
	}

	std::cout << "Arguments:" << std::endl;
	for (size_t i = 0; i < formatted_args.size(); ++i) {
		std::cout << "Argument # " << i << ": " << formatted_args[i] << std::endl;
	}

	std::cout << "Return value: " << result << std::endl;
}

void Debugger::PrintCallInstruction(CONTEXT ctx, void* address, const std::string& inst) {
	const size_t arguments_count = 6;
	std::cout << "CALL @ " << address << "!" << std::endl;
	std::cout << inst.c_str() << std::endl;

	std::vector<size_t> args;
#ifdef _WIN64
	for (size_t i = 0; i < arguments_count; ++i) {
		switch (i) {
		case 0:
		{
			args.push_back(ctx.Rcx);
			break;
		}
		case 1:
		{
			args.push_back(ctx.Rdx);
			break;
		}
		case 2:
		{
			args.push_back(ctx.R8);
			break;
		}
		case 3:
		{
			args.push_back(ctx.R9);
			break;
		}
		default:
		{
			size_t value;
			ReadProcessMemory(this->debugee_handle, (LPCVOID)(ctx.ESP + (i) * sizeof(size_t)), &value, sizeof(size_t), nullptr);
			args.push_back(value);
		}
		}
	}
#else
	size_t value;
	for (size_t i = 0; i < arguments_count; ++i) {
		value = 0;
		ReadProcessMemory(this->debugee_handle, (LPCVOID)(ctx.ESP + (i) * sizeof(size_t)), &value, sizeof(size_t), nullptr);
		args.push_back(value);
	}
#endif
	std::cout << "Possible arguments: " << std::endl;
	for (size_t i = 0; i < args.size(); ++i) {
		std::cout << "Argument # " << i << ": " << args[i] << std::endl;
	}
}

void Debugger::PrintRetInstruction(CONTEXT ctx, void* address, const std::string& inst) {
	size_t value;
	ReadProcessMemory(this->debugee_handle, (LPCVOID)(ctx.ESP), &value, sizeof(size_t), nullptr);

	std::cout << "RET @ " << address << "!" << std::endl;
	std::cout << inst.c_str() << std::endl;
	std::cout << "Returning -> " << ctx.EAX << std::endl;
}

void Debugger::PrintCallingStack() {
	auto copy = this->call_stack;
	while (!copy.empty()) {
		std::cout << copy.top().call_instruction << " @ " << copy.top().call_address << std::endl;
		copy.pop();
	}
}

void Debugger::PrintDiv(const std::string& str, const CONTEXT* ctx) {
	const std::regex checker = std::regex(R"([DIV]+\s+(.*)(0X\d*)?(.*))");
	std::smatch matches;

	if (str.find('[') != std::string::npos) {
		const auto first_pos = str.find('[');
		const auto last_pos = str.find(']');
		Expr expr = Expr(str.substr(first_pos + 1, last_pos - first_pos - 1));

		try {
			const auto result = (Dword)expr.calc(ctx);
			std::stringstream stream;
			stream << std::hex << result;
			std::string hexed(stream.str());
			std::cout << str + " -> " + str.substr(0, 4) + " [ 0x" + hexed + " ]";
		}
		catch (const std::exception&) {
			std::cout << str + " -> unable to calculate the value!";
		}
	}
	else if (std::regex_search(str, matches, checker)) {
		const std::string copy = str.substr(4);
		Expr expr = Expr(copy);

		try {
			const auto result = (Dword)expr.calc(ctx);
			std::stringstream stream;
			stream << std::hex << result;
			std::string hexed(stream.str());
			std::cout << str + " -> 0x" + hexed << std::endl;
		}
		catch (const std::exception&) {
			std::cout << str + " -> unable to calculate the value!";
		}
	}
	else {
		std::cout << str << std::endl;
	}
}

void Debugger::PrintTopItemStackInfo() {
	const auto& top = this->call_stack.top();
	std::cout << "-------------------CALL INFO-------------------" << std::endl;
	std::cout << "Function was called by this instruction: " << top.call_instruction;
	std::cout << " @ " << top.call_address << std::endl;

	std::cout << "Max EBP offset: " << top.current_max_ebp_offset << std::endl;
	std::cout << "EBP offsets values : " << std::endl;
	for (const auto& [offset, value] : top.values_on_ebp_offsets) {
		std::cout << offset << " -> " << std::hex << value << std::endl;
	}
	std::cout << "Registers that were used before initialization (probably arguments): " << std::endl;
	for (const auto& [reg, value] : top.used_registers_before_initialization) {
		std::cout << reg << " -> " << value << std::endl;
	}

	if (top.current_call_accessed_less_than_8_bytes_ebp) {
		std::cout << "Function's stack frame is not aligned" << std::endl;
	}

	std::cout << "After return EAX contains: " << top.returned_value << std::endl;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Debugger::AddCallingStackItem(const std::string call_instrtuction, const Dword address_of_call_inst) {
	CallInformation ci;
	ci.call_address = address_of_call_inst;
	ci.call_instruction = call_instrtuction;
	this->call_stack.push(ci);
}

void Debugger::ParseArgumentsOfMyTracingFunctions(const Dword tid, const std::string& name) {
	CONTEXT ctx = {0};
	HANDLE thread = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(thread, &ctx);

	unsigned int current_argument_number = 0;
	const auto& [function_name, arguments] = *tracing_functions_with_args.find(name);

	for (const auto& argument : arguments) {
		auto type_with_name = split(argument, " ");
		std::transform(
			type_with_name.begin(),
			type_with_name.end(),
			type_with_name.begin(),
			strip
		);
		std::string type = type_with_name[0];
		const std::string argument_name = type_with_name[1];
		bool is_pointer = type.rfind("LP", 0) == 0;
		if (is_pointer) {
			type = type.substr(2, type.length());
		}
		const auto& [_, members_and_treating] = *entities.find(type);
		const auto& members = members_and_treating.first;
		const auto treating = members_and_treating.second;

		switch (treating) {
		case treat_variant::number:
		{
			Dword number, bytes_read;
			std::cout << type << " " << argument_name << " = ";
#ifdef _WIN64
			switch (current_argument_number) {
			case 0:
			{
				std::cout << ctx.Rcx << std::endl;
				break;
			}
			case 1:
			{
				std::cout << ctx.Rdx << std::endl;
				break;
			}
			case 2:
			{
				std::cout << ctx.R8 << std::endl;
				break;
			}
			case 3:
			{
				std::cout << ctx.R9 << std::endl;
				break;
			}
			default:
			{
				size_t value;
				ReadProcessMemory(
					this->debugee_handle,
					(LPCVOID)(ctx.ESP + (current_argument_number) * sizeof(size_t)),
					&value,
					sizeof(size_t),
					nullptr
				);
				std::cout << value << std::endl;
				break;
			}
			}
#else
			size_t value;
			ReadProcessMemory(
				this->debugee_handle,
				(LPCVOID)(ctx.ESP + (current_argument_number) * sizeof(size_t)),
				&value,
				sizeof(size_t),
				nullptr
			);
			std::cout << value << std::endl;
#endif // _WIN64
			break;
		}
		default:
			break;
		}

		current_argument_number++;
	}
}

void Debugger::ParseArguments(Dword tid, const std::string& name) {
	CONTEXT ctx = { 0 };
	HANDLE thread = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(thread, &ctx);

	size_t ret_addr = { 0 };
	std::vector<size_t> args;
	ReadProcessMemory(this->debugee_handle, (LPCVOID)ctx.ESP, &ret_addr, sizeof(size_t), nullptr);

#ifdef _WIN64
	//https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-160
	for (size_t i = 0; i < tracing_functions_with_args.at(name).size(); ++i) {
		switch (i) {
		case 0:
		{
			args.push_back(ctx.Rcx);
			break;
		}
		case 1:
		{
			args.push_back(ctx.Rdx);
			break;
		}
		case 2:
		{
			args.push_back(ctx.R8);
			break;
		}
		case 3:
		{
			args.push_back(ctx.R9);
			break;
		}
		default:
		{
			size_t value;
			ReadProcessMemory(this->debugee_handle, (LPCVOID)(ctx.ESP + (i + 1) * sizeof(size_t)), &value, sizeof(size_t), nullptr);
			args.push_back(value);
		}
		}
	}
#else
	size_t value;
	for (size_t i = 0; i < tracing_functions_with_args.at(name).size(); ++i) {
		value = 0;
		ReadProcessMemory(this->debugee_handle, (LPCVOID)(ctx.ESP + (i + 1) * sizeof(size_t)), &value, sizeof(size_t), nullptr);
		args.push_back(value);
	}
#endif
	this->function_calls[(void*)ret_addr] = FunctionCall{ name, args };
	SetBreakpoint((void*)ret_addr, FUNCTION_RETURN_BREAKPOINT, nullptr);

	CloseHandle(thread);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////