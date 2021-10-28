#pragma once

#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <psapi.h>
#include <strsafe.h>

#include <string>
#include <list>
#include <vector>
#include <map>
#include <stack>
#include <filesystem>
#include <fstream>
#include <set>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <sstream>

#include "Command.h"
#include "parser.h"
#include "disas.h"


typedef unsigned long long Dword;

#ifdef _AMD64_
#define EAX Rax
#define EIP Rip
#define ESP Rsp
#include <ntstatus.h>
#else
#define EAX Eax
#define EIP Eip
#define ESP Esp
#endif


enum BreakPointType {
	TRACING_FUNCTION_BREAKPOINT = 0,
	SAVE_BREAKPOINT,
	INITIAL_BREAKPOINT,
	FUNCTION_RETURN_BREAKPOINT,
	LIB_FUNCTION_BREAKPOINT
};

struct BreakPoint {
	void* addr;
	BreakPointType type;
	char saved_byte;
	BreakPoint* prev;
};

struct FunctionCall {
	std::string name;
	std::vector<size_t> arguments;
};

struct LibFunctionBreakpoint {
	std::wstring lib_name;
	std::string function_name;
	void* addr;
};

struct CallInformation {
	unsigned int current_max_ebp_offset; //�������, ����� ����� ������������ ��������� ���� � ���������� �� ���������� (ebp + 8, ��������) -> 8
	std::map<int, Dword> values_on_ebp_offsets;
	std::map<std::string, std::string> used_registers_before_initialization; //����� �������� �������������� �� ����, ��� � ��� ���-�� �������� (��������� ����� ��������)
	std::set<std::string> initialized_registers; //� ����� �������� ����� �������� (��� ������������ ������� �������)
	bool current_call_accessed_less_than_8_bytes_ebp; //������ ����� ������, ���� �� ������������ ��� ���
	std::string call_instruction; //����� ����������� ������� call
	Dword call_address; //����� �������
	std::string returned_value; //��, ��� ����� return ����� � [E|R]AX

	CallInformation() {
		current_call_accessed_less_than_8_bytes_ebp = false;
		current_max_ebp_offset = 0;
	}
};

const std::map<std::string, std::vector<std::string>> tracing_functions_with_args = {
	{"CreateProcessA", {
		"LPCSTR lpApplicationName", //done
		"LPSTR lpCommandLine", //done
		"LPSECURITY_ATTRIBUTES lpProcessAttributes", //done
		"LPSECURITY_ATTRIBUTES lpThreadAttributes", //done
		"BOOL bInheritHandles", //done
		"DWORD dwCreationFlags", //done
		"LPVOID lpEnvironment",
		"LPCSTR lpCurrentDirectory", //done
		"LPSTARTUPINFOA lpStartupInfo", //done
		"LPPROCESS_INFORMATION lpProcessInformation" //done
}},
	{"CreateProcessW", {
		"LPCWSTR lpApplicationName", //done
		"LPWSTR lpCommandLine", //done
		"LPSECURITY_ATTRIBUTES lpProcessAttributes", //done
		"LPSECURITY_ATTRIBUTES lpThreadAttributes", //done
		"BOOL bInheritHandles", //done
		"DWORD dwCreationFlags", //done
		"LPVOID lpEnvironment",
		"LPCWSTR lpCurrentDirectory", //done
		"LPSTARTUPINFOW lpStartupInfo", //done
		"LPPROCESS_INFORMATION lpProcessInformation" //done
}},
	{"CreateProcessAsUserA", {
		"HANDLE hToken", //done
		"LPCSTR lpApplicationName", //done
		"LPSTR lpCommandLine", //done
		"LPSECURITY_ATTRIBUTES lpProcessAttributes", //done
		"LPSECURITY_ATTRIBUTES lpThreadAttributes", //done
		"BOOL bInheritHandles", //done
		"DWORD dwCreationFlags", //done
		"LPVOID lpEnvironment",
		"LPCSTR lpCurrentDirectory", //done
		"LPSTARTUPINFOA lpStartupInfo", //done
		"LPPROCESS_INFORMATION lpProcessInformation" //done
}},
	{"ExitProcess", {
		"UINT uExitCode", //done
}},
	{"TerminateProcess", {
		"HANDLE hProcess", //done
		"UINT uExitCode", //done
}}
};

enum class treat_variant {
	entity,
	number,
	string,
	wstring,
	boolean,
	byte
};

const std::map<std::string, std::pair<std::vector<std::string>, treat_variant>> entities = {
	{"HANDLE", {{}, treat_variant::number}},
	{"UINT", {{}, treat_variant::number}},
	{"CSTR", {{}, treat_variant::string}},
	{"DWORD", {{}, treat_variant::number}},
	{"BOOL", {{}, treat_variant::boolean}},
	{"BYTE", {{}, treat_variant::byte}},
	{"LPCWSTR", {{}, treat_variant::wstring}},
	{"PROCESS_INFORMATION", {{
		"HANDLE hProcess",
		"HANDLE hThread",
		"DWORD  dwProcessId",
		"DWORD  dwThreadId"
	}, treat_variant::entity}},
	{"STARTUPINFOA", {{
		"DWORD  cb",
		"LPSTR  lpReserved",
		"LPSTR  lpDesktop",
		"LPSTR  lpTitle",
		"DWORD  dwX",
		"DWORD  dwY",
		"DWORD  dwXSize",
		"DWORD  dwYSize",
		"DWORD  dwXCountChars",
		"DWORD  dwYCountChars",
		"DWORD  dwFillAttribute",
		"DWORD  dwFlags",
		"WORD   wShowWindow",
		"WORD   cbReserved2",
		"LPBYTE lpReserved2",
		"HANDLE hStdInput",
		"HANDLE hStdOutput",
		"HANDLE hStdError"
	}, treat_variant::entity}},
	{"SECURITY_ATTRIBUTES", {{
		"DWORD �nLength",
		"LPVOID lpSecurityDescriptor",
		"BOOL ��bInheritHandle",
	}, treat_variant::entity}},
	{"STARTUPINFOW", {{
		"DWORD  cb",
		"LPWSTR lpReserved",
		"LPWSTR lpDesktop",
		"LPWSTR lpTitle",
		"DWORD  dwX",
		"DWORD  dwY",
		"DWORD  dwXSize",
		"DWORD  dwYSize",
		"DWORD  dwXCountChars",
		"DWORD  dwYCountChars",
		"DWORD  dwFillAttribute",
		"DWORD  dwFlags",
		"WORD   wShowWindow",
		"WORD   cbReserved2",
		"LPBYTE lpReserved2",
		"HANDLE hStdInput",
		"HANDLE hStdOutput",
		"HANDLE hStdError",
	}, treat_variant::entity}}
};

/*
������� ��������� ������� (��������)

{
	��������: {
		type1: {
			basic: bool //���� ����� ���������� ��� ������ ����������
			size: Dword
		}
	}
}

���������� �� �������� ��� LP � ������, ��� ����� ����������� ���������


����� ����� ������� ���������, ���� � ���������� ������� � ��� �����������
�����-�� ���, ������� ����� � ���������, ��:
1.
*/

class Debugger {
private:
	bool tracing;
	bool lib_tracing;
	bool fun_tracing;
	bool passed_return;
	bool debugging;
	HANDLE debugee_handle;

	std::map<void*, std::wstring> dll;
	std::vector<Dword> threads;
	std::map<void*, BreakPoint> breakpoints;
	std::map<void*, std::string> tracing_functions;
	std::map<void*, FunctionCall> function_calls;
	std::map<void*, LibFunctionBreakpoint> lib_breakpoints;
	std::stack<CallInformation> call_stack;

	void EventCreateProcess(const Dword& pid, const Dword& tid, LPCREATE_PROCESS_DEBUG_INFO info);
	void EventExitProcess(const Dword& pid, const Dword& tid, LPEXIT_PROCESS_DEBUG_INFO info);
	void EventCreateThread(const Dword& pid, const Dword& tid, LPCREATE_THREAD_DEBUG_INFO info);
	void EventExitThread(const Dword& pid, const Dword& tid, LPEXIT_THREAD_DEBUG_INFO info);
	void EventLoadDll(const Dword& pid, const Dword& tid, LPLOAD_DLL_DEBUG_INFO info);
	void EventUnloadDll(const Dword& pid, const Dword& tid, LPUNLOAD_DLL_DEBUG_INFO info);
	void EventOutputDebugString(const Dword& pid, const Dword& tid, LPOUTPUT_DEBUG_STRING_INFO info);
	Dword EventException(const Dword& pid, const Dword& tid, LPEXCEPTION_DEBUG_INFO info);

	void InsertDLL(void* addr, std::wstring name);
	void DeleteDLL(void* addr);
	void SetBreakpoint(void* addr, BreakPointType type, BreakPoint* prev = nullptr);
	void SetTracingFunctionsBreakpoints();
	void PrintRegisterContext(CONTEXT* ctx);
	void ParseArguments(Dword tid, const std::string& name);
	void PrintFunctionCall(const std::string& name, std::vector<size_t> arguments, size_t result);
	void PrintCallInstruction(CONTEXT ctx, void* address, const std::string& inst);
	void PrintRetInstruction(CONTEXT ctx, void* address, const std::string& inst);
	void PrintCallingStack();
	void AddCallingStackItem(const std::string call_instrtuction, const Dword address_of_call_inst);
	void PrintDiv(const std::string& str, const CONTEXT* ctx);
	void PrintTopItemStackInfo();

	void ParseArgumentsOfMyTracingFunctions(const Dword tid, const std::string& name);

public:
	Debugger() {
		tracing = false;
		lib_tracing = false;
		fun_tracing = false;
		debugging = false;
		passed_return = false;
		debugee_handle = NULL;
		_debug_stream = std::ofstream("debug.txt", std::ios::out);
	}

	std::ofstream _debug_stream;
	void Tracing(const bool tracing);
	void Libs(const bool tracing);
	void Functions(const bool tracing);
	bool Target(const std::wstring& path);
	bool Target(const DWORD pid);


	void Debug();

	~Debugger() {}
};
