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
#include <winternl.h>



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
	unsigned int current_max_ebp_offset; //—читаем, какое самое максимальное обращение было к переменным из аргументов (ebp + 8, допустим) -> 8
	std::map<int, Dword> values_on_ebp_offsets;
	std::map<std::string, std::string> used_registers_before_initialization; // акие регистры использовались до того, как в них что-то положили (аргументы через регистры)
	std::set<std::string> initialized_registers; //¬ какие регистры клали значени€ (дл€ отслеживани€ верхней строчки)
	bool current_call_accessed_less_than_8_bytes_ebp; //ѕросто чтобы узнать, есть ли выравнивание или нет
	std::string call_instruction; // акой инструкцией сделали call
	Dword call_address; //јдрес функции
	std::string returned_value; //“о, что после return нашли в [E|R]AX

	CallInformation() {
		current_call_accessed_less_than_8_bytes_ebp = false;
		current_max_ebp_offset = 0;
	}
};

const std::map<std::string, std::vector<std::string>> tracing_functions_with_args = {
	{"ZwQuerySystemInformation", {
		"SYSTEM_INFORMATION_CLASS SystemInformationClass",
		"PVOID SystemInformation",
		"ULONG SystemInformationLength", 
		"PULONG ReturnLength", 
	}}
}; 

const std::map<int, std::string> id_system_information_class = {
	{0, "SYSTEM_BASIC_INFORMATION"},
	{2, "SYSTEM_PERFORMANCE_INFORMATION"},
	{3, "SYSTEM_TIMEOFDAY_INFORMATION"},
	{5, "SYSTEM_PROCESS_INFORMATION"},
	{8, "SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION"},
	{23, "SYSTEM_INTERRUPT_INFORMATION"},
	{33, "SYSTEM_EXCEPTION_INFORMATION"},
	{37, "SYSTEM_REGISTRY_QUOTA_INFORMATION"},
	{45, "SYSTEM_LOOKASIDE_INFORMATION"},
};

const std::map<std::string, std::vector<std::string>> tracing_structures_with_args = {
	{"SYSTEM_BASIC_INFORMATION", {
		"BYTE Reserved1[24]",
		"PVOID Reserved2[4]",
		"CCHAR  NumberOfProcessors",
	}},
	{"SYSTEM_PERFORMANCE_INFORMATION", {
		"BYTE Reserved1[312]",
	}},
	{"SYSTEM_TIMEOFDAY_INFORMATION", {
		"BYTE Reserved1[48]",
	}},
	{"SYSTEM_PROCESS_INFORMATION", {
		"ULONG NextEntryOffset",
		"ULONG NumberOfThreads",
		"BYTE Reserved1[48]",
		"PVOID Reserved2[3]",
		"HANDLE UniqueProcessId",
		"PVOID Reserved3",
		"ULONG HandleCount",
		"BYTE Reserved4[4]",
		"PVOID Reserved5[11]",
		"SIZE_T PeakPagefileUsage",
		"SIZE_T PrivatePageCount",
		"LARGE_INTEGER Reserved6[6]"
	}},
	{"SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION", {
		"LARGE_INTEGER IdleTime",
		"LARGE_INTEGER KernelTime",
		"LARGE_INTEGER UserTime",
		"LARGE_INTEGER Reserved1[2]",
		"ULONG Reserved2",
	}},
	{"SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION", {
		"LARGE_INTEGER IdleTime",
		"LARGE_INTEGER KernelTime",
		"LARGE_INTEGER UserTime",
		"LARGE_INTEGER Reserved1[2]",
		"ULONG Reserved2",
	}},
	{"SYSTEM_INTERRUPT_INFORMATION", {
		"BYTE Reserved1[24]",
	}},
	{"SYSTEM_EXCEPTION_INFORMATION", {
		"BYTE Reserved1[16]",
	}},
	{"SYSTEM_REGISTRY_QUOTA_INFORMATION", {
		"ULONG RegistryQuotaAllowed",
		"ULONG RegistryQuotaUsed",
		"PVOID Reserved1",
	}},
	{"SYSTEM_LOOKASIDE_INFORMATION", {
		"BYTE Reserved1[32]",
	}},
};

enum class treat_variant {
	number,
	byte,
	pvoid_t,
	pulong_t,
	system_information,
	cchar
};

const std::map<std::string, std::pair<std::vector<std::string>, treat_variant>> entities = {
	{"SYSTEM_INFORMATION_CLASS", {{}, treat_variant::system_information}},
	{"PVOID", {{}, treat_variant::pvoid_t}},
	{"ULONG", {{}, treat_variant::number}},
	{"PULONG", {{}, treat_variant::pulong_t}},
	{"BYTE", {{}, treat_variant::byte}},
	{"LARGE_INTEGER", {{}, treat_variant::number}},
	{"CCHAR", {{}, treat_variant::cchar}},
	{"SIZE_T", {{}, treat_variant::number}},
};

/*
«авести структуру существ (структур)

{
	существо: {
		type1: {
			basic: bool //если стоит трактовать как просту переменную
			size: Dword
		}
	}
}

¬ыкидываем из названий все LP и прочее, это будет разбиратьс€ дебагером


 огда будем парсить аргументы, если в аргументах фунцкии у нас встречаетс€
какой-то тип, который лежит в существах, то:
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
	void ModificateThreadContext(HANDLE& thread, PVOID& exception_address, char saved_byte, CONTEXT& _ctx);
	void SetNextBreakpoint(PVOID& exception_address, char*& buf, char assembly_buffer[], char hex_buffer[], BreakPoint second);
	void DeleteDLL(void* addr);
	void SetBreakpoint(void* addr, BreakPointType type, BreakPoint* prev = nullptr);
	void SetTracingFunctionsBreakpoints();
	void PrintRegisterContext(CONTEXT* ctx);
	void PrintFunctionCall(const std::string& name, std::vector<size_t> arguments, size_t result);
	void PrintCallInstruction(CONTEXT ctx, void* address, const std::string& inst);
	void PrintRetInstruction(CONTEXT ctx, void* address, const std::string& inst);
	void PrintCallingStack();
	void AddCallingStackItem(const std::string call_instrtuction, const Dword address_of_call_inst);
	void PrintRor(const std::string& str, const CONTEXT* ctx);
	void PrintTopItemStackInfo();

	void ParseArgumentsOfMyTracingFunctions(const Dword tid, const std::string& name);
	void ParseArguments(const SIZE_T adress, const std::string& name, const std::string& searching_type);

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
