#include <iostream>

#include "debugger.h"

bool is_number(const std::wstring& s) {
	auto it = s.begin();
	while (it != s.end() && std::isdigit(*it)) ++it;
	return !s.empty() && it == s.end();
}

int main(int argc, char** argv) {
	LPWSTR* szArglist;
	int nArgs;
	int i;

	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);

	Debugger debugger;

	if (!szArglist) {
		throw new std::exception("CommandLineToArgvW failed");
		return 1;
	}
	else {
		for (i = 1; i < nArgs; i++) {
			if (wcscmp(szArglist[i], L"-t") == 0) {
				debugger.Tracing(true);
			}
			else if (wcscmp(szArglist[i], L"-tb") == 0) {
				debugger.BaseTracing(true);
			}
			else if (wcscmp(szArglist[i], L"-f") == 0) {
				debugger.Functions(true);
			}
			else if (wcscmp(szArglist[i], L"-l") == 0) {
				debugger.Libs(true);
			}
			else if (wcscmp(szArglist[i], L"-d") == 0) {
				if (szArglist[i + 1]) {
					if (is_number(szArglist[i + 1])) {
						if (!debugger.Target(std::stoi(szArglist[i + 1]))) {
							std::cout << "Could not attach to process" << std::endl;
							return 1;
						}
						i++;
					}
					else {
						if (!debugger.Target(szArglist[i + 1])) {
							std::cout << "Could not attach to process" << std::endl;
							return 2;
						}
						i++;
					}
				}
			}
		}
	}


	debugger.Debug();


	return 0;
}
