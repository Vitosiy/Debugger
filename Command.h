#pragma once

#include <string> 
#include <set>
#include <vector>
#include <algorithm>
#include <functional>
#include <locale>
#include <regex>
#include <optional>

class Command {
public:
	Command(const std::string& str);
	std::set<std::string> src_used_registers();
	std::set<std::string> dst_used_registers();
	std::optional<int> get_ebp_offset();

private:
	//command src, dst
	//command op1, op2

	std::string command;
	std::string op1;
	std::string op2;

	bool contains_ebp_in_dst();
	bool contains_ebp_in_src();
	bool contains_ebp();

	static const inline std::set<std::string> words_to_remove = {
		"QWORD", "DWORD", "BYTE", "PTR", "[", "]"
	};
	static const inline std::regex register_regex = std::regex(R"(\s*([^0][A-Z1-589]+))");
	static const inline std::regex ebp_offset_getter = std::regex(R"([RE]BP\s*([-+]\s*[0X]*[\dA-F]+))");
};

std::vector<std::string> split(std::string s, std::string delimiter);
std::string strip(std::string in);
