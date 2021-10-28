#include "Command.h"


std::vector<std::string> split(std::string s, std::string delimiter) {
	size_t pos_start = 0, pos_end, delim_len = delimiter.length();
	std::string token;
	std::vector<std::string> res;

	while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
		token = s.substr(pos_start, pos_end - pos_start);
		pos_start = pos_end + delim_len;
		res.push_back(token);
	}

	res.push_back(s.substr(pos_start));
	return res;
}

std::string strip(std::string in) {
	in.erase(
		std::remove_if(
			in.begin(),
			in.end(),
			[](std::string::value_type ch) { return isspace(ch); }
		),
		in.end()
	);

	return in;
}

void replace_all(std::string& str, const std::string& from, const std::string& to) {
	if (from.empty()) {
		return;
	}

	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
	}
}


Command::Command(const std::string& str) {
	std::string copy = str;
	for (const auto& to_remove : words_to_remove) {
		replace_all(copy, to_remove, "");
	}

	auto parts = split(copy, " ");
	std::transform(parts.begin(), parts.end(), parts.begin(), strip);
	command = parts[0];
	if (parts.size() == 1) {
		op1 = "";
		op2 = "";
	}
	if (parts.size() == 2) {
		op1 = parts[1];
		op2 = "";
	}
	else if (parts.size() == 3) {
		if (parts[1].empty()) {
			op1 = parts[2];
		}
		else {
			parts[1].pop_back();
			op1 = parts[1];
			op2 = parts[2];
		}
	}
}

std::set<std::string> Command::src_used_registers() {
	if (op1.length() == 0) {
		return std::set<std::string>();
	}
	try {
		std::stoull(op1);
		return std::set<std::string>();
	}
	catch (const std::exception&) {

	}

	std::set<std::string> result;

	std::smatch m;
	if (std::regex_search(op1, m, register_regex)) {
		for (const auto& match : m) {
			result.insert(match);
		}
	}

	return result;
}

std::set<std::string> Command::dst_used_registers() {
	if (op2.length() == 0) {
		return std::set<std::string>();
	}
	try {
		std::stoull(op2);
		return std::set<std::string>();
	}
	catch (const std::exception&) {

	}

	std::set<std::string> result;

	std::smatch m;
	if (std::regex_search(op2, m, register_regex)) {
		for (const auto& match : m) {
			result.insert(match);
		}
	}

	return result;
}

bool Command::contains_ebp() {
	return contains_ebp_in_dst() || contains_ebp_in_src();
}

std::optional<int> Command::get_ebp_offset() {
	if (contains_ebp()) {
		std::smatch m;
		if (std::regex_search(op2, m, ebp_offset_getter)) {
			return std::stoi(m[1], 0, 16);
		}
	}

	return {};
}

bool Command::contains_ebp_in_dst() {
	const auto result = dst_used_registers();
	return result.find("EBP") != result.end() || result.find("RBP") != result.end();
}

bool Command::contains_ebp_in_src() {
	const auto result = src_used_registers();
	return result.find("EBP") != result.end() || result.find("RBP") != result.end();
}
