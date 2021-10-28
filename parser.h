#pragma once
#include <string>
#include <vector>
#include <stack>
#include <algorithm>
#include <map>
#include <iostream>
#include <functional>
#include <regex>
#include <optional>

#include <Windows.h>

class Expr {
public:
	Expr(const std::string& s);
	void extractTerms();
	double calc(const CONTEXT* ctx);
	void printPol();

private:
	std::string s;
	bool isDelim(const char ch);
	void toPol();

	enum class termTypes { var, constant, openBracket, closeBracket, operation };
	std::vector<std::pair<termTypes, std::string>> parsedTerms;
	std::vector<std::pair<termTypes, std::string>> pol;

	const std::string delims = " +-*";
	static const std::map<std::string, unsigned int> priors;
	static std::map<std::string, std::function<double(std::stack<double>&)>> funcs;
};

std::optional<double> get_variable_from_string(const std::string& str, const CONTEXT* ctx);
