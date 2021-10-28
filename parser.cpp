#include "parser.h"

const std::map<std::string, unsigned int> Expr::priors = {
		{"+", 10}, {"-", 10}, {"*", 20}
};

double pop(std::stack<double>& s) {
	double res = s.top();
	s.pop();
	return res;
}

std::map<std::string, std::function<double(std::stack<double>&)>> Expr::funcs = {
	{"+", [](std::stack<double>& s) {return pop(s) + pop(s); }},
	{"-", [](std::stack<double>& s) {return -pop(s) + pop(s); }},
	{"*", [](std::stack<double>& s) {return pop(s) * pop(s); }},
};


Expr::Expr(const std::string& s) {
	this->s = s;
	extractTerms();
	toPol();
}

void Expr::extractTerms() {
	unsigned int i = 0;
	while (i < s.size()) {
		if (s[i] == ' ') {
			i++;
			continue;
		}
		std::string t;
		do {
			t += s[i++];
		} while (!isDelim(s[i - 1]) && i < s.size() && !isDelim(s[i]));
		parsedTerms.push_back({termTypes::operation, t});
	}

	for (unsigned int i = 0; i < parsedTerms.size(); i++) {
		char first = parsedTerms[i].second[0];
		if (std::isdigit(first)) {
			parsedTerms[i].first = termTypes::constant;
		}
		else if (first == '(') {
			parsedTerms[i].first = termTypes::openBracket;
		}
		else if (first == ')') {
			parsedTerms[i].first = termTypes::closeBracket;
		}
		else if (std::isalpha(first)) {
			parsedTerms[i].first = termTypes::var;
		}
	}
}

double Expr::calc(const CONTEXT* ctx) {
	std::stack<double> s;
	std::optional<double> value;
	for (const auto& [type, name] : pol) {
		switch (type) {
		case termTypes::constant:
			s.push(std::stod(name));
			break;
		case termTypes::var:
			value = get_variable_from_string(name, ctx);
			if (value) {
				s.push(value.value());
			}
			else {
				throw std::exception("");
			}
			break;
		case termTypes::operation:
			s.push(funcs[name](s));
			break;

		default:
			break;
		}
	}

	return s.top();
}

void Expr::printPol() {
	for (const auto& [type, name] : pol) {
		std::cout << name << " ";
	}
	std::cout << std::endl;
}

bool Expr::isDelim(const char ch) {
	return std::find(delims.begin(), delims.end(), ch) != delims.end();
}

void Expr::toPol() {
	std::stack<std::pair<termTypes, std::string>> s;
	for (const auto& term : parsedTerms) {
		switch (term.first) {

		case termTypes::constant:
		case termTypes::var:
			pol.push_back(term);
			break;

		case termTypes::openBracket:
			s.push(term);
			break;

		case termTypes::closeBracket:
			while (s.top().first != termTypes::openBracket) {
				pol.push_back(s.top());
				s.pop();
			}
			s.pop();
			break;

		case termTypes::operation:
			while (!s.empty() && (s.top().first == termTypes::operation
				&& priors.find(s.top().second)->second >= priors.find(term.second)->second)) {
				pol.push_back(s.top());
				s.pop();
			}
			s.push(term);
			break;
		}
	}

	while (!s.empty()) {
		pol.push_back(s.top());
		s.pop();
	}

}

std::optional<double> get_variable_from_string(const std::string& str, const CONTEXT* ctx) {
#ifdef _AMD64_
	if (str == "RAX") return ctx->Rax;
	if (str == "EAX") return ctx->Rax & 0x00000000FFFFFFFF;
	if (str == "AX") return ctx->Rax & 0x000000000000FFFF;
	if (str == "AL") return ctx->Rax & 0x00000000000000FF;
	if (str == "AH") return ctx->Rax & 0x000000000000FF00;

	if (str == "RBX") return ctx->Rbx;
	if (str == "EBX") return ctx->Rbx & 0x00000000FFFFFFFF;
	if (str == "BX") return ctx->Rbx & 0x000000000000FFFF;
	if (str == "BL") return ctx->Rbx & 0x00000000000000FF;
	if (str == "BH") return ctx->Rbx & 0x000000000000FF00;

	if (str == "RCX") return ctx->Rcx;
	if (str == "ECX") return ctx->Rcx & 0x00000000FFFFFFFF;
	if (str == "CX") return ctx->Rcx & 0x000000000000FFFF;
	if (str == "CL") return ctx->Rcx & 0x00000000000000FF;
	if (str == "CH") return ctx->Rcx & 0x000000000000FF00;

	if (str == "RDX") return ctx->Rdx;
	if (str == "EDX") return ctx->Rdx & 0x00000000FFFFFFFF;
	if (str == "DX") return ctx->Rdx & 0x000000000000FFFF;
	if (str == "DL") return ctx->Rdx & 0x00000000000000FF;
	if (str == "DH") return ctx->Rdx & 0x000000000000FF00;

	if (str == "RSI") return ctx->Rsi;
	if (str == "RDI") return ctx->Rdi;
	if (str == "RSP") return ctx->Rsp;
	if (str == "RBP") return ctx->Rbp;
	if (str == "RIP") return ctx->Rip;

	if (str == "ESI") return ctx->Rsi & 0x00000000FFFFFFFF;
	if (str == "EDI") return ctx->Rdi & 0x00000000FFFFFFFF;
	if (str == "ESP") return ctx->Rsp & 0x00000000FFFFFFFF;
	if (str == "EBP") return ctx->Rbp & 0x00000000FFFFFFFF;
	if (str == "EIP") return ctx->Rip & 0x00000000FFFFFFFF;

	if (str == "R8") return ctx->R8;
	if (str == "R8D") return ctx->R8 & 0x00000000FFFFFFFF;
	if (str == "R8W") return ctx->R8 & 0x000000000000FFFF;
	if (str == "R8B") return ctx->R8 & 0x00000000000000FF;
	
	if (str == "R9") return ctx->R9;
	if (str == "R9D") return ctx->R9 & 0x00000000FFFFFFFF;
	if (str == "R9W") return ctx->R9 & 0x000000000000FFFF;
	if (str == "R9B") return ctx->R9 & 0x00000000000000FF;

	if (str == "R10") return ctx->R10;
	if (str == "R10D") return ctx->R10 & 0x00000000FFFFFFFF;
	if (str == "R10W") return ctx->R10 & 0x000000000000FFFF;
	if (str == "R10B") return ctx->R10 & 0x00000000000000FF;

	if (str == "R11") return ctx->R11;
	if (str == "R11D") return ctx->R11 & 0x00000000FFFFFFFF;
	if (str == "R11W") return ctx->R11 & 0x000000000000FFFF;
	if (str == "R11B") return ctx->R11 & 0x00000000000000FF;

	if (str == "R12") return ctx->R12;
	if (str == "R12D") return ctx->R12 & 0x00000000FFFFFFFF;
	if (str == "R12W") return ctx->R12 & 0x000000000000FFFF;
	if (str == "R12B") return ctx->R12 & 0x00000000000000FF;

	if (str == "R13") return ctx->R13;
	if (str == "R13D") return ctx->R13 & 0x00000000FFFFFFFF;
	if (str == "R13W") return ctx->R13 & 0x000000000000FFFF;
	if (str == "R13B") return ctx->R13 & 0x00000000000000FF;

	if (str == "R14") return ctx->R14;
	if (str == "R14D") return ctx->R14 & 0x00000000FFFFFFFF;
	if (str == "R14W") return ctx->R14 & 0x000000000000FFFF;
	if (str == "R14B") return ctx->R14 & 0x00000000000000FF;

	if (str == "R15") return ctx->R15;
	if (str == "R15D") return ctx->R15 & 0x00000000FFFFFFFF;
	if (str == "R15W") return ctx->R15 & 0x000000000000FFFF;
	if (str == "R15B") return ctx->R15 & 0x00000000000000FF;
#else
	if (str == "EAX") return ctx->Eax;
	if (str == "AX") return ctx->Eax & 0x0000FFFF;
	if (str == "AL") return ctx->Eax & 0x000000FF;
	if (str == "AH") return ctx->Eax & 0x0000FF00;

	if (str == "EBX") return ctx->Ebx;
	if (str == "BX") return ctx->Ebx & 0x0000FFFF;
	if (str == "BL") return ctx->Ebx & 0x000000FF;
	if (str == "BH") return ctx->Ebx & 0x0000FF00;

	if (str == "ECX") return ctx->Ecx;
	if (str == "CX") return ctx->Ecx & 0x0000FFFF;
	if (str == "CL") return ctx->Ecx & 0x000000FF;
	if (str == "CH") return ctx->Ecx & 0x0000FF00;

	if (str == "EDX") return ctx->Edx;
	if (str == "DX") return ctx->Edx & 0x0000FFFF;
	if (str == "DL") return ctx->Edx & 0x000000FF;
	if (str == "DH") return ctx->Edx & 0x0000FF00;

	if (str == "ESI") return ctx->Esi;
	if (str == "EDI") return ctx->Edi;
	if (str == "ESP") return ctx->Esp;
	if (str == "EBP") return ctx->Ebp;
	if (str == "EIP") return ctx->Eip;
#endif // _AMD64_
	return {};
}
