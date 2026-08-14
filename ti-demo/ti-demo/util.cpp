#include <Windows.h>
#include <sddl.h>
#include <string>
#include "../../w32oop/w32use.hpp"
using namespace std;


// 功能：提取命令行
wstring util_提取命令行(int argc, WCHAR** argv, int start) {
	wstring cmdLine;

	for (int i = start; i < argc; i++) {
		wstring argWide = (argv[i]);
		if (i != start) cmdLine += L" ";
		bool shouldQuote = argWide.find_first_of(L" ") != wstring::npos || argWide.find_first_of(L"\t") != wstring::npos;
		if (argWide.find(L"\"") != wstring::npos) {
			argWide = w32oop::util::str::operations::replace(argWide, L"\"", L"\"\"");
			shouldQuote = true;
		}
		// 参数中包含空格或制表符时，用双引号括起来
		if (shouldQuote) {
			cmdLine += L"\"";
			cmdLine += argWide;
			cmdLine += L"\"";
		}
		else {
			cmdLine += argWide;
		}
	}

	return cmdLine;
}


// 功能：检查是不是SYSTEM权限
bool util_是否是SYSTEM() {
	HANDLE hToken = nullptr;
	// 打开自身进程令牌，需要TOKEN_QUERY权限
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		__fastfail(2);
	}
	DWORD cbNeeded = 0;
	// 第一次调用获取需要的缓冲区大小
	GetTokenInformation(hToken, TokenUser, nullptr, 0, &cbNeeded);
	auto spBuf = make_unique<BYTE[]>(cbNeeded);
	PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(spBuf.get());
	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, cbNeeded, &cbNeeded)) {
		CloseHandle(hToken);
		__fastfail(2);
	}
	PSID pSystemSid = nullptr;
	SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
	// S‑1‑5‑18：子授权只有1个，值18
	if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
		CloseHandle(hToken);
		__fastfail(2);
	}
	bool bIsSystem = ::EqualSid(pTokenUser->User.Sid, pSystemSid);
	FreeSid(pSystemSid);
	CloseHandle(hToken);
	return bIsSystem;
}


// 功能：打开所有特权。
BOOL util_打开所有特权(HANDLE hToken) {
	BOOL bResult = FALSE;
	HANDLE hTokenLocal = nullptr;
	DWORD dwTokenInfoSize = 0;
	PTOKEN_PRIVILEGES pTokenPrivileges = nullptr;

	// 处理令牌句柄
	if (hToken == nullptr) {
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTokenLocal)) {
			return FALSE;
		}
		hToken = hTokenLocal;
	}

	// 获取所需缓冲区大小
	if (!GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &dwTokenInfoSize) &&
		GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		goto cleanup;
	}

	// 分配权限信息缓冲区
	pTokenPrivileges = reinterpret_cast<PTOKEN_PRIVILEGES>(malloc(dwTokenInfoSize));
	if (!pTokenPrivileges) {
		goto cleanup;
	}

	// 获取实际权限信息
	if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwTokenInfoSize, &dwTokenInfoSize)) {
		goto cleanup;
	}

	// 启用所有权限
	bResult = TRUE;
	for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; ++i) {
		LUID_AND_ATTRIBUTES& la = pTokenPrivileges->Privileges[i];
		TOKEN_PRIVILEGES tp = { 1, { { la.Luid, SE_PRIVILEGE_ENABLED } } };

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
			bResult = FALSE;
		}
		else if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
			bResult = FALSE;
		}
	}

cleanup:
	if (pTokenPrivileges) free(pTokenPrivileges);
	if (hTokenLocal) CloseHandle(hTokenLocal);
	return bResult;
}

