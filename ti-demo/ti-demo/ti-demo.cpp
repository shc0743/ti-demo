#include <Windows.h>
#include <string>
#include <shlobj.h>
#include <ShObjIdl.h>
#include <Shlwapi.h>
#include "../../w32oop/w32use.hpp"
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
using namespace std;


wstring util_提取命令行(int argc, WCHAR** argv, int start);
bool util_是否是SYSTEM();
BOOL util_打开所有特权(HANDLE hToken = NULL);
inline int util_失败返回() { DWORD e = GetLastError(); if (e) return e; return 1; }
int ui();
int 一阶段(int argc, WCHAR** argv);
int 二阶段(int argc, WCHAR** argv);
int 三阶段(int argc, WCHAR** argv);

#define MYFAIL return util_失败返回()


int WINAPI wWinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR lpCmdLine,
	_In_ int nShowCmd
) {
	int argc{};
	WCHAR** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	w32oop::util::RAIIHelper _argv([&argv] {LocalFree(argv);});

	if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE))) return GetLastError();

	if (argc < 2) return ui();

	util_打开所有特权();

	// 检查权限
	if (!IsUserAnAdmin()) return 一阶段(argc, argv);

	// 获取 SeTcbPrivilege
	if (!util_是否是SYSTEM()) return 二阶段(argc, argv);

	// 在 TrustedInstaller 下创建进程
	return 三阶段(argc, argv);
}


// 功能：显示UI，询问用户要运行的内容
int ui() {
	u:
	InputDialog command(L"请输入文本", 500);
	command.create();
	command.setAcceptButtonText(L"运行");
	command.setRejectButtonText(L"取消");
	auto input = command.getInput<wstring>(L"输入要运行的程序命令行。");
	if (input.has_value()) {
		if (input.value().empty()) {
			MessageBoxW(NULL, L"空的输入！", NULL, MB_ICONERROR);
			goto u;
		}
		run:
		STARTUPINFOW si{ sizeof(si) };PROCESS_INFORMATION pi{};
		auto app = make_unique<WCHAR[]>(32768);
		auto cmd = make_unique<WCHAR[]>(32768);
		if (!GetModuleFileNameW(NULL, app.get(), 32768)) __fastfail(2);
		wstring v = L"_ "; // argv0需要一个占位符
		v += input.value();
		wcscpy_s(cmd.get(), 32768, v.c_str());
		if (!CreateProcessW(app.get(), cmd.get(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
			MessageBoxW(NULL, ErrorChecker().message().c_str(), 0, MB_ICONERROR);
			MYFAIL;
		}
		CloseHandle(pi.hThread);
		DWORD code{};
		WaitForSingleObject(pi.hProcess, INFINITE);
		GetExitCodeProcess(pi.hProcess, &code);
		CloseHandle(pi.hProcess);
		// UI进程：显示错误信息（如果有错误）
		if (code != 0) {
			int p = 0;
			TaskDialog(NULL, NULL, L"运行失败", format(L"运行结果：进程以代码 {} 退出。", code).c_str(), ErrorChecker(code).message().c_str(), TDCBF_CANCEL_BUTTON | TDCBF_RETRY_BUTTON, TD_ERROR_ICON, &p);
			if (p == IDRETRY) goto run;
		}
		return (int)code;
	}
	return 0;
}


// 功能：提权到管理员
int 一阶段(int argc, WCHAR** argv) {
	SHELLEXECUTEINFOW si{ sizeof(si) };
	auto app = make_unique<WCHAR[]>(32768);
	if (!GetModuleFileNameW(NULL, app.get(), 32768)) __fastfail(2);
	si.lpFile = app.get();
	auto params = util_提取命令行(argc, argv, 1); // strip argv[0], ShellExecute会加上
	si.lpParameters = params.c_str();
	si.lpVerb = L"runas";
	si.nShow = SW_SHOWDEFAULT;
	si.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
	if (!ShellExecuteExW(&si) || !si.hProcess) MYFAIL;
	DWORD code{};
	WaitForSingleObject(si.hProcess, INFINITE);
	GetExitCodeProcess(si.hProcess, &code);
	CloseHandle(si.hProcess);
	return (int)code;
}


// 功能：提到SYSTEM
// 当前权限：admin
int 二阶段(int argc, WCHAR** argv) {
	// 正常方法是创建临时服务，但是懒得折腾了，偷一个token得了
	w32ProcessHandle DcomLaunch;
	try {
		ServiceManager scm;
		auto svc = scm.get(L"DcomLaunch", SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
		SERVICE_STATUS_PROCESS ssp{};
		DWORD bytesNeeded = 0;
		BOOL ok = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);
		if (ok) {
			DcomLaunch = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION, 0, ssp.dwProcessId);
		}
	}
	catch (...) {
		MYFAIL;
	}

	STARTUPINFOEXW si{ sizeof(si) };
	PROCESS_INFORMATION pi{};
	std::unique_ptr<uint8_t[]> attributeList;
	auto app = make_unique<WCHAR[]>(32768);
	if (!GetModuleFileNameW(NULL, app.get(), 32768)) __fastfail(2);

	DWORD flags = CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;

	SIZE_T need{};
	InitializeProcThreadAttributeList(0, 1, 0, &need);
	HANDLE hRaw = DcomLaunch; // 重要
	bool ok = false;
	if (need && need < 32768) {
		attributeList = make_unique<uint8_t[]>(need);
		if (InitializeProcThreadAttributeList((PPROC_THREAD_ATTRIBUTE_LIST)attributeList.get(),
			1, 0, &need)) {
			if (UpdateProcThreadAttribute(
				(PPROC_THREAD_ATTRIBUTE_LIST)attributeList.get(), 0,
				PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
				&hRaw,
				sizeof(HANDLE),
				NULL, NULL
			)) ok = true;
		}
	}
	if (!ok) {
		if (attributeList) DeleteProcThreadAttributeList((PPROC_THREAD_ATTRIBUTE_LIST)attributeList.get());
		MYFAIL;
	}

	si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
	si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	si.StartupInfo.wShowWindow = SW_SHOWNORMAL;
	si.lpAttributeList = PPROC_THREAD_ATTRIBUTE_LIST(attributeList ? attributeList.get() : nullptr);

	DWORD current_session{}; ProcessIdToSessionId(GetCurrentProcessId(), &current_session);
	wstring newcmd = to_wstring(current_session) + L" " + util_提取命令行(argc, argv, 1);
	if (!CreateProcessW(app.get(), newcmd.data(), NULL, NULL, FALSE, flags, NULL, NULL, (LPSTARTUPINFOW)&si, &pi)) {
		if (attributeList) DeleteProcThreadAttributeList((PPROC_THREAD_ATTRIBUTE_LIST)attributeList.get());
		MYFAIL;
	}

	if (attributeList) DeleteProcThreadAttributeList((PPROC_THREAD_ATTRIBUTE_LIST)attributeList.get());
	DWORD code{};
	ResumeThread(pi.hThread);
	CloseHandle(pi.hThread);
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hProcess);
	return (int)code;
}


// 功能：在 TrustedInstaller 下创建进程
// 当前权限：SYSTEM
int 三阶段(int argc, WCHAR** argv) {
	if (argc < 2) return ERROR_INVALID_PARAMETER;

	// 先解析 session id
	DWORD sess = (DWORD)-1;
	try { sess = (DWORD)stoul(argv[0]); }
	catch (...) { sess = (DWORD)-1; }

	// 先打开 TrustedInstaller (然后需要尽快，因为它一段时间没事做会自己停止)
	w32ProcessHandle hTrustedInstaller;
	try {
		ServiceManager scm;
		auto ti = scm.get(L"TrustedInstaller");
		
		// 第一步，先看看服务是不是被禁用了（有的windows更新阻止器会禁用它）
		{
			DWORD cbNeed = 0;
			void(QueryServiceConfigW(ti, nullptr, 0, &cbNeed));
			auto pBuf = std::make_unique<BYTE[]>(cbNeed);
			LPQUERY_SERVICE_CONFIGW pCfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(pBuf.get());
			if (!QueryServiceConfigW(ti, pCfg, cbNeed, &cbNeed)) {
				MYFAIL;
			}
			if (pCfg->dwStartType == SERVICE_DISABLED) {
				ChangeServiceConfigW(ti, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
			}
		}

		// 第二步，看看服务是不是正在运行，没运行就启动
		DWORD dwServiceState = SERVICE_STOPPED;
		DWORD cbStatusBuf = sizeof(SERVICE_STATUS_PROCESS);
		auto pStatusBuf = std::make_unique<BYTE[]>(cbStatusBuf);
		SERVICE_STATUS_PROCESS* pSvcStatus = reinterpret_cast<SERVICE_STATUS_PROCESS*>(pStatusBuf.get());

		if (!QueryServiceStatusEx(ti, SC_STATUS_PROCESS_INFO, pStatusBuf.get(), cbStatusBuf, &cbStatusBuf)) {
			MYFAIL;
		}
		dwServiceState = pSvcStatus->dwCurrentState;
		DWORD dwTiPid = pSvcStatus->dwProcessId;

		if (dwServiceState != SERVICE_RUNNING) {
			// 启动TrustedInstaller服务
			if (!StartServiceW(ti, 0, nullptr)) {
				MYFAIL;
			}

			// 简单等待直到进入运行状态，带超时，TrustedInstaller启动会有延迟
			auto dwStartTick = GetTickCount64();
			const decltype(dwStartTick) dwMaxWaitMs = 10000;
			bool bGotPid = false;
			while ((GetTickCount64() - dwStartTick) < dwMaxWaitMs) {
				if (!QueryServiceStatusEx(ti, SC_STATUS_PROCESS_INFO, pStatusBuf.get(), cbStatusBuf, &cbStatusBuf)) {
					MYFAIL;
				}
				if (pSvcStatus->dwCurrentState == SERVICE_RUNNING && pSvcStatus->dwProcessId != 0) {
					dwTiPid = pSvcStatus->dwProcessId;
					bGotPid = true;
					break;
				}
				Sleep(100);
			}
			if (!bGotPid || dwTiPid == 0) {
				MYFAIL;
			}
		}

		// 第三步，打开服务进程句柄
		hTrustedInstaller = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, dwTiPid);
	}
	catch (...) {
		MYFAIL;
	}

	// 是否需要打开用户令牌以放到用户桌面运行？
	HANDLE hToken{};
	if (sess != DWORD(-1)) {
		HANDLE hTiToken{};
		if (!OpenProcessToken(hTrustedInstaller, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hTiToken)) {
			MYFAIL;
		}
		HANDLE hTiCopiedPrimaryToken = nullptr;
		// 获取主令牌
		if (!DuplicateTokenEx(hTiToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &hTiCopiedPrimaryToken)) {
			CloseHandle(hTiToken);
			MYFAIL;
		}
		CloseHandle(hTiToken);
		if (!SetTokenInformation(hTiCopiedPrimaryToken, TokenSessionId, (void*)&sess, sizeof(DWORD))) {
			CloseHandle(hTiCopiedPrimaryToken);
			MYFAIL;
		}
		// 输出结果
		hToken = hTiCopiedPrimaryToken;
	}
	w32oop::util::RAIIHelper _hToken([&hToken] {
		if (hToken) CloseHandle(hToken);
	});

	// 设置进程信息，然后创建进程
	STARTUPINFOEXW si{ sizeof(si) };
	PROCESS_INFORMATION pi{};
	std::unique_ptr<uint8_t[]> attributeList;

	DWORD flags = CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB | EXTENDED_STARTUPINFO_PRESENT;

	SIZE_T need{};
	bool ok = false;
	HANDLE hRawHandle = hTrustedInstaller; // 必须获取raw句柄，不然把包装器喂进去直接炸
	InitializeProcThreadAttributeList(0, 1, 0, &need);
	if (need && need < 32768) {
		attributeList = make_unique<uint8_t[]>(need);
		if (InitializeProcThreadAttributeList((PPROC_THREAD_ATTRIBUTE_LIST)attributeList.get(),
			1, 0, &need)) {
			if (UpdateProcThreadAttribute(
				(PPROC_THREAD_ATTRIBUTE_LIST)attributeList.get(), 0,
				PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
				&hRawHandle,
				sizeof(HANDLE),
				NULL, NULL
			)) {
				ok = true;
			}
		}
	}
	if (!ok) {
		MYFAIL;
	}

	si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
	si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	si.StartupInfo.wShowWindow = SW_SHOWNORMAL;
	si.lpAttributeList = PPROC_THREAD_ATTRIBUTE_LIST(attributeList ? attributeList.get() : nullptr);

	wstring cmd = util_提取命令行(argc, argv, 1);
	if (!(hToken ? 
		CreateProcessAsUserW(hToken, NULL, cmd.data(), NULL, NULL, FALSE, flags, NULL, NULL, (LPSTARTUPINFOW)&si, &pi) :
		CreateProcessW(NULL, cmd.data(), NULL, NULL, FALSE, flags, NULL, NULL, (LPSTARTUPINFOW)&si, &pi)
	)) {
		if (attributeList) DeleteProcThreadAttributeList((PPROC_THREAD_ATTRIBUTE_LIST)attributeList.get());
		MYFAIL;
	}
	if (attributeList) DeleteProcThreadAttributeList((PPROC_THREAD_ATTRIBUTE_LIST)attributeList.get());

	// 可等待也可以不等待，我们的demo中等待一会

	DWORD code{};
	ResumeThread(pi.hThread);
	CloseHandle(pi.hThread);
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hProcess);
	return (int)code;
}
