//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <Windows.h>
#include <intrin.h>

namespace winpriv
{
	class DynamicCodeScope final
	{
	public:
		DynamicCodeScope() noexcept
		{
			// Temporarily opt this thread out only when the process policy explicitly permits it.
			PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy{};
			if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &policy, sizeof(policy)))
			{
				result_ = GetLastError();
				return;
			}
			if (!policy.ProhibitDynamicCode || !policy.AllowThreadOptOut) return;
			if (!GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &threadPolicy_, sizeof(threadPolicy_)))
			{
				result_ = GetLastError();
				return;
			}
			if ((threadPolicy_ & THREAD_DYNAMIC_CODE_ALLOW) != 0) return;
			DWORD allowed = threadPolicy_ | THREAD_DYNAMIC_CODE_ALLOW;
			if (!SetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &allowed, sizeof(allowed)))
			{
				result_ = GetLastError();
				return;
			}
			restore_ = true;
		}

		DynamicCodeScope(const DynamicCodeScope&) = delete;
		DynamicCodeScope& operator=(const DynamicCodeScope&) = delete;
		~DynamicCodeScope() { Restore(); }

		LONG Result() const noexcept { return result_; }

		void Restore() noexcept
		{
			// Preserve the operation's error while restoring the caller's thread policy.
			if (!restore_) return;
			const DWORD previousError = GetLastError();
			if (!SetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &threadPolicy_, sizeof(threadPolicy_)))
			{
				const DWORD error = GetLastError();
				EXCEPTION_RECORD exception{};
				exception.ExceptionCode = HRESULT_FROM_WIN32(error);
				exception.ExceptionAddress = _ReturnAddress();
				exception.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
				exception.NumberParameters = 1;
				exception.ExceptionInformation[0] = error;
				OutputDebugStringW(L"WinPriv: Failed to restore thread dynamic-code policy; terminating the process.\n");
				// Committed hooks can still target the DLL, so returning a load failure could unload live code.
				RaiseFailFastException(&exception, nullptr, 0);
				TerminateProcess(GetCurrentProcess(), error);
			}
			restore_ = false;
			SetLastError(previousError);
		}

	private:
		LONG result_ = NO_ERROR;
		DWORD threadPolicy_ = 0;
		bool restore_ = false;
	};
}
