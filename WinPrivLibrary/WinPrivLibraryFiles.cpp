//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "WinPrivLibrary.h"
#include <Shellapi.h>
#include <LM.h>
#include <algorithm>
#include <array>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "onecore.lib")

struct FileRule
{
	std::wstring source;
	std::wstring destination;
};

struct FileHandlePath
{
	std::wstring logical;
	std::wstring physical;
};

struct FilePathRequest
{
	OBJECT_ATTRIBUTES attributes{};
	UNICODE_STRING name{};
	std::wstring logical;
	std::wstring redirected;
};

static std::vector<FileRule> fileRules;
static std::map<HANDLE, FileHandlePath> fileHandlePaths;
static constinit std::shared_mutex fileHandleLock;
static auto TrueNtClose = &NtClose;
static auto TrueNtOpenFile = &NtOpenFile;
static auto TrueNtCreateFile = &NtCreateFile;
static auto TrueNtDuplicateObject = LoadNtFunction<NtDuplicateObjectFunction>("NtDuplicateObject");
static auto TrueNtQueryAttributesFile = LoadNtFunction<NtFileAttributesFunction>("NtQueryAttributesFile");
static auto TrueNtQueryFullAttributesFile = LoadNtFunction<NtFileAttributesFunction>("NtQueryFullAttributesFile");
static auto TrueNtDeleteFile = LoadNtFunction<NtDeleteFileFunction>("NtDeleteFile");
static auto TrueNtSetInformationFile = LoadNtFunction<NtSetInformationFileFunction>("NtSetInformationFile");
static auto TrueNtQueryInformationByName = LoadNtFunction<NtQueryInformationByNameFunction>("NtQueryInformationByName");
static const auto NtOpenSymbolicLinkObject = LoadNtFunction<NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK,
	POBJECT_ATTRIBUTES)>("NtOpenSymbolicLinkObject");
static const auto NtQuerySymbolicLinkObject = LoadNtFunction<NTSTATUS(NTAPI*)(HANDLE, PUNICODE_STRING,
	PULONG)>("NtQuerySymbolicLinkObject");

static bool FilePathPrefix(std::wstring_view path, std::wstring_view prefix)
{
	return path.size() >= prefix.size() &&
		CompareStringOrdinal(path.data(), static_cast<int>(prefix.size()),
			prefix.data(), static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL &&
		(path.size() == prefix.size() || path[prefix.size()] == L'\\' || path[prefix.size()] == L':');
}

static std::wstring FileMatchPath(std::wstring path)
{
	// Resolve DOS device aliases without opening the file; rules also cover paths that do not exist yet.
	constexpr std::wstring_view dosDevices = L"\\DosDevices\\";
	constexpr std::wstring_view dosPrefix = L"\\??\\";
	constexpr std::wstring_view uncPrefix = L"\\??\\UNC\\";
	constexpr int maxAliases = 8;
	constexpr ACCESS_MASK symbolicLinkQuery = 1;
	for (int attempt = 0; attempt < maxAliases; ++attempt)
	{
		if (_wcsnicmp(path.c_str(), dosDevices.data(), dosDevices.size()) == 0)
			path = dosPrefix.data() + path.substr(dosDevices.size());
		if (_wcsnicmp(path.c_str(), uncPrefix.data(), uncPrefix.size()) == 0)
		{
			path = L"\\Device\\Mup\\" + path.substr(uncPrefix.size());
			break;
		}
		if (!path.starts_with(dosPrefix)) break;
		const size_t separator = path.find(L'\\', dosPrefix.size());

		// Query the device link directly, without opening its directory or tracking internal handles.
		const std::wstring device = path.substr(0, separator);
		UNICODE_STRING deviceName{};
		if (RtlInitUnicodeStringEx(&deviceName, device.c_str()) < 0) break;
		OBJECT_ATTRIBUTES attributes{ sizeof(OBJECT_ATTRIBUTES), nullptr, &deviceName, OBJ_CASE_INSENSITIVE };
		HANDLE handle = nullptr;
		if (NtOpenSymbolicLinkObject(&handle, symbolicLinkQuery, &attributes) < 0) break;
		std::unique_ptr<void, decltype(TrueNtClose)> link(handle, TrueNtClose);
		std::array<WCHAR, MAX_PATH> buffer;
		UNICODE_STRING target{ 0, sizeof(buffer), buffer.data() };
		ULONG required = 0;
		NTSTATUS status = NtQuerySymbolicLinkObject(handle, &target, &required);
		std::wstring expanded;
		if (status == STATUS_BUFFER_TOO_SMALL && required <= UNICODE_STRING_MAX_BYTES)
		{
			expanded.resize(required / sizeof(WCHAR));
			target = { 0, static_cast<USHORT>(required), expanded.data() };
			status = NtQuerySymbolicLinkObject(handle, &target, nullptr);
		}
		if (status < 0) break;
		path.replace(0, separator == std::wstring::npos ? path.size() : separator,
			target.Buffer, target.Length / sizeof(WCHAR));
	}
	while (!path.empty() && path.back() == L'\\') path.pop_back();
	return path;
}

static const FileRule* FindFileRule(std::wstring_view path)
{
	// Prefer the longest matching source, with later rules winning ties.
	const FileRule* match = nullptr;
	for (const auto& rule : fileRules)
	{
		if ((match == nullptr || rule.source.size() >= match->source.size()) && FilePathPrefix(path, rule.source))
			match = &rule;
	}
	return match;
}

static std::wstring GetFileHandlePath(HANDLE handle, bool logical = true)
{
	// Read the handle's physical name before consulting its logical path cache.
	const DWORD flags = FILE_NAME_OPENED | VOLUME_NAME_NT;
	std::wstring path(MAX_PATH, L'\0');
	DWORD copied = GetFinalPathNameByHandleW(handle, path.data(), static_cast<DWORD>(path.size()), flags);
	if (copied >= path.size())
	{
		path.resize(copied);
		copied = GetFinalPathNameByHandleW(handle, path.data(), static_cast<DWORD>(path.size()), flags);
	}
	if (copied == 0 || copied >= path.size()) return {};
	path.resize(copied);
	path = FileMatchPath(std::move(path));
	if (!logical) return path;

	// Keep the requested directory name for relative opens through a redirected handle.
	std::shared_lock lock(fileHandleLock);
	const auto found = fileHandlePaths.find(handle);
	if (found != fileHandlePaths.end() && path.size() == found->second.physical.size() &&
		FilePathPrefix(path, found->second.physical)) return found->second.logical;
	return path;
}

static NTSTATUS PrepareFilePath(POBJECT_ATTRIBUTES attributes, ULONG options, FilePathRequest& request)
{
	// Resolve counted native paths, including names relative to an open directory.
	if (fileRules.empty() || attributes == nullptr || attributes->ObjectName == nullptr ||
		attributes->ObjectName->Buffer == nullptr || attributes->ObjectName->Length % sizeof(WCHAR) != 0 ||
		(options & FILE_OPEN_BY_FILE_ID) != 0) return STATUS_SUCCESS;

	std::wstring path(attributes->ObjectName->Buffer, attributes->ObjectName->Length / sizeof(WCHAR));
	if (path.find(L'\0') != std::wstring::npos) return STATUS_SUCCESS;
	if (path.empty() || path.front() != L'\\')
	{
		if (attributes->RootDirectory == nullptr) return STATUS_SUCCESS;
		std::wstring root = GetFileHandlePath(attributes->RootDirectory);
		if (root.empty()) return STATUS_SUCCESS;
		path = root + (path.empty() ? L"" : L"\\") + path;
	}
	request.logical = FileMatchPath(std::move(path));
	const FileRule* rule = FindFileRule(request.logical);
	if (rule == nullptr) return STATUS_SUCCESS;

	// Apply exactly one rule so redirects cannot cycle or unexpectedly cascade into another rule.
	std::wstring suffix = request.logical.substr(rule->source.size());
	request.redirected = rule->destination;
	if (request.redirected.back() == L'\\' && !suffix.empty() && suffix.front() == L'\\') suffix.erase(0, 1);
	request.redirected += suffix;
	const NTSTATUS status = RtlInitUnicodeStringEx(&request.name, request.redirected.c_str());
	if (status < 0) return status;
	request.attributes = *attributes;
	request.attributes.ObjectName = &request.name;
	request.attributes.RootDirectory = nullptr;
	return STATUS_SUCCESS;
}

static NTSTATUS FileFailure(NTSTATUS status, PIO_STATUS_BLOCK ioStatus, PHANDLE handle = nullptr)
{
	if (handle != nullptr) *handle = nullptr;
	if (ioStatus != nullptr) *ioStatus = { .Status = status, .Information = 0 };
	return status;
}

template <typename Operation>
static NTSTATUS WithFilePath(POBJECT_ATTRIBUTES attributes, ULONG options,
	PHANDLE handle, PIO_STATUS_BLOCK ioStatus, Operation operation)
{
	try
	{
		// Apply path rules before issuing the original operation.
		FilePathRequest request;
		const NTSTATUS prepared = PrepareFilePath(attributes, options, request);
		if (prepared < 0) return FileFailure(prepared, ioStatus, handle);
		const NTSTATUS status = operation(request.redirected.empty() ? attributes : &request.attributes);
		if (status >= 0 && handle != nullptr && *handle != nullptr && !request.redirected.empty())
		{
			// Remember the opened path after resolving any filesystem reparse points.
			std::unique_ptr<void, decltype(TrueNtClose)> opened(*handle, TrueNtClose);
			FileHandlePath path{ std::move(request.logical), GetFileHandlePath(*handle, false) };
			std::lock_guard lock(fileHandleLock);
			fileHandlePaths.insert_or_assign(*handle, std::move(path));
			opened.release();
		}
		return status;
	}
	catch (...)
	{
		return FileFailure(STATUS_NO_MEMORY, ioStatus, handle);
	}
}

static NTSTATUS NTAPI DetourNtClose(HANDLE handle)
{
	// Serialize removal with close so a reused handle cannot inherit another file's logical path.
	std::lock_guard lock(fileHandleLock);
	const NTSTATUS status = TrueNtClose(handle);
	if (status >= 0) fileHandlePaths.erase(handle);
	return status;
}

static NTSTATUS NTAPI DetourNtDuplicateObject(HANDLE sourceProcess, HANDLE sourceHandle, HANDLE targetProcess,
	PHANDLE targetHandle, ACCESS_MASK access, ULONG attributes, ULONG options)
{
	// Handle comparison does not require process query access in addition to duplication access.
	const HANDLE currentProcess = GetCurrentProcess();
	if (sourceProcess != currentProcess && !CompareObjectHandles(sourceProcess, currentProcess))
		return TrueNtDuplicateObject(sourceProcess, sourceHandle, targetProcess,
			targetHandle, access, attributes, options);
	try
	{
		// Keep logical names synchronized with native handle duplication.
		std::lock_guard lock(fileHandleLock);
		const auto found = fileHandlePaths.find(sourceHandle);
		const FileHandlePath path = found == fileHandlePaths.end() ? FileHandlePath{} : found->second;
		const NTSTATUS status = TrueNtDuplicateObject(
			sourceProcess, sourceHandle, targetProcess, targetHandle, access, attributes, options);
		if ((options & DUPLICATE_CLOSE_SOURCE) != 0) fileHandlePaths.erase(sourceHandle);
		if (status >= 0 && targetHandle != nullptr &&
			(targetProcess == currentProcess || CompareObjectHandles(targetProcess, currentProcess)))
		{
			std::unique_ptr<void, decltype(TrueNtClose)> opened(*targetHandle, TrueNtClose);
			if (!path.logical.empty()) fileHandlePaths.insert_or_assign(*targetHandle, path);
			opened.release();
		}
		return status;
	}
	catch (...)
	{
		return FileFailure(STATUS_NO_MEMORY, nullptr, targetHandle);
	}
}

static NTSTATUS NTAPI DetourNtQueryAttributesFile(POBJECT_ATTRIBUTES attributes, PVOID information)
{
	return WithFilePath(attributes, 0, nullptr, nullptr, [&](POBJECT_ATTRIBUTES path) {
		return TrueNtQueryAttributesFile(path, information);
	});
}

static NTSTATUS NTAPI DetourNtQueryFullAttributesFile(POBJECT_ATTRIBUTES attributes, PVOID information)
{
	return WithFilePath(attributes, 0, nullptr, nullptr, [&](POBJECT_ATTRIBUTES path) {
		return TrueNtQueryFullAttributesFile(path, information);
	});
}

static NTSTATUS NTAPI DetourNtDeleteFile(POBJECT_ATTRIBUTES attributes)
{
	return WithFilePath(attributes, 0, nullptr, nullptr, [&](POBJECT_ATTRIBUTES path) {
		return TrueNtDeleteFile(path);
	});
}

static NTSTATUS NTAPI DetourNtQueryInformationByName(POBJECT_ATTRIBUTES attributes, PIO_STATUS_BLOCK ioStatus,
	PVOID information, ULONG length, FileInformationClass informationClass)
{
	return WithFilePath(attributes, 0, nullptr, ioStatus, [&](POBJECT_ATTRIBUTES path) {
		return TrueNtQueryInformationByName(path, ioStatus, information, length, informationClass);
	});
}

static NTSTATUS NTAPI DetourNtSetInformationFile(HANDLE handle, PIO_STATUS_BLOCK ioStatus,
	PVOID information, ULONG length, FileInformationClass informationClass)
{
	// Rename and hard-link destinations share the same layout, including the extended flag variants.
	using enum FileInformationClass;
	const bool rename = informationClass == Rename || informationClass == RenameBypassAccessCheck ||
		informationClass == RenameEx || informationClass == RenameExBypassAccessCheck;
	const bool link = informationClass == Link || informationClass == LinkBypassAccessCheck ||
		informationClass == LinkEx || informationClass == LinkExBypassAccessCheck;
	if ((!rename && !link) || information == nullptr || length < offsetof(FILE_RENAME_INFO, FileName))
		return TrueNtSetInformationFile(handle, ioStatus, information, length, informationClass);
	try
	{
		const auto original = static_cast<FILE_RENAME_INFO*>(information);
		if (original->FileNameLength > length - offsetof(FILE_RENAME_INFO, FileName) ||
			original->FileNameLength > UNICODE_STRING_MAX_BYTES ||
			original->FileNameLength % sizeof(WCHAR) != 0)
			return TrueNtSetInformationFile(handle, ioStatus, information, length, informationClass);
		std::wstring name(original->FileName, original->FileNameLength / sizeof(WCHAR));

		// Stream renames stay within the file whose handle was already redirected.
		if (name.find(L'\0') != std::wstring::npos || (!name.empty() && name.front() == L':'))
			return TrueNtSetInformationFile(handle, ioStatus, information, length, informationClass);
		if (original->RootDirectory == nullptr && !name.empty() && name.front() != L'\\')
		{
			const std::wstring source = GetFileHandlePath(handle);
			const size_t separator = source.rfind(L'\\');
			if (separator == std::wstring::npos)
				return TrueNtSetInformationFile(handle, ioStatus, information, length, informationClass);
			name = source.substr(0, separator + 1) + name;
		}
		UNICODE_STRING unicodeName{};
		const NTSTATUS initialized = RtlInitUnicodeStringEx(&unicodeName, name.c_str());
		if (initialized < 0) return FileFailure(initialized, ioStatus);
		OBJECT_ATTRIBUTES attributes{ sizeof(OBJECT_ATTRIBUTES), original->RootDirectory, &unicodeName };
		FilePathRequest request;
		const NTSTATUS prepared = PrepareFilePath(&attributes, 0, request);
		if (prepared < 0) return FileFailure(prepared, ioStatus);

		// Build a replacement destination buffer only when a redirect matched.
		std::vector<BYTE> buffer;
		if (!request.redirected.empty())
		{
			const ULONG bytes = static_cast<ULONG>(offsetof(FILE_RENAME_INFO, FileName) +
				request.name.Length + sizeof(WCHAR));
			buffer.resize((std::max)(bytes, static_cast<ULONG>(sizeof(FILE_RENAME_INFO))));
			auto redirected = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
			memcpy(redirected, original, offsetof(FILE_RENAME_INFO, FileName));
			redirected->RootDirectory = nullptr;
			redirected->FileNameLength = request.name.Length;
			memcpy(redirected->FileName, request.name.Buffer, request.name.Length);
			information = redirected;
			length = static_cast<ULONG>(buffer.size());
		}

		// A renamed directory also changes the paths of open handles beneath it.
		const std::wstring previous = rename ? GetFileHandlePath(handle, false) : L"";
		const NTSTATUS status = TrueNtSetInformationFile(handle, ioStatus, information, length, informationClass);
		if (status < 0 || previous.empty() || request.logical.empty()) return status;
		const std::wstring physical = GetFileHandlePath(handle, false);
		if (physical.empty()) return status;
		std::lock_guard lock(fileHandleLock);
		for (auto& [trackedHandle, path] : fileHandlePaths)
		{
			if (!FilePathPrefix(path.physical, previous)) continue;
			const std::wstring suffix = path.physical.substr(previous.size());
			path.logical = request.logical + suffix;
			path.physical = physical + suffix;
		}
		if (!request.redirected.empty())
			fileHandlePaths.insert_or_assign(handle, FileHandlePath{ request.logical, physical });
		return status;
	}
	catch (...)
	{
		return FileFailure(STATUS_NO_MEMORY, ioStatus);
	}
}

//   ___         ___     __   __   ___
//  |__  | |    |__     /  \ |__) |__  |\ |
//  |    | |___ |___    \__/ |    |___ | \|
//

static bool CloseFileHandle(PUNICODE_STRING sFileNameUnicodeString)
{
	// valid path formats
	static const std::wregex tRegexLocal(LR"(\\\?\?\\(.*))", std::wregex::optimize);
	static const std::wregex tRegexUnc(LR"(\\\?\?\\UNC\\([^\\]+?)\\([^\\]+?)\\(.*))", std::wregex::optimize);

	std::wstring sComputerName;
	std::wstring sPath;

	const std::wstring sFileName(sFileNameUnicodeString->Buffer, sFileNameUnicodeString->Length / sizeof(WCHAR));

	// see if the path looks like a unc path
	std::wsmatch tMatches;
	if (std::regex_match(sFileName, tMatches, tRegexUnc))
	{
		// extract the important parts of the regular expression result
		sComputerName = tMatches[1].str();
		const std::wstring sShareName = tMatches[2].str();
		const std::wstring sLocalPath = tMatches[3].str();

		// get the real path name using the computer and share name
		SmartPointer<PSHARE_INFO_502> tShareInfo(NetApiBufferFree, nullptr);
		if (NetShareGetInfo((LPWSTR)sComputerName.c_str(), (LPWSTR)sShareName.c_str(),
			502, (LPBYTE*)&tShareInfo) != NERR_Success || tShareInfo == nullptr) return false;
		const size_t iSharePathLength = tShareInfo->shi502_path == nullptr ? 0 : wcslen(tShareInfo->shi502_path);
		if (iSharePathLength == 0) return false;
		const bool bNeedsBackslash = tShareInfo->shi502_path[iSharePathLength - 1] != L'\\';
		sPath = std::wstring(tShareInfo->shi502_path) + ((bNeedsBackslash) ? L"\\" : L"") + sLocalPath;
	}

	// see if the path looks like a local path
	else if (std::regex_match(sFileName, tMatches, tRegexLocal))
	{
		sPath = tMatches[1].str();
	}

	// unrecognized path type
	else
	{
		return false;
	}

	// loop through the files matching the path
	DWORD iClosedFiles = 0;
	DWORD iStatus = 0;
	DWORD iEntriesRead = 0;
	DWORD iReturned = 0;
	DWORD_PTR hHandle = 0;
	std::vector<DWORD> tFileIds;
	SmartPointer<PFILE_INFO_3> tFileInfo(NetApiBufferFree, nullptr);
	while ((iStatus = NetFileEnum(sComputerName.empty() ? nullptr : (LPWSTR)sComputerName.c_str(),
		(LPWSTR)sPath.c_str(), nullptr, 3, (LPBYTE*)&tFileInfo,
		MAX_PREFERRED_LENGTH, &iEntriesRead, &iReturned, &hHandle)) == NERR_Success || iStatus == ERROR_MORE_DATA)
	{
		if (iEntriesRead == 0) break;

		// put the files into a vector so we can close them all at once and not
		// interrupt the enumeration operation
		for (DWORD iEntry = 0; iEntry < iEntriesRead; iEntry++)
		{
			if (tFileInfo[iEntry].fi3_pathname != nullptr &&
				CompareStringOrdinal(tFileInfo[iEntry].fi3_pathname, -1,
					sPath.c_str(), -1, TRUE) == CSTR_EQUAL)
			{
				tFileIds.push_back(tFileInfo[iEntry].fi3_id);
			}
		}
		tFileInfo.Cleanup();
		if (iStatus != ERROR_MORE_DATA) break;
	}

	// close the open files
	for (const DWORD iFileId : tFileIds)
	{
		if (NetFileClose(sComputerName.empty() ? nullptr : (LPWSTR)sComputerName.c_str(),
			iFileId) == NERR_Success)
		{
			iClosedFiles++;
		}
	}
	return iClosedFiles > 0;
}

template <typename Operation>
static NTSTATUS OpenFileWithOptions(POBJECT_ATTRIBUTES attributes, ULONG options,
	PHANDLE handle, PIO_STATUS_BLOCK ioStatus, Operation operation)
{
	// Apply backup intent and retry failed opens after closing remote locks.
	if (VariableIsSet(WINPRIV_EV_BACKUP_RESTORE, 1)) options |= FILE_OPEN_FOR_BACKUP_INTENT;
	return WithFilePath(attributes, options, handle, ioStatus, [&](POBJECT_ATTRIBUTES path) {
		const NTSTATUS status = operation(path, options);
		if ((status != STATUS_SHARING_VIOLATION && status != STATUS_ACCESS_DENIED) ||
			!VariableIsSet(WINPRIV_EV_BREAK_LOCKS, 1) || !CloseFileHandle(path->ObjectName)) return status;

		// try operation again now that file is closed
		return operation(path, options);
	});
}

EXTERN_C NTSTATUS NTAPI DetourNtOpenFile(OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess, IN ULONG OpenOptions)
{
	return OpenFileWithOptions(ObjectAttributes, OpenOptions,
		FileHandle, IoStatusBlock, [&](POBJECT_ATTRIBUTES path, ULONG options) {
		return TrueNtOpenFile(FileHandle, DesiredAccess, path, IoStatusBlock, ShareAccess, options);
	});
}

EXTERN_C NTSTATUS NTAPI DetourNtCreateFile(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL, IN ULONG FileAttributes, IN ULONG ShareAccess,
	IN ULONG CreateDisposition, IN ULONG CreateOptions, IN PVOID EaBuffer OPTIONAL, IN ULONG EaLength)
{
	return OpenFileWithOptions(ObjectAttributes, CreateOptions,
		FileHandle, IoStatusBlock, [&](POBJECT_ATTRIBUTES path, ULONG options) {
		return TrueNtCreateFile(FileHandle, DesiredAccess, path, IoStatusBlock, AllocationSize,
			FileAttributes, ShareAccess, CreateDisposition, options, EaBuffer, EaLength);
	});
}

// Install file hooks together so opening, attributes, and mutation share the same rules.
bool DllFileAttachDetach(winpriv::detours::action requestedAction)
{
	const bool attaching = requestedAction == winpriv::detours::action::attach;
	const bool rulesEnabled = VariableNotEmpty(WINPRIV_EV_FILE_RULES);

	// Load the ordered rules once when the library attaches.
	if (rulesEnabled && attaching)
	{
		try
		{
			int count = 0;
			SmartPointer<LPWSTR*> arguments(LocalFree, CommandLineToArgvW(_wgetenv(WINPRIV_EV_FILE_RULES), &count));
			if (arguments == nullptr || count % 2 != 0) return false;
			for (int index = 0; index < count; index += 2)
			{
				std::wstring source = FileMatchPath(arguments[index]);
				std::wstring destination = arguments[index + 1];
				if (source.empty() || destination.empty()) return false;
				fileRules.push_back({ std::move(source), std::move(destination) });
			}
		}
		catch (...)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return false;
		}
	}

	// Enable the hooks required by the selected file options.
	if (rulesEnabled || VariableIsSet(WINPRIV_EV_BACKUP_RESTORE, 1) || VariableIsSet(WINPRIV_EV_BREAK_LOCKS, 1))
	{
		ApplyDetour(requestedAction, TrueNtOpenFile, DetourNtOpenFile);
		ApplyDetour(requestedAction, TrueNtCreateFile, DetourNtCreateFile);
	}
	if (rulesEnabled)
	{
		ApplyDetour(requestedAction, TrueNtQueryAttributesFile, DetourNtQueryAttributesFile);
		ApplyDetour(requestedAction, TrueNtQueryFullAttributesFile, DetourNtQueryFullAttributesFile);
		ApplyDetour(requestedAction, TrueNtDeleteFile, DetourNtDeleteFile);
		ApplyDetour(requestedAction, TrueNtSetInformationFile, DetourNtSetInformationFile);
		ApplyDetour(requestedAction, TrueNtClose, DetourNtClose);
		ApplyDetour(requestedAction, TrueNtDuplicateObject, DetourNtDuplicateObject);
		if (TrueNtQueryInformationByName != nullptr)
			ApplyDetour(requestedAction, TrueNtQueryInformationByName, DetourNtQueryInformationByName);
	}
	return true;
}
