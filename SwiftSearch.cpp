#include <process.h>
#include <stddef.h>
#include <stdio.h>
#include <tchar.h>
#include <time.h>
#include <wchar.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include <algorithm>
#include <map>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include <boost/algorithm/string/predicate.hpp>
#if __cplusplus >= 201103L || defined(__GXX_EXPERIMENTAL_CXX0X__) || defined(_CPPLIB_VER) && 600 <= _CPPLIB_VER
#include <atomic>
#else
#include <boost/atomic/atomic.hpp>
#endif
#include <boost/smart_ptr/intrusive_ptr.hpp>

namespace WTL { using std::min; using std::max; }

#include <Windows.h>
#include <Dbt.h>
#include <ProvExce.h>
#include <ShlObj.h>

#include <atlbase.h>
#include <atlapp.h>
#include <atlcrack.h>
#include <atlmisc.h>
extern WTL::CAppModule _Module;
#include <atlwin.h>
#include <atlframe.h>
#include <atlctrls.h>
#include <atlctrlx.h>
#include <atltheme.h>

#include "nformat.hpp"
#include "path.hpp"

#include "BackgroundWorker.hpp"
#include "ShellItemIDList.hpp"
#include "CModifiedDialogImpl.hpp"

#include "resource.h"

#ifndef _DEBUG
#define clear() resize(0)
#include <boost/exception/info.hpp>
#undef clear
#include <boost/xpressive/detail/dynamic/matchable.hpp>
#define clear() resize(0)
#define push_back(x) operator +=(x)
#include <boost/xpressive/detail/dynamic/parser_traits.hpp>
#undef  push_back
#undef clear
#include <boost/xpressive/match_results.hpp>
#include <boost/xpressive/xpressive_dynamic.hpp>

#endif

#ifdef BOOST_XPRESSIVE_DYNAMIC_HPP_EAN_10_04_2005
#define BOOST_XPRESSIVE_DYNAMIC_HPP_EAN BOOST_XPRESSIVE_DYNAMIC_HPP_EAN_10_04_2005
#endif

namespace std { typedef basic_string<TCHAR> tstring; }
namespace std
{
	template<class> struct is_scalar;
#if defined(_CPPLIB_VER) && 600 <= _CPPLIB_VER
#ifdef _XMEMORY_
	template<class T1, class T2> struct is_scalar<std::pair<T1, T2> > : integral_constant<bool, is_pod<T1>::value && is_pod<T2>::value>{};
	template<class T1, class T2, class _Diff, class _Valty>
	inline void _Uninit_def_fill_n(std::pair<T1, T2> *_First, _Diff _Count, _Wrap_alloc<allocator<std::pair<T1, T2> > >&, _Valty *,
#if defined(_CPPLIB_VER) && _CPPLIB_VER >= 650
		_Trivially_copyable_ptr_iterator_tag
#else
		_Scalar_ptr_iterator_tag
#endif
	)
	{ _Fill_n(_First, _Count, _Valty()); }
#endif
#else
	template<class T> struct is_pod { static bool const value = __is_pod(T); };
#endif
}

class mutex
{
	void init()
	{
#if defined(_WIN32)
		InitializeCriticalSection(&p);
#elif defined(_OPENMP) || defined(_OMP_LOCK_T)
		omp_init_lock(&p);
#endif
	}
	void term()
	{
#if defined(_WIN32)
		DeleteCriticalSection(&p);
#elif defined(_OPENMP) || defined(_OMP_LOCK_T)
		omp_destroy_lock(&p);
#endif
	}
public:
	mutex &operator =(mutex const &) { return *this; }
#if defined(_WIN32)
	CRITICAL_SECTION p;
#elif defined(_OPENMP) || defined(_OMP_LOCK_T)
	omp_lock_t p;
#elif defined(BOOST_THREAD_MUTEX_HPP)
	boost::mutex m;
#else
	std::mutex m;
#endif
	mutex(mutex const &) { this->init(); }
	mutex() { this->init(); }
	~mutex() { this->term(); }
	void lock()
	{
#if defined(_WIN32)
		EnterCriticalSection(&p);
#elif defined(_OPENMP) || defined(_OMP_LOCK_T)
		omp_set_lock(&p);
#else
		return m.lock();
#endif
	}
	void unlock()
	{
#if defined(_WIN32)
		LeaveCriticalSection(&p);
#elif defined(_OPENMP) || defined(_OMP_LOCK_T)
		omp_unset_lock(&p);
#else
		return m.unlock();
#endif
	}
	bool try_lock()
	{
#if defined(_WIN32)
		return !!TryEnterCriticalSection(&p);
#elif defined(_OPENMP) || defined(_OMP_LOCK_T)
		return !!omp_test_lock(&p);
#else
		return m.try_lock();
#endif
	}
};
template<class Mutex>
struct lock_guard
{
	typedef Mutex mutex_type;
	mutex_type *p;
	~lock_guard() { if (p) { p->unlock(); } }
	lock_guard() : p() { }
	explicit lock_guard(mutex_type *const mutex, bool const already_locked = false) : p(mutex) { if (p && !already_locked) { p->lock(); } }
	explicit lock_guard(mutex_type &mutex, bool const already_locked = false) : p(&mutex) { if (!already_locked) { p->lock(); } }
	lock_guard(lock_guard const &other) : p(other.p) { if (p) { p->lock(); } }
	lock_guard &operator =(lock_guard other) { return this->swap(other), *this; }
	void swap(lock_guard &other) { using std::swap; swap(this->p, other.p); }
	friend void swap(lock_guard &a, lock_guard &b) { return a.swap(b); }
};

struct tchar_ci_traits : public std::char_traits<TCHAR>
{
	typedef std::char_traits<TCHAR> Base;
	static bool eq(TCHAR c1, TCHAR c2)
	{
		return c1 < SCHAR_MAX
			? c1 == c2 ||
				_T('A') <= c1 && c1 <= _T('Z') && c1 - c2 == _T('A') - _T('a') ||
				_T('A') <= c2 && c2 <= _T('Z') && c2 - c1 == _T('A') - _T('a')
			: _totupper(c1) == _totupper(c2);
	}
	static bool ne(TCHAR c1, TCHAR c2) { return !eq(c1, c2); }
	static bool lt(TCHAR c1, TCHAR c2)
	{
		if (c1 < SCHAR_MAX && c2 < SCHAR_MAX)
		{
			if (_T('A') <= c1 && c1 <= _T('Z')) { c1 -= static_cast<TCHAR>(_T('A') - _T('a')); }
			if (_T('A') <= c2 && c2 <= _T('Z')) { c2 -= static_cast<TCHAR>(_T('A') - _T('a')); }
			return c1 < c2;
		}
		return _totupper(c1) <  _totupper(c2);
	}
	static int compare(TCHAR const *s1, TCHAR const *s2, size_t n)
	{
		while (n-- != 0)
		{
			if (lt(*s1, *s2)) { return -1; }
			if (lt(*s2, *s1)) { return +1; }
			++s1; ++s2;
		}
		return 0;
	}
	static TCHAR const *find(TCHAR const *s, size_t n, TCHAR a)
	{
		while (n > 0 && ne(*s, a)) { ++s; --n; }
		return s;
	}
};

template<class Tr>
struct char_traits_equals
{
	Tr const *tr;
	bool operator()(typename Tr::char_type const a, typename Tr::char_type const b) const
	{
		return tr->eq(a, b);
	}
};

template<class It2, class Tr>
inline bool wildcard(TCHAR const *patBegin, TCHAR const *const patEnd, It2 strBegin, It2 const strEnd, Tr const &tr = std::char_traits<typename std::iterator_traits<It2>::value_type>())
{
	typedef TCHAR const *It1;
	(void)tr;
	if (patBegin == patEnd) { return strBegin == strEnd; }
	if (patEnd - patBegin >= 2 && *patBegin == _T('*') && *(patEnd - 1) == _T('*') && tr.find(patBegin + 1, patEnd - patBegin - 2, _T('*')) == patEnd - 1)
	{
		// TODO: just a substring search... no need for full-blown wildcard matching
		char_traits_equals<Tr> cte = { &tr };
		return boost::algorithm::contains(std::pair<It2, It2>(strBegin, strEnd), std::pair<It1, It1>(patBegin + 1, patEnd - 1), cte);
	}
	for (It1 p = patBegin; p != patEnd; ++p)  // check if ANY characters match!
	{
		if (*p != _T('*') && *p != _T('?'))
		{
			bool found = false;
			for (It2 s = strBegin; s != strEnd; ++s)
			{
				if (tr.eq(*s, *p))
				{
					found = true;
					break;
				}
			}
			if (!found) { return false; }
			break;
		}
	}
	//http://xoomer.virgilio.it/acantato/dev/wildcard/wildmatch.html
	{
		It2 s(strBegin);
		It1 p(patBegin);
		bool star = false;

	loop:
		for (s = strBegin, p = patBegin; s != strEnd && p != patEnd; ++s, ++p)
		{
			if (tr.eq(*p, _T('*')))
			{
				star = true;
				strBegin = s, patBegin = p;
				if (++patBegin == patEnd)
				{ return true; }
				goto loop;
			}
			else if (!tr.eq(*p, _T('?')) && !tr.eq(*s, *p))
			{
				if (!star) { return false; }
				strBegin++;
				goto loop;
			}
		}
		while (p != patEnd && tr.eq(*p, _T('*'))) { ++p; }
		return p == patEnd && s == strEnd;
	}
}

static void append(std::tstring &str, TCHAR const sz[], size_t const cch)
{
	size_t const n = str.size();
	if (n + cch > str.capacity())
	{ str.reserve(n + n / 2 + cch * 2); }
	str.append(sz, cch);
}

namespace winnt
{
	struct IO_STATUS_BLOCK { union { long Status; void *Pointer; }; uintptr_t Information; };

	struct UNICODE_STRING
	{
		unsigned short Length, MaximumLength;
		wchar_t *buffer_ptr;
	};

	struct OBJECT_ATTRIBUTES
	{
		unsigned long Length;
		HANDLE RootDirectory;
		UNICODE_STRING *ObjectName;
		unsigned long Attributes;
		void *SecurityDescriptor;
		void *SecurityQualityOfService;
	};

	typedef VOID NTAPI IO_APC_ROUTINE(IN PVOID ApcContext, IN IO_STATUS_BLOCK *IoStatusBlock, IN ULONG Reserved);

	enum IO_PRIORITY_HINT { IoPriorityVeryLow = 0, IoPriorityLow, IoPriorityNormal, IoPriorityHigh, IoPriorityCritical, MaxIoPriorityTypes };
	struct FILE_FS_SIZE_INFORMATION { long long TotalAllocationUnits, ActualAvailableAllocationUnits; unsigned long SectorsPerAllocationUnit, BytesPerSector; };
	struct FILE_FS_ATTRIBUTE_INFORMATION { unsigned long FileSystemAttributes; unsigned long MaximumComponentNameLength; unsigned long FileSystemNameLength; wchar_t FileSystemName[1]; };
	union FILE_IO_PRIORITY_HINT_INFORMATION { IO_PRIORITY_HINT PriorityHint; unsigned long long _alignment; };

	template<class T> struct identity { typedef T type; };
	typedef long NTSTATUS;
#define X(F, T) identity<T>::type &F = *reinterpret_cast<identity<T>::type *>(GetProcAddress(GetModuleHandle(_T("NTDLL.dll")), #F))
	X(NtOpenFile, NTSTATUS NTAPI(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN OBJECT_ATTRIBUTES *ObjectAttributes, OUT IO_STATUS_BLOCK *IoStatusBlock, IN ULONG ShareAccess, IN ULONG OpenOptions));
	X(NtReadFile, NTSTATUS NTAPI(IN HANDLE FileHandle, IN HANDLE Event OPTIONAL, IN IO_APC_ROUTINE *ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL, OUT IO_STATUS_BLOCK *IoStatusBlock, OUT PVOID buffer_ptr, IN ULONG Length, IN PLARGE_INTEGER ByteOffset OPTIONAL, IN PULONG Key OPTIONAL));
	X(NtQueryVolumeInformationFile, NTSTATUS NTAPI(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID FsInformation, unsigned long Length, unsigned long FsInformationClass));
	X(NtQueryInformationFile, NTSTATUS NTAPI(IN HANDLE FileHandle, OUT IO_STATUS_BLOCK *IoStatusBlock, OUT PVOID FileInformation, IN ULONG Length, IN unsigned long FileInformationClass));
	X(NtSetInformationFile, NTSTATUS NTAPI(IN HANDLE FileHandle, OUT IO_STATUS_BLOCK *IoStatusBlock, IN PVOID FileInformation, IN ULONG Length, IN unsigned long FileInformationClass));
	X(RtlInitUnicodeString, VOID NTAPI(UNICODE_STRING * DestinationString, PCWSTR SourceString));
	X(RtlNtStatusToDosError, unsigned long NTAPI(IN NTSTATUS NtStatus));
	X(RtlSystemTimeToLocalTime, NTSTATUS NTAPI(IN LARGE_INTEGER const *SystemTime, OUT PLARGE_INTEGER LocalTime));
#undef  X
}

LONGLONG RtlSystemTimeToLocalTime(LONGLONG systemTime)
{
	LARGE_INTEGER time2, localTime;
	time2.QuadPart = systemTime;
	long status = winnt::RtlSystemTimeToLocalTime(&time2, &localTime);
	if (status != 0) { RaiseException(status, 0, 0, NULL); }
	return localTime.QuadPart;
}

LPCTSTR SystemTimeToString(LONGLONG systemTime, LPTSTR buffer, size_t cchBuffer, LPCTSTR dateFormat = NULL, LPCTSTR timeFormat = NULL, LCID lcid = GetThreadLocale())
{
	LONGLONG time = RtlSystemTimeToLocalTime(systemTime);
	SYSTEMTIME sysTime = { 0 };
	if (FileTimeToSystemTime(&reinterpret_cast<FILETIME &>(time), &sysTime))
	{
		size_t const cchDate = static_cast<size_t>(GetDateFormat(lcid, 0, &sysTime, dateFormat, &buffer[0], static_cast<int>(cchBuffer)));
		if (cchDate > 0)
		{
			// cchDate INCLUDES null-terminator
			buffer[cchDate - 1] = _T(' ');
			size_t const cchTime = static_cast<size_t>(GetTimeFormat(lcid, 0, &sysTime, timeFormat, &buffer[cchDate], static_cast<int>(cchBuffer - cchDate)));
			buffer[cchDate + cchTime - 1] = _T('\0');
		}
		else { memset(&buffer[0], 0, sizeof(buffer[0]) * cchBuffer); }
	}
	else { *buffer = _T('\0'); }
	return buffer;
}

namespace ntfs
{
#pragma pack(push, 1)
	struct NTFS_BOOT_SECTOR
	{
		unsigned char Jump[3];
		unsigned char Oem[8];
		unsigned short BytesPerSector;
		unsigned char SectorsPerCluster;
		unsigned short ReservedSectors;
		unsigned char Padding1[3];
		unsigned short Unused1;
		unsigned char MediaDescriptor;
		unsigned short Padding2;
		unsigned short SectorsPerTrack;
		unsigned short NumberOfHeads;
		unsigned long HiddenSectors;
		unsigned long Unused2;
		unsigned long Unused3;
		long long TotalSectors;
		long long MftStartLcn;
		long long Mft2StartLcn;
		signed char ClustersPerFileRecordSegment;
		unsigned char Padding3[3];
		unsigned long ClustersPerIndexBlock;
		long long VolumeSerialNumber;
		unsigned long Checksum;

		unsigned char BootStrap[0x200 - 0x54];
		unsigned int file_record_size() const { return this->ClustersPerFileRecordSegment >= 0 ? this->ClustersPerFileRecordSegment * this->SectorsPerCluster * this->BytesPerSector : 1U << static_cast<int>(-this->ClustersPerFileRecordSegment); }
		unsigned int cluster_size() const { return this->SectorsPerCluster * this->BytesPerSector; }
	};
#pragma pack(pop)
	struct MULTI_SECTOR_HEADER
	{
		unsigned long Magic;
		unsigned short USAOffset;
		unsigned short USACount;
		
		bool unfixup(size_t max_size)
		{
			unsigned short *usa = reinterpret_cast<unsigned short *>(&reinterpret_cast<unsigned char *>(this)[this->USAOffset]);
			bool result = true;
			for (unsigned short i = 1; i < this->USACount; i++)
			{
				const size_t offset = i * 512 - sizeof(unsigned short);
				unsigned short *const check = (unsigned short *) ((unsigned char*)this + offset);
				if (offset < max_size)
				{
					if (usa[0] != *check)
					{
						result = false;
					}
					*check = usa[i];
				}
				else { break; }
			}
			return result;
		}
	};
	enum AttributeTypeCode
	{
		AttributeStandardInformation = 0x10,
		AttributeAttributeList = 0x20,
		AttributeFileName = 0x30,
		AttributeObjectId = 0x40,
		AttributeSecurityDescriptor = 0x50,
		AttributeVolumeName = 0x60,
		AttributeVolumeInformation = 0x70,
		AttributeData = 0x80,
		AttributeIndexRoot = 0x90,
		AttributeIndexAllocation = 0xA0,
		AttributeBitmap = 0xB0,
		AttributeReparsePoint = 0xC0,
		AttributeEAInformation = 0xD0,
		AttributeEA = 0xE0,
		AttributePropertySet = 0xF0,
		AttributeLoggedUtilityStream = 0x100,
		AttributeEnd = -1,
	};
	struct ATTRIBUTE_RECORD_HEADER
	{
		AttributeTypeCode Type;
		unsigned long Length;
		unsigned char IsNonResident;
		unsigned char NameLength;
		unsigned short NameOffset;
		unsigned short Flags;
		unsigned short Instance;
		union
		{
			struct RESIDENT
			{
				unsigned long ValueLength;
				unsigned short ValueOffset;
				unsigned short Flags;
				inline void *GetValue() { return reinterpret_cast<void *>(reinterpret_cast<char *>(CONTAINING_RECORD(this, ATTRIBUTE_RECORD_HEADER, Resident)) + this->ValueOffset); }
				inline void const *GetValue() const { return reinterpret_cast<const void *>(reinterpret_cast<const char *>(CONTAINING_RECORD(this, ATTRIBUTE_RECORD_HEADER, Resident)) + this->ValueOffset); }
			} Resident;
			struct NONRESIDENT
			{
				unsigned long long LowestVCN;
				unsigned long long HighestVCN;
				unsigned short MappingPairsOffset;
				unsigned char CompressionUnit;
				unsigned char Reserved[5];
				long long AllocatedSize;
				long long DataSize;
				long long InitializedSize;
				long long CompressedSize;
			} NonResident;
		};
		ATTRIBUTE_RECORD_HEADER *next() { return reinterpret_cast<ATTRIBUTE_RECORD_HEADER *>(reinterpret_cast<unsigned char *>(this) + this->Length); }
		ATTRIBUTE_RECORD_HEADER const *next() const { return reinterpret_cast<ATTRIBUTE_RECORD_HEADER const *>(reinterpret_cast<unsigned char const *>(this) + this->Length); }
		wchar_t *name() { return reinterpret_cast<wchar_t *>(reinterpret_cast<unsigned char *>(this) + this->NameOffset); }
		wchar_t const *name() const { return reinterpret_cast<wchar_t const *>(reinterpret_cast<unsigned char const *>(this) + this->NameOffset); }
	};
	enum FILE_RECORD_HEADER_FLAGS
	{
		FRH_IN_USE = 0x0001,    /* Record is in use */
		FRH_DIRECTORY = 0x0002,    /* Record is a directory */
	};
	struct FILE_RECORD_SEGMENT_HEADER
	{
		MULTI_SECTOR_HEADER MultiSectorHeader;
		unsigned long long LogFileSequenceNumber;
		unsigned short SequenceNumber;
		unsigned short LinkCount;
		unsigned short FirstAttributeOffset;
		unsigned short Flags /* FILE_RECORD_HEADER_FLAGS */;
		unsigned long BytesInUse;
		unsigned long BytesAllocated;
		unsigned long long BaseFileRecordSegment;
		unsigned short NextAttributeNumber;
		//http://blogs.technet.com/b/joscon/archive/2011/01/06/how-hard-links-work.aspx
		unsigned short SegmentNumberUpper_or_USA_or_UnknownReserved;  // WARNING: This does NOT seem to be the actual "upper" segment number of anything! I found it to be 0x26e on one of my drives... and checkdisk didn't say anything about it
		unsigned long SegmentNumberLower;
		ATTRIBUTE_RECORD_HEADER *begin() { return reinterpret_cast<ATTRIBUTE_RECORD_HEADER *>(reinterpret_cast<unsigned char *>(this) + this->FirstAttributeOffset); }
		ATTRIBUTE_RECORD_HEADER const *begin() const { return reinterpret_cast<ATTRIBUTE_RECORD_HEADER const *>(reinterpret_cast<unsigned char const *>(this) + this->FirstAttributeOffset); }
		void *end(size_t const max_buffer_size = ~size_t()) { return reinterpret_cast<unsigned char *>(this) + (max_buffer_size < this->BytesInUse ? max_buffer_size : this->BytesInUse); }
		void const *end(size_t const max_buffer_size = ~size_t()) const { return reinterpret_cast<unsigned char const *>(this) + (max_buffer_size < this->BytesInUse ? max_buffer_size : this->BytesInUse); }
	};
	struct FILENAME_INFORMATION
	{
		unsigned long long ParentDirectory;
		long long CreationTime;
		long long LastModificationTime;
		long long LastChangeTime;
		long long LastAccessTime;
		long long AllocatedLength;
		long long FileSize;
		unsigned long FileAttributes;
		unsigned short PackedEaSize;
		unsigned short Reserved;
		unsigned char FileNameLength;
		unsigned char Flags;
		WCHAR FileName[1];
	};
	struct STANDARD_INFORMATION
	{
		long long CreationTime;
		long long LastModificationTime;
		long long LastChangeTime;
		long long LastAccessTime;
		unsigned long FileAttributes;
		// There's more, but only in newer versions
	};
	struct INDEX_HEADER
	{
		unsigned long FirstIndexEntry;
		unsigned long FirstFreeByte;
		unsigned long BytesAvailable;
		unsigned char Flags;  // '1' == has INDEX_ALLOCATION
		unsigned char Reserved[3];
	};
	struct INDEX_ROOT
	{
		AttributeTypeCode Type;
		unsigned long CollationRule;
		unsigned long BytesPerIndexBlock;
		unsigned char ClustersPerIndexBlock;
		INDEX_HEADER Header;
	};
	struct ATTRIBUTE_LIST
	{
		AttributeTypeCode AttributeType;
		unsigned short Length;
		unsigned char NameLength;
		unsigned char NameOffset;
		unsigned long long StartVcn; // LowVcn
		unsigned long long FileReferenceNumber;
		unsigned short AttributeNumber;
		unsigned short AlignmentOrReserved[3];
	};
	static struct { TCHAR const *data; size_t size; } attribute_names [] =
	{
#define X(S) { _T(S), sizeof(_T(S)) / sizeof(*_T(S)) - 1 }
		X(""),
		X("$STANDARD_INFORMATION"),
		X("$ATTRIBUTE_LIST"),
		X("$FILE_NAME"),
		X("$OBJECT_ID"),
		X("$SECURITY_DESCRIPTOR"),
		X("$VOLUME_NAME"),
		X("$VOLUME_INFORMATION"),
		X("$DATA"),
		X("$INDEX_ROOT"),
		X("$INDEX_ALLOCATION"),
		X("$BITMAP"),
		X("$REPARSE_POINT"),
		X("$EA_INFORMATION"),
		X("$EA"),
		X("$PROPERTY_SET"),
		X("$LOGGED_UTILITY_STREAM"),
#undef  X
	};
}

std::tstring NormalizePath(std::tstring const &path)
{
	std::tstring result;
	bool wasSep = false;
	bool isCurrentlyOnPrefix = true;
	for (size_t i = 0; i < path.size(); i++)
	{
		TCHAR const &c = path[i];
		isCurrentlyOnPrefix &= isdirsep(c);
		if (isCurrentlyOnPrefix || !wasSep || !isdirsep(c)) { result += c; }
		wasSep = isdirsep(c);
	}
	if (!isrooted(result.begin(), result.end()))
	{
		std::tstring currentDir(32 * 1024, _T('\0'));
		currentDir.resize(GetCurrentDirectory(static_cast<DWORD>(currentDir.size()), &currentDir[0]));
		adddirsep(currentDir);
		result = currentDir + result;
	}
	return result;
}

std::tstring GetDisplayName(HWND hWnd, const std::tstring &path, DWORD shgdn)
{
	ATL::CComPtr<IShellFolder> desktop;
	STRRET ret;
	LPITEMIDLIST shidl;
	ATL::CComBSTR bstr;
	ULONG attrs = SFGAO_ISSLOW | SFGAO_HIDDEN;
	std::tstring result = (
		SHGetDesktopFolder(&desktop) == S_OK
		&& desktop->ParseDisplayName(hWnd, NULL, path.empty() ? NULL : const_cast<LPWSTR>(path.c_str()), NULL, &shidl, &attrs) == S_OK
		&& (attrs & SFGAO_ISSLOW) == 0
		&& desktop->GetDisplayNameOf(shidl, shgdn, &ret) == S_OK
		&& StrRetToBSTR(&ret, shidl, &bstr) == S_OK
		) ? static_cast<LPCTSTR>(bstr) : std::tstring(basename(path.begin(), path.end()), path.end());
	return result;
}

void CheckAndThrow(int const success) { if (!success) { RaiseException(GetLastError(), 0, 0, NULL); } }

LPTSTR GetAnyErrorText(DWORD errorCode, va_list* pArgList = NULL)
{
	static TCHAR buffer[1 << 15];
	ZeroMemory(buffer, sizeof(buffer));
	if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | (pArgList == NULL ? FORMAT_MESSAGE_IGNORE_INSERTS : 0), NULL, errorCode, 0, buffer, sizeof(buffer) / sizeof(*buffer), pArgList))
	{
		if (!FormatMessage(FORMAT_MESSAGE_FROM_HMODULE | (pArgList == NULL ? FORMAT_MESSAGE_IGNORE_INSERTS : 0), GetModuleHandle(_T("NTDLL.dll")), errorCode, 0, buffer, sizeof(buffer) / sizeof(*buffer), pArgList))
		{ _stprintf(buffer, _T("%#x"), errorCode); }
	}
	return buffer;
}

class Handle
{
	static bool valid(void *const value) { return value && value != reinterpret_cast<void *>(-1); }
public:
	void *value;
	Handle() : value() { }
	explicit Handle(void *const value) : value(value)
	{
		if (!valid(value))
		{ throw std::invalid_argument("invalid handle"); }
	}
	Handle(Handle const &other) : value(other.value)
	{
		if (valid(this->value))
		{ CheckAndThrow(DuplicateHandle(GetCurrentProcess(), this->value, GetCurrentProcess(), &this->value, MAXIMUM_ALLOWED, TRUE, DUPLICATE_SAME_ACCESS)); }
	}
	~Handle() { if (valid(this->value)) { CloseHandle(value); } }
	Handle &operator =(Handle other) { return other.swap(*this), *this; }
	operator void *() const { return this->value; }
	void swap(Handle &other) { using std::swap; swap(this->value, other.value); }
	friend void swap(Handle &a, Handle &b) { return a.swap(b); }
};

template<class T, class Alloc =
#if defined(MEMORY_HEAP_HPP)
	memheap::MemoryHeapAllocator
#else
	std::allocator
#endif
	<T>
>
class memheap_vector : std::vector<T, Alloc>
{
	typedef std::vector<T, Alloc> base_type;
	typedef memheap_vector this_type;
protected:
	typename base_type::size_type _reserve(typename base_type::size_type extra_capacity)
	{
		typename base_type::size_type extra_reserved = 0;
#if defined(MEMORY_HEAP_HPP) && defined(_CPPLIB_VER) && 600 <= _CPPLIB_VER && _CPPLIB_VER <= 699
		typename base_type::size_type const current_capacity = this->base_type::capacity();
		if (current_capacity > 0 && extra_capacity > current_capacity - this->base_type::size())
		{
			extra_capacity = this->base_type::_Grow_to(current_capacity + extra_capacity) - current_capacity;
			if (typename base_type::pointer const ptr = this->base_type::get_allocator().allocate(extra_capacity, this->base_type::_Myend(), true))
			{
				if (ptr == this->base_type::_Myend())
				{
					this->base_type::_Myend() = ptr + static_cast<typename base_type::difference_type>(extra_capacity);
					extra_reserved = extra_capacity;
				}
				else
				{
					this->base_type::get_allocator().deallocate(ptr, extra_capacity);
				}
			}
		}
#else
		(void) extra_capacity;
#endif
		return extra_reserved;
	}
public:
	typedef typename base_type::allocator_type allocator_type;
	typedef typename base_type::value_type value_type;
	// typedef typename base_type::pointer pointer;
	// typedef typename base_type::const_pointer const_pointer;
	typedef typename base_type::reference reference;
	typedef typename base_type::const_reference const_reference;
	typedef typename base_type::iterator iterator;
	typedef typename base_type::const_iterator const_iterator;
	typedef typename base_type::reverse_iterator reverse_iterator;
	typedef typename base_type::const_reverse_iterator const_reverse_iterator;
	typedef typename base_type::size_type size_type;
	typedef typename base_type::difference_type difference_type;
	memheap_vector() : base_type() { }
	memheap_vector(base_type const &other) : base_type(other) { }
	explicit memheap_vector(allocator_type const &alloc) : base_type(alloc) { }
	using base_type::begin;
	using base_type::end;
	using base_type::rbegin;
	using base_type::rend;
	using base_type::size;
	using base_type::empty;
	using base_type::capacity;
	using base_type::clear;
	void swap(this_type &other) { this->base_type::swap(static_cast<this_type &>(other)); }
	friend void swap(this_type &me, this_type &other) { return me.swap(other); }
	void reserve(size_type const size)
	{
		typename base_type::size_type const current_size = this->base_type::size(), size_difference = size > current_size ? size - current_size : 0;
		if (size_difference && this->_reserve(size_difference) < size_difference)
		{
			this->base_type::reserve(size);
		}
	}
	void push_back(value_type const &value) { this->_reserve(1); return this->base_type::push_back(value); }
};

unsigned int get_cluster_size(void *const volume)
{
	winnt::IO_STATUS_BLOCK iosb;
	winnt::FILE_FS_SIZE_INFORMATION info = {};
	if (winnt::NtQueryVolumeInformationFile(volume, &iosb, &info, sizeof(info), 3))
	{ SetLastError(ERROR_INVALID_FUNCTION), CheckAndThrow(false); }
	return info.BytesPerSector * info.SectorsPerAllocationUnit;
}

std::vector<std::pair<unsigned long long, long long> > get_mft_retrieval_pointers(void *const volume, TCHAR const path[], long long *const size, long long const mft_start_lcn, unsigned int const file_record_size)
{
	(void) mft_start_lcn;
	(void) file_record_size;
	typedef std::vector<std::pair<unsigned long long, long long> > Result;
	Result result;
	Handle handle;
	{
		Handle root_dir;
		{
			unsigned long long root_dir_id = 0x0005000000000005;
			winnt::UNICODE_STRING us = { sizeof(root_dir_id), sizeof(root_dir_id), reinterpret_cast<wchar_t *>(&root_dir_id) };
			winnt::OBJECT_ATTRIBUTES oa = { sizeof(oa), volume, &us };
			winnt::IO_STATUS_BLOCK iosb;
			unsigned long const error = winnt::RtlNtStatusToDosError(winnt::NtOpenFile(&root_dir.value, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0x00002000 /* FILE_OPEN_BY_FILE_ID */ | 0x00000020 /* FILE_SYNCHRONOUS_IO_NONALERT */));
			if (error) { SetLastError(error); CheckAndThrow(!error); }
		}
		{
			size_t const cch = path ? std::char_traits<TCHAR>::length(path) : 0;
			winnt::UNICODE_STRING us = { static_cast<unsigned short>(cch * sizeof(*path)), static_cast<unsigned short>(cch * sizeof(*path)), const_cast<TCHAR *>(path) };
			winnt::OBJECT_ATTRIBUTES oa = { sizeof(oa), root_dir, &us };
			winnt::IO_STATUS_BLOCK iosb;
			unsigned long const error = winnt::RtlNtStatusToDosError(winnt::NtOpenFile(&handle.value, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0x00200000 /* FILE_OPEN_REPARSE_POINT */ | 0x00000020 /* FILE_SYNCHRONOUS_IO_NONALERT */));
			if (error) { SetLastError(error); CheckAndThrow(!error); }
		}
	}
	result.resize(1 + (sizeof(RETRIEVAL_POINTERS_BUFFER) - 1) / sizeof(Result::value_type));
	STARTING_VCN_INPUT_BUFFER input = {};
	BOOL success;
	for (unsigned long nr; !(success = DeviceIoControl(handle, FSCTL_GET_RETRIEVAL_POINTERS, &input, sizeof(input), &*result.begin(), static_cast<unsigned long>(result.size()) * sizeof(*result.begin()), &nr, NULL), success) && GetLastError() == ERROR_MORE_DATA;)
	{
		size_t const n = result.size();
		Result(/* free old memory */).swap(result);
		Result(n * 2).swap(result);
	}
	CheckAndThrow(success);
	if (size)
	{
		LARGE_INTEGER large_size;
		CheckAndThrow(GetFileSizeEx(handle, &large_size));
		*size = large_size.QuadPart;
	}
	result.erase(result.begin() + 1 + reinterpret_cast<unsigned long const &>(*result.begin()), result.end());
	result.erase(result.begin(), result.begin() + 1);
	return result;
}

template<class From, class To> struct propagate_const { typedef To type; };
template<class From, class To> struct propagate_const<From const, To> : propagate_const<From, To const> { };
template<class From, class To> struct propagate_const<From &, To> : propagate_const<From, To> { };

namespace atomic_namespace =
#ifdef BOOST_ATOMIC_ATOMIC_HPP_INCLUDED_
	boost
#else
	std
#endif
	;

template<class Derived>
class RefCounted
{
	mutable atomic_namespace::atomic<unsigned int> refs;
	friend void intrusive_ptr_add_ref(RefCounted const volatile *p) { p->refs.fetch_add(1, atomic_namespace::memory_order_acq_rel); }
	friend void intrusive_ptr_release(RefCounted const volatile *p)
	{
		if (p->refs.fetch_sub(1, atomic_namespace::memory_order_acq_rel) - 1 == 0)
		{
			delete static_cast<Derived const volatile *>(p);
		}
	}

protected:
	RefCounted() : refs(0) { }
	RefCounted(RefCounted const &) : refs(0) { }
	~RefCounted() { }
	RefCounted &operator =(RefCounted const &) { }
	void swap(RefCounted &) { }
};

class Overlapped : public OVERLAPPED, public RefCounted<Overlapped>
{
	Overlapped(Overlapped const &);
	Overlapped &operator =(Overlapped const &);
public:
	virtual ~Overlapped() { }
	Overlapped() : OVERLAPPED() { }
	virtual int /* > 0 if re-queue requested, = 0 if no re-queue but no destruction, < 0 if destruction requested */ operator()(size_t const size, uintptr_t const /*key*/) = 0;
	long long offset() const
	{
		return (static_cast<long long>(this->OVERLAPPED::OffsetHigh) << (CHAR_BIT * sizeof(this->OVERLAPPED::Offset))) | this->OVERLAPPED::Offset;
	}
	void offset(long long const value)
	{
		this->OVERLAPPED::Offset = static_cast<unsigned long>(value);
		this->OVERLAPPED::OffsetHigh = static_cast<unsigned long>(value >> (CHAR_BIT * sizeof(this->OVERLAPPED::Offset)));
	}
};

static clock_t const begin_time = clock();

static struct negative_one
{
	template<class T>
	operator T() const { return static_cast<T>(~T()); }
} const negative_one;

template<size_t V>
class constant
{
	template<size_t I, size_t N>
	struct impl;
public:
	friend size_t operator *(size_t const m, constant<V> const)
	{
		return impl<0, sizeof(V) * CHAR_BIT>::multiply(m);
	}
};
template<size_t V> template<size_t I, size_t N> struct constant<V>::impl
{
	static size_t multiply(size_t const m) { return impl<I, N / 2>::multiply(m) + impl<I + N / 2, N - N / 2>::multiply(m); }
};
template<size_t V> template<size_t I> struct constant<V>::impl<I, 1>
{
	static size_t multiply(size_t const m) { return (V & static_cast<size_t>(static_cast<size_t>(1) << I)) ? static_cast<size_t>(m << I) : size_t(); }
};
template<> class constant<0xD> { public: friend size_t operator *(size_t const m, constant<0xD> const) { return (m << 4) - (m << 1) - m; } };

template<class It>
typename propagate_const<typename std::iterator_traits<It>::reference, typename std::iterator_traits<It>::value_type>::type *fast_subscript(It const it, size_t const i)
{
	return
#if 1
		&*(it + static_cast<ptrdiff_t>(i))
#else
		reinterpret_cast<typename propagate_const<typename std::iterator_traits<It>::reference, typename std::iterator_traits<It>::value_type>::type *>(
			reinterpret_cast<typename propagate_const<typename std::iterator_traits<It>::reference, unsigned char>::type *>(&*it) + i * constant<sizeof(*it)>())
#endif
		;
}

class buffer
{
	typedef buffer this_type;
	typedef void value_type_internal;
	typedef value_type_internal *pointer_internal;
	typedef size_t size_type_internal;
	typedef ptrdiff_t difference_type;
	pointer_internal p;
	size_type_internal c, n;
	void init() { if (!this->p && this->c) { using namespace std; this->p = malloc(this->c); } }
public:
	typedef value_type_internal value_type;
	typedef size_type_internal size_type;
	typedef pointer_internal pointer;
	typedef value_type const *const_pointer;
	typedef unsigned char &reference;
	typedef unsigned char const &const_reference;
	typedef unsigned char *iterator;
	typedef unsigned char const *const_iterator;
	~buffer() { using namespace std; free(this->p); }
	buffer() : p(), c(), n() { }
	explicit buffer(size_type const c) : p(), c(c), n() { this->init(); }
	buffer(this_type const &other) : p(), c(other.c), n() { this->init(); this->n = static_cast<size_type>(std::uninitialized_copy(other.begin(), other.end(), this->begin()) - this->begin()); }
	pointer get() const { return this->p; }
	size_type size() const { return this->n; }
	size_type capacity() const { return this->c; }
	this_type &operator =(this_type other) { return other.swap(*this), *this; }
	pointer tail() { return static_cast<unsigned char *>(this->p) + static_cast<ptrdiff_t>(this->n); }
	const_pointer tail() const { return static_cast<unsigned char const *>(this->p) + static_cast<ptrdiff_t>(this->n); }
	void swap(this_type &other) { using std::swap; swap(this->p, other.p); swap(this->c, other.c); swap(this->n, other.n); }
	friend void swap(this_type &a, this_type &b) { return a.swap(b); }
	iterator begin() { return static_cast<iterator>(this->get()); }
	const_iterator begin() const { return static_cast<const_iterator>(this->get()); }
	iterator end() { return static_cast<iterator>(this->tail()); }
	const_iterator end() const { return static_cast<const_iterator>(this->tail()); }
	bool empty() const { return !this->n; }
	void clear() { buffer().swap(*this); }
	template<class T>
	T *emplace_back(size_type const size = sizeof(T))
	{
		size_type const old_size = this->size();
		this->resize(old_size + size);
		return new (static_cast<unsigned char *>(this->get()) + static_cast<difference_type>(old_size)) T;
	}
	reference operator[](size_type const i) { return *(this->begin() + static_cast<difference_type>(i)); }
	const_reference operator[](size_type const i) const { return *(this->begin() + static_cast<difference_type>(i)); }
	// These arguments are in BYTES and not elements, so users might get confused
	void reserve_bytes(size_type c)
	{
		if (c > this->c)
		{
			size_type const min_c = this->c + this->c / 2;
			if (c < min_c) { c = min_c; }
			using namespace std;
			this->p = realloc(this->p, this->n);  // shrink first, to avoid copying memory beyond the block
			this->c = this->n;
			this->p = realloc(this->p, c);
			this->c = c;
		}
	}
private:
	void resize(size_type const n)
	{
		if (n <= this->c)
		{
			// No destructors to call here...
			this->n = n;
		}
		else
		{
			size_type c = this->c + this->c / 2;
			if (c < n) { c = n; }
			using namespace std;
			this->p = c ? realloc(this->p, c) : NULL;
			this->n = n;
		}
	}
};

class NtfsIndex : public RefCounted<NtfsIndex>
{
	typedef NtfsIndex this_type;
	template<class = void> struct small_t { typedef unsigned int type; };
#pragma pack(push, 1)
	class file_size_type
	{
		unsigned int low;
		unsigned short high;
		typedef file_size_type this_type;
	public:
		file_size_type() : low(), high() { }
		file_size_type(unsigned long long const value) : low(static_cast<unsigned int>(value)), high(static_cast<unsigned short>(value >> (sizeof(unsigned int) * CHAR_BIT))) { }
		operator unsigned long long() const { return (static_cast<unsigned long long>(this->high) << (sizeof(unsigned int) * CHAR_BIT)) | this->low; }
		this_type &operator+=(unsigned long long const &other) { return *this = *this + other; }
	};
	struct StandardInfo
	{
		unsigned long long created, written, accessed;
		unsigned long attributes;
	};
	struct SizeInfo
	{
		file_size_type length, allocated, bulkiness;
	};
	friend struct std::is_scalar<StandardInfo>;
	struct NameInfo
	{
		small_t<size_t>::type offset;
		unsigned char length;
	};
	friend struct std::is_scalar<NameInfo>;
	struct LinkInfo
	{
		LinkInfo() : next_entry(negative_one) { this->name.offset = negative_one; }
		typedef small_t<size_t>::type next_entry_type; next_entry_type next_entry;
		NameInfo name;
		unsigned int parent;
	};
	friend struct std::is_scalar<LinkInfo>;
	struct StreamInfo : SizeInfo
	{
		StreamInfo() : SizeInfo(), next_entry(), name(), type_name_id() { }
		typedef small_t<size_t>::type next_entry_type; next_entry_type next_entry;
		NameInfo name;
		unsigned char type_name_id /* zero if and only if $I30:$INDEX_ROOT or $I30:$INDEX_ALLOCATION */;
	};
	friend struct std::is_scalar<StreamInfo>;
	typedef std::codecvt<std::tstring::value_type, char, int /*std::mbstate_t*/> CodeCvt;
	typedef std::vector<LinkInfo> LinkInfos;
	typedef std::vector<StreamInfo> StreamInfos;
	struct Record;
	typedef std::vector<Record> Records;
	typedef std::vector<unsigned int> RecordsLookup;
	struct ChildInfo
	{
		ChildInfo() : next_entry(negative_one), record_number(negative_one), name_index(negative_one) { }
		typedef small_t<size_t>::type next_entry_type; next_entry_type next_entry;
		small_t<Records::size_type>::type record_number;
		unsigned short name_index;
	};
	typedef std::vector<ChildInfo> ChildInfos;
	struct Record
	{
		StandardInfo stdinfo;
		unsigned short name_count, stream_count;
		ChildInfos::value_type::next_entry_type first_child;
		LinkInfos::value_type first_name;
		StreamInfos::value_type first_stream;
		Record() : stdinfo(), name_count(), stream_count(), first_name(), first_stream(), first_child(negative_one)
		{
			this->stdinfo.attributes = negative_one;
			this->first_stream.name.offset = negative_one;
			this->first_stream.next_entry = negative_one;
		}
	};
#pragma pack(pop)
	friend struct std::is_scalar<Record>;
	mutable mutex _mutex;
	bool _init_called, _failed;
	std::tstring _root_path;
	Handle _volume;
	std::tstring names;
	Records records_data;
	RecordsLookup records_lookup;
	LinkInfos nameinfos;
	StreamInfos streaminfos;
	ChildInfos childinfos;
	Handle _finished_event;
	size_t _total_names_and_streams;
	unsigned int _expected_records;
	atomic_namespace::atomic<bool> _cancelled;
	atomic_namespace::atomic<unsigned int> _records_so_far;
#pragma pack(push, 1)
	struct key_type_internal
	{
		typedef unsigned int frs_type; frs_type frs;
		typedef unsigned short name_info_type; name_info_type name_info;
		typedef unsigned short stream_info_type; stream_info_type stream_info;
		typedef RecordsLookup::value_type direct_address_type; direct_address_type direct_address;
	};
#pragma pack(pop)

	Records::iterator at(size_t const frs, Records::iterator *const existing_to_revalidate = NULL)
	{
		if (frs >= this->records_lookup.size())
		{ this->records_lookup.resize(frs + 1, ~RecordsLookup::value_type()); }
		RecordsLookup::iterator const k = this->records_lookup.begin() + static_cast<ptrdiff_t>(frs);
		if (!~*k)
		{
			ptrdiff_t const j = (existing_to_revalidate ? *existing_to_revalidate : this->records_data.end()) - this->records_data.begin();
			*k = static_cast<unsigned int>(this->records_data.size());
			this->records_data.resize(this->records_data.size() + 1);
			if (existing_to_revalidate) { *existing_to_revalidate = this->records_data.begin() + j; }
		}
		return this->records_data.begin() + static_cast<ptrdiff_t>(*k);
	}

	template<class Me>
	static typename propagate_const<Me, Records::value_type>::type *_find(Me *const me, key_type_internal::frs_type const frs)
	{
		typedef typename propagate_const<Me, Records::value_type>::type *pointer_type;
		pointer_type result;
		if (frs < me->records_lookup.size())
		{
			RecordsLookup::value_type const islot = me->records_lookup[frs];
			// The complicated logic here is to remove the 'imul' instruction...
			result = fast_subscript(me->records_data.begin(), islot);
		}
		else
		{
			result = me->records_data.empty() ? NULL : &*(me->records_data.end() - 1) + 1;
		}
		return result;
	}

	Records::value_type * find(key_type_internal::frs_type const frs) { return this->_find(this, frs); }
	Records::value_type const * find(key_type_internal::frs_type const frs) const { return this->_find(this, frs); }

	ChildInfos::value_type *childinfo(Records::value_type *const i) { return this->childinfo(i->first_child); }
	ChildInfos::value_type const *childinfo(Records::value_type const *const i) const { return this->childinfo(i->first_child); }
	ChildInfos::value_type *childinfo(ChildInfo::next_entry_type const i) { return !~i ? NULL : fast_subscript(this->childinfos.begin(), i); }
	ChildInfos::value_type const *childinfo(ChildInfo::next_entry_type const i) const { return !~i ? NULL : fast_subscript(this->childinfos.begin(), i); }
	LinkInfos::value_type *nameinfo(LinkInfo::next_entry_type const i) { return !~i ? NULL : fast_subscript(this->nameinfos.begin(), i); }
	LinkInfos::value_type const *nameinfo(LinkInfo::next_entry_type const i) const { return !~i ? NULL : fast_subscript(this->nameinfos.begin(), i); }
	LinkInfos::value_type *nameinfo(Records::value_type *const i) { return ~i->first_name.name.offset ? &i->first_name : NULL; }
	LinkInfos::value_type const *nameinfo(Records::value_type const *const i) const { return ~i->first_name.name.offset ? &i->first_name : NULL; }
	StreamInfos::value_type *streaminfo(StreamInfo::next_entry_type const i) { return !~i ? NULL : fast_subscript(this->streaminfos.begin(), i); }
	StreamInfos::value_type const *streaminfo(StreamInfo::next_entry_type const i) const { return !~i ? NULL : fast_subscript(this->streaminfos.begin(), i); }
	StreamInfos::value_type *streaminfo(Records::value_type *const i) { assert(~i->first_stream.name.offset || (!i->first_stream.name.length && !i->first_stream.length)); return ~i->first_stream.name.offset ? &i->first_stream : NULL; }
	StreamInfos::value_type const *streaminfo(Records::value_type const *const i) const { assert(~i->first_stream.name.offset || (!i->first_stream.name.length && !i->first_stream.length)); return ~i->first_stream.name.offset ? &i->first_stream : NULL; }
public:
	typedef key_type_internal key_type;
	typedef StandardInfo standard_info;
	typedef SizeInfo size_info;
	unsigned int mft_record_size;
	unsigned int mft_capacity;
	NtfsIndex(std::tstring value) : _init_called(), _failed(), _root_path(value), _finished_event(CreateEvent(NULL, TRUE, FALSE, NULL)), _total_names_and_streams(), _records_so_far(0), _expected_records(0), _cancelled(false), mft_record_size(), mft_capacity()
	{
	}
	~NtfsIndex()
	{
	}
	bool init_called() const { return this->_init_called; }
	void init()
	{
		this->_init_called = true;
		bool success = false;
		std::tstring dirsep;
		dirsep.append(1, _T('\\'));
		dirsep.append(1, _T('/'));
		try
		{
			std::tstring path_name = this->_root_path;
			path_name.erase(path_name.begin() + static_cast<ptrdiff_t>(path_name.size() - std::min(path_name.find_last_not_of(dirsep), path_name.size())), path_name.end());
			if (!path_name.empty() && *path_name.begin() != _T('\\') && *path_name.begin() != _T('/')) { path_name.insert(0, _T("\\\\.\\")); }
			Handle volume(CreateFile(path_name.c_str(), FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL));
			winnt::IO_STATUS_BLOCK iosb;
			struct : winnt::FILE_FS_ATTRIBUTE_INFORMATION { unsigned char buf[MAX_PATH]; } info = {};
			if (winnt::NtQueryVolumeInformationFile(volume.value, &iosb, &info, sizeof(info), 5) ||
				info.FileSystemNameLength != 4 * sizeof(*info.FileSystemName) || std::char_traits<TCHAR>::compare(info.FileSystemName, _T("NTFS"), 4))
			{ throw std::invalid_argument("invalid volume"); }
			if (false)
			{
				winnt::FILE_IO_PRIORITY_HINT_INFORMATION io_priority = { winnt::IoPriorityLow };
				winnt::NtSetInformationFile(volume, &iosb, &io_priority, sizeof(io_priority), 43);
			}
			volume.swap(this->_volume);
			success = true;
		}
		catch (std::invalid_argument &) {}
		this->_failed = !success;
		if (!success) { SetEvent(this->_finished_event); }
	}
	NtfsIndex *unvolatile() volatile { return const_cast<NtfsIndex *>(this); }
	NtfsIndex const *unvolatile() const volatile { return const_cast<NtfsIndex *>(this); }
	size_t total_names_and_streams() const volatile
	{
		this_type const *const me = this->unvolatile();
		lock_guard<mutex> const lock(me->_mutex);
		return me->total_names_and_streams();
	}
	size_t total_names_and_streams() const { return this->_total_names_and_streams; }
	size_t total_names() const volatile
	{
		this_type const *const me = this->unvolatile();
		lock_guard<mutex> const lock(me->_mutex);
		return me->total_names();
	}
	size_t total_names() const { return this->nameinfos.size(); }
	size_t expected_records() const volatile
	{
		this_type const *const me = this->unvolatile();
		lock_guard<mutex> const lock(me->_mutex);
		return me->expected_records();
	}
	size_t expected_records() const { return this->_expected_records; }
	size_t records_so_far() const volatile { return this->_records_so_far.load(atomic_namespace::memory_order_acquire); }
	size_t records_so_far() const { return this->_records_so_far.load(atomic_namespace::memory_order_relaxed); }
	void *volume() const volatile { return this->_volume.value; }
	mutex &get_mutex() const volatile { return this->unvolatile()->_mutex; }
	std::tstring const &root_path() const { return this->_root_path; }
	std::tstring const &root_path() const volatile
	{
		this_type const *const me = this->unvolatile();
		lock_guard<mutex> const lock(me->_mutex);
		return me->root_path();
	}
	bool failed() const
	{
		return this->_failed;
	}
	bool cancelled() const volatile
	{
		this_type const *const me = this->unvolatile();
		return me->_cancelled.load(atomic_namespace::memory_order_acquire);
	}
	void cancel() volatile
	{
		this_type *const me = this->unvolatile();
		me->_cancelled.store(true, atomic_namespace::memory_order_release);
	}
	uintptr_t finished_event() const volatile
	{
		this_type const *const me = this->unvolatile();
		lock_guard<mutex> const lock(me->_mutex);
		return me->finished_event();
	}
	uintptr_t finished_event() const
	{
		return reinterpret_cast<uintptr_t>(this->_finished_event.value);
	}
	bool check_finished()
	{
		unsigned int const records_so_far = this->_records_so_far.load(atomic_namespace::memory_order_acquire);
		bool const finished = records_so_far >= this->mft_capacity;
		bool const b = finished && !this->_root_path.empty();
		if (b)
		{
			size_t volatile arr[] =
			{
				this->names.size() * sizeof(*this->names.begin()),
				this->records_data.size() * sizeof(*this->records_data.begin()),
				this->records_lookup.size() * sizeof(*this->records_lookup.begin()),
				this->nameinfos.size() * sizeof(*this->nameinfos.begin()),
				this->streaminfos.size() * sizeof(*this->streaminfos.begin()),
				this->childinfos.size() * sizeof(*this->childinfos.begin()),
			};
			for (size_t i = 0; i < sizeof(arr) / sizeof(*arr); i++)
			{
				arr[i] = arr[i];
			}
			typedef std::tstring::const_iterator It;
			this->preprocess(0x000000000005);
			Handle().swap(this->_volume);
			_ftprintf(stderr, _T("Finished: %s (%u ms)\n"), this->_root_path.c_str(), (clock() - begin_time) * 1000U / CLOCKS_PER_SEC);
		}
		finished ? SetEvent(this->_finished_event) : ResetEvent(this->_finished_event);
		return b;
	}
	void reserve(unsigned int const records) volatile
	{
		this_type *const me = this->unvolatile();
		lock_guard<mutex> const lock(me->_mutex);
		me->reserve(records);
	}
	void reserve(unsigned int const records)
	{
		this->_expected_records = records;
		try
		{
			if (this->records_lookup.size() < records)
			{
				this->nameinfos.reserve(records + records / 16);
				this->streaminfos.reserve(records / 4);
				this->childinfos.reserve(records + records / 2);
				this->names.reserve(records * 23);
				this->records_lookup.resize(records, ~RecordsLookup::value_type());
				this->records_data.reserve(records + records / 4);
			}
		}
		catch (std::bad_alloc &) { }
	}
	void load(unsigned long long const virtual_offset, void *const buffer, size_t const size) volatile
	{
		this_type *const me = this->unvolatile();
		lock_guard<mutex> const lock(me->_mutex);
		// TODO: This lock prevents parallelism. Instead, add the entries to a private queue locally, then transfer them in bulk.
		me->load(virtual_offset, buffer, size);
	}
	void load(unsigned long long const virtual_offset, void *const buffer, size_t const size)
	{
		if (size % this->mft_record_size)
		{ throw std::runtime_error("cluster size is smaller than MFT record size; split MFT records not supported"); }
		for (size_t i = virtual_offset % this->mft_record_size ? this->mft_record_size - virtual_offset % this->mft_record_size : 0; i + this->mft_record_size <= size; i += this->mft_record_size, this->_records_so_far.fetch_add(1, atomic_namespace::memory_order_acq_rel))
		{
			unsigned int const frs = static_cast<unsigned int>((virtual_offset + i) / this->mft_record_size);
			ntfs::FILE_RECORD_SEGMENT_HEADER *const frsh = reinterpret_cast<ntfs::FILE_RECORD_SEGMENT_HEADER *>(&static_cast<unsigned char *>(buffer)[i]);
			if (frsh->MultiSectorHeader.Magic == 'ELIF' && frsh->MultiSectorHeader.unfixup(this->mft_record_size) && !!(frsh->Flags & ntfs::FRH_IN_USE))
			{
				unsigned int const frs_base = frsh->BaseFileRecordSegment ? static_cast<unsigned int>(frsh->BaseFileRecordSegment) : frs;
				Records::iterator base_record = this->at(frs_base);
				for (ntfs::ATTRIBUTE_RECORD_HEADER const
					*ah = frsh->begin(); ah < frsh->end(this->mft_record_size) && ah->Type != ntfs::AttributeTypeCode() && ah->Type != ntfs::AttributeEnd; ah = ah->next())
				{
					switch (ah->Type)
					{
					case ntfs::AttributeStandardInformation:
						if (ntfs::STANDARD_INFORMATION const *const fn = static_cast<ntfs::STANDARD_INFORMATION const *>(ah->Resident.GetValue()))
						{
							base_record->stdinfo.created = fn->CreationTime;
							base_record->stdinfo.written = fn->LastModificationTime;
							base_record->stdinfo.accessed = fn->LastAccessTime;
							base_record->stdinfo.attributes = fn->FileAttributes | ((frsh->Flags & ntfs::FRH_DIRECTORY) ? FILE_ATTRIBUTE_DIRECTORY : 0);
						}
						break;
					case ntfs::AttributeFileName:
						if (ntfs::FILENAME_INFORMATION const *const fn = static_cast<ntfs::FILENAME_INFORMATION const *>(ah->Resident.GetValue()))
						{
							unsigned int const frs_parent = static_cast<unsigned int>(fn->ParentDirectory);
							if (fn->Flags != 0x02 /* FILE_NAME_DOS */)
							{
								if (LinkInfos::value_type *const si = this->nameinfo(&*base_record))
								{
									size_t const link_index = this->nameinfos.size();
									this->nameinfos.push_back(base_record->first_name);
									base_record->first_name = LinkInfos::value_type();
									base_record->first_name.next_entry = static_cast<LinkInfos::value_type::next_entry_type>(link_index);
								}
								base_record->first_name.name.offset = static_cast<unsigned int>(this->names.size());
								base_record->first_name.name.length = static_cast<unsigned char>(fn->FileNameLength);
								base_record->first_name.parent = frs_parent;
								append(this->names, fn->FileName, fn->FileNameLength);
								Records::iterator const parent = this->at(frs_parent, &base_record);
								size_t const child_index = this->childinfos.size();
								ChildInfo child_info = ChildInfo();
								child_info.record_number = frs_base;
								child_info.name_index = base_record->name_count;
								child_info.next_entry = parent->first_child;
								this->childinfos.push_back(child_info);
								parent->first_child = static_cast<ChildInfos::value_type::next_entry_type>(child_index);
								this->_total_names_and_streams += base_record->stream_count;
								++base_record->name_count;
							}
						}
						break;
					// case ntfs::AttributeAttributeList:
					// case ntfs::AttributeLoggedUtilityStream:
					case ntfs::AttributeBitmap:
					case ntfs::AttributeIndexAllocation:
					case ntfs::AttributeIndexRoot:
					case ntfs::AttributeData:
					case ntfs::AttributeReparsePoint:
					case ntfs::AttributeEA:
					case ntfs::AttributeEAInformation:
						if (!ah->IsNonResident || !ah->NonResident.LowestVCN)
						{
							bool const isI30 = ah->NameLength == 4 && memcmp(ah->name(), _T("$I30"), sizeof(*ah->name()) * 4) == 0;
							if (ah->Type == (isI30 ? ntfs::AttributeIndexAllocation : ntfs::AttributeIndexRoot))
							{
								// Skip this -- for $I30, index header will take care of index allocation; for others, no point showing index root anyway
							}
							else if (!(isI30 && ah->Type == ntfs::AttributeBitmap))
							{
								StreamInfo info = StreamInfo();
								if ((ah->Type == ntfs::AttributeIndexRoot || ah->Type == ntfs::AttributeIndexAllocation) && isI30)
								{
									// Suppress name
								}
								else
								{
									info.name.offset = static_cast<unsigned int>(this->names.size());
									info.name.length = static_cast<unsigned char>(ah->NameLength);
									append(this->names, ah->name(), ah->NameLength);
								}
								info.type_name_id = static_cast<unsigned char>((ah->Type == ntfs::AttributeIndexRoot || ah->Type == ntfs::AttributeIndexAllocation) && isI30 ? 0 : ah->Type >> (CHAR_BIT / 2));
								info.length = ah->IsNonResident ? static_cast<file_size_type>(frs_base == 0x000000000008 /* $BadClus */ ? ah->NonResident.InitializedSize /* actually this is still wrong... */ : ah->NonResident.DataSize) : ah->Resident.ValueLength;
								info.allocated = ah->IsNonResident ? ah->NonResident.CompressionUnit ? static_cast<file_size_type>(ah->NonResident.CompressedSize) : static_cast<file_size_type>(frs_base == 0x000000000008 /* $BadClus */ ? ah->NonResident.InitializedSize /* actually this is still wrong... should be looking at VCNs */ : ah->NonResident.AllocatedSize) : 0;
								info.bulkiness = info.allocated;
								if (StreamInfos::value_type *const si = this->streaminfo(&*base_record))
								{
									size_t const stream_index = this->streaminfos.size();
									this->streaminfos.push_back(*si);
									si->next_entry = static_cast<small_t<size_t>::type>(stream_index);
								}
								info.next_entry = base_record->first_stream.next_entry;
								base_record->first_stream = info;
								this->_total_names_and_streams += base_record->name_count;
								++base_record->stream_count;
							}
						}
						break;
					}
				}
				// fprintf(stderr, "%llx\n", frsh->BaseFileRecordSegment);
			}
		}
		this->check_finished();
	}

	size_t get_path(key_type key, std::tstring &result, bool const name_only) const volatile
	{
		this_type const *const me = this->unvolatile();
		if (!name_only && WaitForSingleObject(me->_finished_event, 0) == WAIT_TIMEOUT)
		{ return 0; }
		lock_guard<mutex> const lock(me->_mutex);
		return me->get_path(key, result, name_only);
	}

	size_t get_path(key_type key, std::tstring &result, bool const name_only) const
	{
		size_t const old_size = result.size();
		bool leaf = true;
		while (~key.frs)
		{
			Records::value_type const * const fr = this->find(key.frs);
			bool found = false;
			unsigned short ji = 0;
			for (LinkInfos::value_type const *j = this->nameinfo(fr); !found && j; j = this->nameinfo(j->next_entry), ++ji)
			{
				if (key.name_info == (std::numeric_limits<unsigned short>::max)() || ji == key.name_info)
				{
					unsigned short ki = 0;
					for (StreamInfos::value_type const *k = this->streaminfo(fr); !found && k; k = this->streaminfo(k->next_entry), ++ki)
					{
						if (k->name.offset + k->name.length > this->names.size()) { throw std::logic_error("invalid entry"); }
						if (key.stream_info == (std::numeric_limits<unsigned short>::max)() ? !k->type_name_id : ki == key.stream_info)
						{
							found = true;
							size_t const old_size2 = result.size();
							append(result, &this->names[j->name.offset], j->name.length);
							if (leaf)
							{
								bool const is_alternate_stream = k->type_name_id && (k->type_name_id << (CHAR_BIT / 2)) != ntfs::AttributeData;
								if (k->name.length || is_alternate_stream) { result += _T(':'); }
								append(result, k->name.length ? &this->names[k->name.offset] : NULL, k->name.length);
								if (is_alternate_stream && k->type_name_id < sizeof(ntfs::attribute_names) / sizeof(*ntfs::attribute_names))
								{
									result += _T(':'); append(result, ntfs::attribute_names[k->type_name_id].data, ntfs::attribute_names[k->type_name_id].size);
								}
							}
							if (key.frs != 0x000000000005)
							{
								if (!k->type_name_id) { result += _T('\\'); }
							}
							std::reverse(result.begin() + static_cast<ptrdiff_t>(old_size2), result.end());
							key_type const new_key = { j->parent /* ... | 0 | 0 (since we want the first name of all ancestors)*/, static_cast<key_type::name_info_type>(~key_type::name_info_type()), static_cast<key_type::stream_info_type>(~key_type::stream_info_type()), static_cast<key_type::direct_address_type>(std::numeric_limits<key_type::direct_address_type>::max() / 2 + 1) };
							key = new_key;
						}
					}
				}
			}
			if (!found)
			{
				throw std::logic_error("could not find a file attribute");
				break;
			}
			leaf = false;
			if (name_only || key.frs == 0x000000000005) { break; }
		}
		std::reverse(result.begin() + static_cast<ptrdiff_t>(old_size), result.end());
		return result.size() - old_size;
	}

	size_info get_sizes(key_type const key) const volatile
	{
		this_type const *const me = this->unvolatile();
		lock_guard<mutex> const lock(me->_mutex);
		return me->get_sizes(key);
	}

	size_info const &get_sizes(key_type const key) const
	{
		return (~key.direct_address < key.direct_address ? this->records_data[static_cast<key_type::direct_address_type>(~key.direct_address)].first_stream : *this->streaminfo(key.direct_address));
	}

	standard_info get_stdinfo(unsigned int const frn) const volatile
	{
		this_type const *const me = this->unvolatile();
		lock_guard<mutex> const lock(me->_mutex);
		return me->get_stdinfo(frn);
	}

	standard_info const &get_stdinfo(unsigned int const frn) const
	{
		return this->find(frn)->stdinfo;
	}

	std::pair<std::pair<file_size_type, file_size_type>, file_size_type> preprocess(key_type::frs_type const frs)
	{
		std::pair<std::pair<file_size_type, file_size_type>, file_size_type> result;
		if (frs < this->records_lookup.size())
		{
			Records::value_type const * const i = this->find(frs);
			unsigned short const jn = i->name_count;
			unsigned short ji = 0;
			for (LinkInfos::value_type const *j = this->nameinfo(i); j; j = this->nameinfo(j->next_entry), ++ji)
			{
				std::pair<std::pair<file_size_type, file_size_type>, file_size_type> const
					subresult = this->preprocess(frs, ji, jn);
				result.first.first += subresult.first.first;
				result.first.second += subresult.first.second;
				result.second += subresult.second;
				++ji;
			}
		}
		return result;
	}

	std::pair<std::pair<file_size_type, file_size_type>, file_size_type> preprocess(key_type::frs_type const frs, key_type::name_info_type const name_info, unsigned short const total_names)
	{
		std::pair<std::pair<file_size_type, file_size_type>, file_size_type> result;
		if (frs < this->records_lookup.size())
		{
			Records::value_type * const fr = this->find(frs);
			std::pair<std::pair<file_size_type, file_size_type>, file_size_type> children_size;
			unsigned short ii = 0;
			for (ChildInfos::value_type *i = this->childinfo(fr); i && ~i->record_number; i = this->childinfo(i->next_entry), ++ii)
			{
				Records::value_type const *const fr2 = this->find(i->record_number);
				unsigned short const jn = fr2->name_count;
				unsigned short ji = 0;
				for (LinkInfos::value_type const *j = this->nameinfo(fr2); j; j = this->nameinfo(j->next_entry), ++ji)
				{
					if (j->parent == frs && i->name_index == jn - static_cast<size_t>(1) - ji &&
						(static_cast<unsigned int>(i->record_number) != frs || ji != name_info))
					{
						std::pair<std::pair<file_size_type, file_size_type>, file_size_type> const
							subresult = this->preprocess(static_cast<unsigned int>(i->record_number), ji, jn);
						children_size.first.first += subresult.first.first;
						children_size.first.second += subresult.first.second;
					}
				}
			}
			result = children_size;
			unsigned short ki = 0;
			for (StreamInfos::value_type *k = this->streaminfo(fr); k; k = this->streaminfo(k->next_entry), ++ki)
			{
				result.first.first += k->length * (name_info + 1) / total_names - k->length * name_info / total_names;
				result.first.second += k->allocated * (name_info + 1) / total_names - k->allocated * name_info / total_names;
				result.second += k->bulkiness * (name_info + 1) / total_names - k->bulkiness * name_info / total_names;
				if (!k->type_name_id)
				{
					k->length += children_size.first.first;
					k->allocated += children_size.first.second;
					k->bulkiness += children_size.second;
				}
			}
		}
		return result;
	}

	template<class F>
	void matches(F func, std::tstring &path, bool const match_paths, bool const match_streams) const volatile
	{
		this_type const *const me = this->unvolatile();
		lock_guard<mutex> const lock(me->_mutex);
		return me->matches<F &>(func, path, match_paths, match_streams);
	}

	template<class F>
	void matches(F func, std::tstring &path, bool const match_paths, bool const match_streams) const
	{
		Matcher<F &> matcher = { this, func, match_paths, match_streams, &path, 0 };
		return matcher(0x000000000005);
	}

private:
	template<class F>
	struct Matcher
	{
		NtfsIndex const *me;
		F func;
		bool match_paths;
		bool match_streams;
		std::tstring *path;
		size_t basename_index_in_path;
		std::pair<std::tstring::const_iterator, std::tstring::const_iterator> name;
		size_t depth;

		void operator()(key_type::frs_type const frs)
		{
			if (frs < me->records_lookup.size())
			{
				Records::value_type const * const i = me->find(frs);
				unsigned short ji = 0;
				for (LinkInfos::value_type const *j = me->nameinfo(i); j; j = me->nameinfo(j->next_entry), ++ji)
				{
					this->operator()(frs, ji, &me->names[j->name.offset], j->name.length);
				}
			}
		}

		void operator()(key_type::frs_type const frs, key_type::name_info_type const name_info, TCHAR const stream_prefix [], size_t const stream_prefix_size)
		{
			bool const buffered_matching = stream_prefix_size || match_paths || match_streams;
			std::tstring const empty_string;
			if (frs < me->records_lookup.size())
			{
				size_t const islot = me->records_lookup[frs];
				Records::value_type const * const fr = me->find(frs);
				unsigned short ii = 0;
				for (ChildInfos::value_type const *i = me->childinfo(fr); i && ~i->record_number; i = me->childinfo(i->next_entry), ++ii)
				{
					Records::value_type const * const fr2 = me->find(i->record_number);
					unsigned short const jn = fr2->name_count;
					unsigned short ji = 0;
					for (LinkInfos::value_type const *j = me->nameinfo(fr2); j; j = me->nameinfo(j->next_entry), ++ji)
					{
						if (j->parent == frs && i->name_index == jn - static_cast<size_t>(1) - ji)
						{
							size_t const old_size = path->size();
							size_t old_basename_index_in_path = basename_index_in_path;
							std::pair<std::tstring::const_iterator, std::tstring::const_iterator> old_name = name;
							if (buffered_matching)
							{
								if (match_paths || match_streams) { *path += _T('\\'); }
								basename_index_in_path = path->size();
								append(*path, &me->names[j->name.offset], j->name.length);
							}
							name.first = me->names.begin() + static_cast<ptrdiff_t>(j->name.offset);
							name.second = name.first + static_cast<ptrdiff_t>(j->name.length);
							if (static_cast<key_type::frs_type>(i->record_number) != frs || ji != name_info)
							{
								++depth;
								this->operator()(static_cast<key_type::frs_type>(i->record_number), ji, NULL, 0);
								--depth;
							}
							if (buffered_matching)
							{
								path->erase(old_size, path->size() - old_size);
							}
							name = old_name;
							basename_index_in_path = old_basename_index_in_path;
						}
					}
				}
				unsigned short ki = 0;
				for (StreamInfos::value_type const *k0 = me->streaminfo(fr), *k = k0; k; k = me->streaminfo(k->next_entry), ++ki)
				{
					if (k->name.offset > me->names.size()) { throw std::logic_error("invalid entry"); }
					size_t const old_size = path->size();
					if (stream_prefix_size)
					{
						append(*path, stream_prefix, stream_prefix_size);
					}
					if (match_paths || match_streams)
					{
						if ((fr->stdinfo.attributes & FILE_ATTRIBUTE_DIRECTORY) && frs != 0x00000005)
						{
							*path += _T('\\');
						}
					}
					if (match_streams)
					{
						if (k->name.length)
						{
							*path += _T(':');
							append(*path, k->name.length ? &me->names[k->name.offset] : NULL, k->name.length);
						}
						bool const is_alternate_stream = k->type_name_id && (k->type_name_id << (CHAR_BIT / 2)) != ntfs::AttributeData;
						if (is_alternate_stream)
						{
							if (!k->name.length) { *path += _T(':'); }
							*path += _T(':'), append(*path, ntfs::attribute_names[k->type_name_id].data, ntfs::attribute_names[k->type_name_id].size);
						}
					}
					key_type const new_key = { frs, name_info, ki, k == k0 ? ~static_cast<key_type::direct_address_type>(islot) : static_cast<key_type::direct_address_type>(k - &*me->streaminfos.begin()) };
					func(buffered_matching ? std::pair<std::tstring::const_iterator, std::tstring::const_iterator>(path->begin() + (match_paths ? 0 : static_cast<ptrdiff_t>(basename_index_in_path)), path->end()) : name, new_key, depth);
					if (buffered_matching)
					{
						path->erase(old_size, path->size() - old_size);
					}
				}
			}
		}
	};
};

template<typename Str, typename S1, typename S2>
void replace_all(Str &str, S1 from, S2 to)
{
	size_t const nFrom = Str(from).size();  // SLOW but OK because this function is O(n^2) anyway
	size_t const nTo = Str(to).size();  // SLOW but OK because this function is O(n^2) anyway
	for (size_t i = 0; (i = str.find_first_of(from, i)) != Str::npos; i += nTo)
	{
		str.erase(i, nFrom);
		str.insert(i, to);
	}
}


namespace std
{
#ifdef _XMEMORY_
#define X(...) template<> struct is_scalar<__VA_ARGS__> : is_pod<__VA_ARGS__>{}
	X(NtfsIndex::StandardInfo);
	X(NtfsIndex::NameInfo);
	X(NtfsIndex::StreamInfo);
	X(NtfsIndex::LinkInfo);
	X(NtfsIndex::Record);
#undef X
#endif
}

class CoInit
{
	CoInit(CoInit const &) : hr(S_FALSE) { }
	CoInit &operator =(CoInit const &) { }
public:
	HRESULT hr;
	CoInit(bool initialize = true) : hr(initialize ? CoInitialize(NULL) : S_FALSE) { }
	~CoInit() { if (this->hr == S_OK) { CoUninitialize(); } }
};

template<class T>
inline T const &use_facet(std::locale const &loc)
{
	return std::
#if defined(_USEFAC)
		_USE(loc, T)
#else
		use_facet<T>(loc)
#endif
		;
}

#ifdef WM_SETREDRAW
class CSetRedraw
{
	static TCHAR const *key() { return _T("Redraw.{A303353B-C8AA-40FA-8518-C4E02B30033A}"); }
public:
	HWND hWnd;
	HANDLE notPrev;
	CSetRedraw(HWND const hWnd, BOOL redraw)
		: hWnd(hWnd), notPrev(GetProp(hWnd, key()))
	{
		SendMessage(hWnd, WM_SETREDRAW, redraw, 0);
		SetProp(hWnd, key(), (HANDLE)(!redraw));
	}
	~CSetRedraw()
	{
		SetProp(hWnd, key(), notPrev);
		SendMessage(hWnd, WM_SETREDRAW, !this->notPrev, 0);
	}
};
#endif

class iless
{
	mutable std::basic_string<TCHAR> s1, s2;
	std::ctype<TCHAR> const &ctype;
	bool logical;
	struct iless_ch
	{
		iless const *p;
		iless_ch(iless const &l) : p(&l) { }
		bool operator()(TCHAR a, TCHAR b) const
		{
			return _totupper(a) < _totupper(b);
			//return p->ctype.toupper(a) < p->ctype.toupper(b);
		}
	};

	template<class T>
	static T const &use_facet(std::locale const &loc)
	{
		return std::
#if defined(_USEFAC)
			_USE(loc, T)
#else
			use_facet<T>(loc)
#endif
			;
	}

public:
	iless(std::locale const &loc, bool const logical) : ctype(static_cast<std::ctype<TCHAR> const &>(use_facet<std::ctype<TCHAR> >(loc))), logical(logical) {}
	bool operator()(boost::iterator_range<TCHAR const *> const a, boost::iterator_range<TCHAR const *> const b) const
	{
		s1.assign(a.begin(), a.end());
		s2.assign(b.begin(), b.end());
		return logical ? StrCmpLogicalW(s1.c_str(), s2.c_str()) < 0 : std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(), iless_ch(*this));
	}
};

template<class It, class ItBuf, class Pred>
void mergesort_level(It const begin, ptrdiff_t const n, ItBuf const buf, Pred comp, bool const in_buf, ptrdiff_t const m, ptrdiff_t const j)
{
	using std::merge;
	using std::min;
	if (in_buf)
	{
		merge(
			buf + min(n, j), buf + min(n, j + m),
			buf + min(n, j + m), buf + min(n, j + m + m),
			begin + min(n, j),
			comp);
	}
	else
	{
		merge(
			begin + min(n, j), begin + min(n, j + m),
			begin + min(n, j + m), begin + min(n, j + m + m),
			buf + min(n, j),
			comp);
	}
}

template<class It, class ItBuf, class Pred>
bool mergesort(It const begin, It const end, ItBuf const buf, Pred comp, bool const parallel)  // MUST check the return value!
{
	bool in_buf = false;
	for (ptrdiff_t m = 1, n = end - begin; m < n; in_buf = !in_buf, m += m)
	{
		ptrdiff_t const k = n + n - m;
#define X() for (ptrdiff_t j = 0; j < k; j += m + m) { mergesort_level<It, ItBuf, Pred>(begin, n, buf, comp, in_buf, m, j); }
#ifdef _OPENMP
		if (parallel)
		{
#pragma omp parallel for
			X();
		}
		else
#endif
		{
			(void) parallel;
			X();
		}
#undef X
	}
	// if (in_buf) { using std::swap_ranges; swap_ranges(begin, end, buf), in_buf = !in_buf; }
	return in_buf;
}

template<class It, class Pred>
void inplace_mergesort(It const begin, It const end, Pred const &pred, bool const parallel)
{
	class buffer_ptr
	{
		buffer_ptr(buffer_ptr const &) { }
		void operator =(buffer_ptr const &) { }
		typedef typename std::iterator_traits<It>::value_type value_type;
		typedef value_type *pointer;
		typedef size_t size_type;
		pointer p;
	public:
		typedef pointer iterator;
		~buffer_ptr() { delete [] this->p; }
		explicit buffer_ptr(size_type const n) : p(new value_type[n]) { }
		iterator begin() { return this->p; }
	} buf(static_cast<size_t>(std::distance(begin, end)));
	if (mergesort<It, typename buffer_ptr::iterator, Pred>(begin, end, buf.begin(), pred, parallel))
	{
		using std::swap_ranges; swap_ranges(begin, end, buf.begin());
	}
}

class CProgressDialog : private CModifiedDialogImpl<CProgressDialog>, private WTL::CDialogResize<CProgressDialog>
{
	typedef CProgressDialog This;
	typedef CModifiedDialogImpl<CProgressDialog> Base;
	friend CDialogResize<This>;
	friend CDialogImpl<This>;
	friend CModifiedDialogImpl<This>;
	enum { IDD = IDD_DIALOGPROGRESS, BACKGROUND_COLOR = COLOR_WINDOW };
	class CUnselectableWindow : public ATL::CWindowImpl<CUnselectableWindow>
	{
		BEGIN_MSG_MAP(CUnselectableWindow)
			MESSAGE_HANDLER(WM_NCHITTEST, OnNcHitTest)
		END_MSG_MAP()
		LRESULT OnNcHitTest(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL&)
		{
			LRESULT result = this->DefWindowProc(uMsg, wParam, lParam);
			return result == HTCLIENT ? HTTRANSPARENT : result;
		}
	};

	CUnselectableWindow progressText;
	WTL::CProgressBarCtrl progressBar;
	bool canceled;
	bool invalidated;
	DWORD creationTime;
	DWORD lastUpdateTime;
	HWND parent;
	std::basic_string<TCHAR> lastProgressText, lastProgressTitle;
	bool windowCreated;
	bool windowCreateAttempted;
	int lastProgress, lastProgressTotal;

	BOOL OnInitDialog(CWindow /*wndFocus*/, LPARAM /*lInitParam*/)
	{
		(this->progressText.SubclassWindow)(this->GetDlgItem(IDC_RICHEDITPROGRESS));
		// SetClassLongPtr(this->m_hWnd, GCLP_HBRBACKGROUND, reinterpret_cast<LONG_PTR>(GetSysColorBrush(COLOR_3DFACE)));
		this->progressBar.Attach(this->GetDlgItem(IDC_PROGRESS1));
		this->DlgResize_Init(false, false, 0);
		ATL::CComBSTR bstr;
		this->progressText.GetWindowText(&bstr);
		this->lastProgressText = bstr;

		return TRUE;
	}

	void OnPause(UINT uNotifyCode, int nID, CWindow wndCtl)
	{
		UNREFERENCED_PARAMETER((uNotifyCode, nID, wndCtl));
		__debugbreak();
	}

	void OnCancel(UINT uNotifyCode, int nID, CWindow wndCtl)
	{
		UNREFERENCED_PARAMETER((uNotifyCode, nID, wndCtl));
		PostQuitMessage(ERROR_CANCELLED);
	}

	BOOL OnEraseBkgnd(WTL::CDCHandle dc)
	{
		RECT rc = {};
		this->GetClientRect(&rc);
		dc.FillRect(&rc, BACKGROUND_COLOR);
		return TRUE;
	}

	HBRUSH OnCtlColorStatic(WTL::CDCHandle dc, WTL::CStatic /*wndStatic*/)
	{
		return GetSysColorBrush(BACKGROUND_COLOR);
	}

	BEGIN_MSG_MAP_EX(This)
		CHAIN_MSG_MAP(CDialogResize<This>)
		MSG_WM_INITDIALOG(OnInitDialog)
		// MSG_WM_ERASEBKGND(OnEraseBkgnd)
		// MSG_WM_CTLCOLORSTATIC(OnCtlColorStatic)
		COMMAND_HANDLER_EX(IDRETRY, BN_CLICKED, OnPause)
		COMMAND_HANDLER_EX(IDCANCEL, BN_CLICKED, OnCancel)
	END_MSG_MAP()

	BEGIN_DLGRESIZE_MAP(This)
		DLGRESIZE_CONTROL(IDC_PROGRESS1, DLSZ_MOVE_Y | DLSZ_SIZE_X)
		DLGRESIZE_CONTROL(IDC_RICHEDITPROGRESS, DLSZ_SIZE_Y | DLSZ_SIZE_X)
		DLGRESIZE_CONTROL(IDCANCEL, DLSZ_MOVE_X | DLSZ_MOVE_Y)
	END_DLGRESIZE_MAP()

	static BOOL EnableWindowRecursive(HWND hWnd, BOOL enable, BOOL includeSelf = true)
	{
		struct Callback
		{
			static BOOL CALLBACK EnableWindowRecursiveEnumProc(HWND hWnd, LPARAM lParam)
			{
				EnableWindowRecursive(hWnd, static_cast<BOOL>(lParam), TRUE);
				return TRUE;
			}
		};
		if (enable)
		{
			EnumChildWindows(hWnd, &Callback::EnableWindowRecursiveEnumProc, enable);
			return includeSelf && ::EnableWindow(hWnd, enable);
		}
		else
		{
			BOOL result = includeSelf && ::EnableWindow(hWnd, enable);
			EnumChildWindows(hWnd, &Callback::EnableWindowRecursiveEnumProc, enable);
			return result;
		}
	}

	unsigned long WaitMessageLoop(uintptr_t const handles[], size_t const nhandles)
	{
		for (;;)
		{
			unsigned long result = MsgWaitForMultipleObjectsEx(static_cast<unsigned int>(nhandles), reinterpret_cast<HANDLE const *>(handles), UPDATE_INTERVAL, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
			if (WAIT_OBJECT_0 <= result && result < WAIT_OBJECT_0 + nhandles || result == WAIT_TIMEOUT)
			{ return result; }
			else if (result == WAIT_OBJECT_0 + static_cast<unsigned int>(nhandles))
			{
				this->ProcessMessages();
			}
			else
			{
				RaiseException(GetLastError(), 0, 0, NULL);
			}
		}
	}

	DWORD GetMinDelay() const
	{
		return IsDebuggerPresent() ? 0 : 750;
	}

public:
	enum { UPDATE_INTERVAL = 25 };
	CProgressDialog(ATL::CWindow parent)
		: Base(true), parent(parent), lastUpdateTime(0), creationTime(GetTickCount()), lastProgress(0), lastProgressTotal(1), invalidated(false), canceled(false), windowCreated(false), windowCreateAttempted(false)
	{
	}

	~CProgressDialog()
	{
		if (this->windowCreateAttempted)
		{
			::EnableWindow(parent, TRUE);
		}
		if (this->windowCreated)
		{
			this->DestroyWindow();
		}
	}

	unsigned long Elapsed() const { return GetTickCount() - this->lastUpdateTime; }

	bool ShouldUpdate() const
	{
		return this->Elapsed() >= UPDATE_INTERVAL;
	}

	void ProcessMessages()
	{
		MSG msg;
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
		{
			if (!this->windowCreated || !this->IsDialogMessage(&msg))
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
			if (msg.message == WM_QUIT)
			{
				this->canceled = true;
			}
		}
	}

	void ForceShow()
	{
		if (!this->windowCreateAttempted)
		{
			this->windowCreated = !!this->Create(parent);
			this->windowCreateAttempted = true;
			::EnableWindow(parent, FALSE);
			this->Flush();
		}
	}

	bool HasUserCancelled()
	{
		bool justCreated = false;
		unsigned long const now = GetTickCount();
		if (abs(static_cast<int>(now - this->creationTime)) >= static_cast<int>(this->GetMinDelay()))
		{
			this->ForceShow();
		}
		if (this->windowCreated && (justCreated || this->ShouldUpdate()))
		{
			this->ProcessMessages();
		}
		return this->canceled;
	}

	void Flush()
	{
		if (this->invalidated)
		{
			if (this->windowCreated)
			{
				this->invalidated = false;
				this->SetWindowText(this->lastProgressTitle.c_str());
				this->progressBar.SetRange32(0, this->lastProgressTotal);
				this->progressBar.SetPos(this->lastProgress);
				this->progressText.SetWindowText(this->lastProgressText.c_str());
				this->progressBar.UpdateWindow();
				this->progressText.UpdateWindow();
				this->UpdateWindow();
			}
			this->lastUpdateTime = GetTickCount();
		}
	}

	void SetProgress(long long current, long long total)
	{
		if (total > INT_MAX)
		{
			current = static_cast<long long>((static_cast<double>(current) / total) * INT_MAX);
			total = INT_MAX;
		}
		this->invalidated |= this->lastProgress != current || this->lastProgressTotal != total;
		this->lastProgressTotal = static_cast<int>(total);
		this->lastProgress = static_cast<int>(current);
	}

	void SetProgressTitle(LPCTSTR title)
	{
		this->invalidated |= this->lastProgressTitle != title;
		this->lastProgressTitle = title;
	}

	void SetProgressText(boost::iterator_range<TCHAR const *> const text)
	{
		this->invalidated |= !boost::equal(this->lastProgressText, text);
		this->lastProgressText.assign(text.begin(), text.end());
	}
};

class OverlappedNtfsMftReadPayload : public Overlapped
{
	typedef std::vector<std::pair<std::pair<unsigned long long, unsigned long long>, long long> > RetPtrs;
	Handle iocp;
	HWND m_hWnd;
	Handle closing_event;
	RetPtrs bitmap_ret_ptrs, data_ret_ptrs;
	unsigned int cluster_size;
	unsigned long long read_block_size;
	atomic_namespace::atomic<RetPtrs::size_type> jbitmap, nbitmap_chunks_left, jdata;
	atomic_namespace::atomic<unsigned int> records_so_far, valid_records;
	boost::intrusive_ptr<NtfsIndex volatile> p;
public:
	class ReadOperation;
	~OverlappedNtfsMftReadPayload()
	{
	}
	OverlappedNtfsMftReadPayload(Handle const &iocp, boost::intrusive_ptr<NtfsIndex volatile> p, HWND const m_hWnd, Handle const &closing_event)
		: Overlapped(), iocp(iocp), m_hWnd(m_hWnd), closing_event(closing_event), records_so_far(0), valid_records(0), cluster_size(), read_block_size(2ULL << 20), jbitmap(0), nbitmap_chunks_left(0), jdata(0)
	{
		using std::swap; swap(p, this->p);
	}
	bool queue_next() volatile;
	int operator()(size_t const /*size*/, uintptr_t const /*key*/);
};
class OverlappedNtfsMftReadPayload::ReadOperation : public Overlapped
{
	unsigned long long _voffset;
	static mutex recycled_mutex;
	static std::vector<std::pair<size_t, void *> > recycled;
	bool _is_bitmap;
	boost::intrusive_ptr<OverlappedNtfsMftReadPayload volatile> q;
	static void *operator new(size_t n)
	{
		void *p;
		if (false)
		{
			{
				lock_guard<mutex> guard(recycled_mutex);
				size_t ifound = recycled.size();
				for (size_t i = 0; i != recycled.size(); ++i)
				{
					if (recycled[i].first >= n && (ifound >= recycled.size() || recycled[i].first <= recycled[ifound].first))
					{
						ifound = i;
					}
				}
				if (ifound < recycled.size())
				{
					p = recycled[ifound].second;
					recycled.erase(recycled.begin() + static_cast<ptrdiff_t>(ifound));
				}
				else
				{
					p = NULL;
				}
			}
			if (!p)
			{
				p = malloc(n) /* so we can use _msize() */;
			}
		}
		else { p = ::operator new(n); }
		return p;
	}
public:
	static void *operator new(size_t n, size_t m) { return operator new(n + m); }
	static void operator delete(void *p)
	{
		if (false)
		{
			lock_guard<mutex>(recycled_mutex), recycled.push_back(std::pair<size_t, void *>(_msize(p), p));
		}
		else
		{
			return ::operator delete(p);
		}
	}
	static void operator delete(void *p, size_t /*m*/) { return operator delete(p); }
	explicit ReadOperation(boost::intrusive_ptr<OverlappedNtfsMftReadPayload volatile> const &q, bool const is_bitmap)
		: Overlapped(), _voffset(), q(q), _is_bitmap(is_bitmap) { }
	unsigned long long voffset() { return this->_voffset; }
	void voffset(unsigned long long const value) { this->_voffset = value; }
	int operator()(size_t const size, uintptr_t const /*key*/)
	{
		OverlappedNtfsMftReadPayload *const q = const_cast<OverlappedNtfsMftReadPayload *>(static_cast<OverlappedNtfsMftReadPayload volatile *>(this->q.get()));
		if (!q->p->cancelled())
		{
			this->q->queue_next();
			void *const buffer = this + 1;
			if (this->_is_bitmap)
			{
				static unsigned char const popcount [] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
				unsigned int nrecords = 0;
				for (size_t i = 0, n = size * CHAR_BIT < q->p->mft_capacity ? size : 1 + (q->p->mft_capacity - 1) / CHAR_BIT; i < n; ++i)
				{
					unsigned char const
						v = static_cast<unsigned char const *>(buffer)[i],
						vlow = static_cast<unsigned char>(v >> (CHAR_BIT / 2)),
						vhigh = static_cast<unsigned char>(v ^ (vlow << (CHAR_BIT / 2)));
					nrecords += popcount[vlow];
					nrecords += popcount[vhigh];
				}
				q->valid_records.fetch_add(nrecords, atomic_namespace::memory_order_acq_rel);
				q->nbitmap_chunks_left.fetch_sub(1, atomic_namespace::memory_order_acq_rel);
			}
			else
			{
				if (!q->nbitmap_chunks_left.load(atomic_namespace::memory_order_acquire))  // 'nbitmap_chunks_left' is to make sure we've finished reading the entire bitmap, even with concurrent reads
				{
					if (unsigned int const valid_records = q->valid_records.exchange(0 /* make sure this doesn't happen twice */, atomic_namespace::memory_order_acq_rel))
					{
						q->p->reserve(valid_records);
					}
				}
				q->p->load(this->voffset(), buffer, size);
			}
		}
		return -1;
	}
};
mutex OverlappedNtfsMftReadPayload::ReadOperation::recycled_mutex;
std::vector<std::pair<size_t, void *> > OverlappedNtfsMftReadPayload::ReadOperation::recycled;

bool OverlappedNtfsMftReadPayload::queue_next() volatile
{
	OverlappedNtfsMftReadPayload const *const me = const_cast<OverlappedNtfsMftReadPayload const *>(this);
	bool any = false;
	bool handled = false;
	if (!handled)
	{
		size_t const jbitmap = this->jbitmap.fetch_add(1, atomic_namespace::memory_order_acq_rel);
		if (jbitmap < me->bitmap_ret_ptrs.size())
		{
			handled = true;
			unsigned int const cb = static_cast<unsigned int>(me->bitmap_ret_ptrs[jdata].first.second * me->cluster_size);
			boost::intrusive_ptr<ReadOperation> p(new(cb) ReadOperation(this, true));
			p->offset(me->bitmap_ret_ptrs[jdata].second * static_cast<long long>(me->cluster_size));
			p->voffset(me->bitmap_ret_ptrs[jdata].first.first * me->cluster_size);
			void *const buffer = p.get() + 1;
			if (ReadFile(me->p->volume(), buffer, cb, NULL, p.get()))
			{
				if (PostQueuedCompletionStatus(me->iocp, cb, 0, p.get()))
				{
					any = true, p.detach();
				}
				else { CheckAndThrow(false); }
			}
			else if (GetLastError() == ERROR_IO_PENDING)
			{
				any = true, p.detach();
			}
			else { CheckAndThrow(false); }
		}
		else if (jbitmap > me->bitmap_ret_ptrs.size())
		{
			// oops, increased multiple times... decrease to keep at max
			this->jbitmap.fetch_sub(1, atomic_namespace::memory_order_acq_rel);
		}
	}
	if (!handled)
	{
		// TODO: PERF: Optimization opportunity: only read the valid MFT entries, based on $MFT::$BITMAP
		size_t const jdata = this->jdata.fetch_add(1, atomic_namespace::memory_order_acq_rel);
		if (jdata < me->data_ret_ptrs.size())
		{
			handled = true;
			unsigned int const cb = static_cast<unsigned int>(me->data_ret_ptrs[jdata].first.second * me->cluster_size);
			boost::intrusive_ptr<ReadOperation> p(new(cb) ReadOperation(this, false));
			p->offset(me->data_ret_ptrs[jdata].second * static_cast<long long>(me->cluster_size));
			p->voffset(me->data_ret_ptrs[jdata].first.first * me->cluster_size);
			void *const buffer = p.get() + 1;
			if (ReadFile(me->p->volume(), buffer, cb, NULL, p.get()))
			{
				if (PostQueuedCompletionStatus(me->iocp, cb, 0, p.get()))
				{
					any = true, p.detach();
				}
				else { CheckAndThrow(false); }
			}
			else if (GetLastError() == ERROR_IO_PENDING)
			{
				any = true, p.detach();
			}
			else { CheckAndThrow(false); }
		}
		else if (jdata > me->data_ret_ptrs.size())
		{
			// oops, increased multiple times... decrease to keep at max
			this->jdata.fetch_sub(1, atomic_namespace::memory_order_acq_rel);
		}
	}
	return any;
}
int OverlappedNtfsMftReadPayload::operator()(size_t const /*size*/, uintptr_t const key)
{
	int result = -1;
	boost::intrusive_ptr<NtfsIndex> p = this->p->unvolatile();
	if (!p->init_called())
	{
		p->init();
	}
	if (void *const volume = p->volume())
	{
		DEV_BROADCAST_HANDLE dev = { sizeof(dev), DBT_DEVTYP_HANDLE, 0, volume, reinterpret_cast<HDEVNOTIFY>(this->m_hWnd) };
		dev.dbch_hdevnotify = RegisterDeviceNotification(this->m_hWnd, &dev, DEVICE_NOTIFY_WINDOW_HANDLE);
		unsigned long br;
		NTFS_VOLUME_DATA_BUFFER info;
		CheckAndThrow(DeviceIoControl(volume, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &info, sizeof(info), &br, NULL));
		this->cluster_size = static_cast<unsigned int>(info.BytesPerCluster);
		p->mft_record_size = info.BytesPerFileRecordSegment;
		p->mft_capacity = static_cast<unsigned int>(info.MftValidDataLength.QuadPart / p->mft_record_size);
		CheckAndThrow(!!CreateIoCompletionPort(volume, this->iocp, reinterpret_cast<uintptr_t>(&*p), 0));
		typedef std::vector<std::pair<unsigned long long, long long> > RP;
#if 1
		{
			long long llsize = 0;
			RP const ret_ptrs = get_mft_retrieval_pointers(volume, _T("$MFT::$BITMAP"), &llsize, info.MftStartLcn.QuadPart, this->p->mft_record_size);
			unsigned long long prev_vcn = 0;
			for (RP::const_iterator i = ret_ptrs.begin(); i != ret_ptrs.end(); ++i)
			{
				long long const clusters_left = static_cast<long long>(std::max(i->first, prev_vcn) - prev_vcn);
				unsigned long long n;
				for (long long m = 0; m < clusters_left; m += static_cast<long long>(n))
				{
					n = std::min(i->first - prev_vcn, 1 + (static_cast<unsigned long long>(this->read_block_size) - 1) / this->cluster_size);
					this->bitmap_ret_ptrs.push_back(RetPtrs::value_type(RetPtrs::value_type::first_type(prev_vcn, n), i->second + m));
					prev_vcn += n;
				}
			}
			this->nbitmap_chunks_left.store(this->bitmap_ret_ptrs.size(), atomic_namespace::memory_order_release);
		}
#endif
		{
			long long llsize = 0;
			RP const ret_ptrs = get_mft_retrieval_pointers(volume, _T("$MFT::$DATA"), &llsize, info.MftStartLcn.QuadPart, p->mft_record_size);
			unsigned long long prev_vcn = 0;
			for (RP::const_iterator i = ret_ptrs.begin(); i != ret_ptrs.end(); ++i)
			{
				long long const clusters_left = static_cast<long long>(std::max(i->first, prev_vcn) - prev_vcn);
				unsigned long long n;
				for (long long m = 0; m < clusters_left; m += static_cast<long long>(n))
				{
					n = std::min(i->first - prev_vcn, 1 + (static_cast<unsigned long long>(this->read_block_size) - 1) / this->cluster_size);
					this->data_ret_ptrs.push_back(RetPtrs::value_type(RetPtrs::value_type::first_type(prev_vcn, n), i->second + m));
					prev_vcn += n;
				}
			}
		}
		{
			for (int concurrency = 0; concurrency < 2; ++concurrency)
			{
				this->queue_next();
			}
		}
	}
	return result;
}

#pragma pack(push, 1)
struct SearchResult
{
	typedef NtfsIndex::key_type second_type;
	typedef unsigned short third_type;
	// NOTE: No intrusive_ptr here (to avoid a TON of refcount operations).
	// However, we acquire and references elsewhere.
	typedef NtfsIndex volatile const *first_type;
	struct depth_compare { bool operator()(SearchResult const &a, SearchResult const &b) const { return a.depth < b.depth; } };
	first_type index;
	second_type key;
	third_type depth;
};
#pragma pack(pop)

class CMainDlg : public CModifiedDialogImpl<CMainDlg>, public WTL::CDialogResize<CMainDlg>, public CInvokeImpl<CMainDlg>, private WTL::CMessageFilter
{
	enum { IDC_STATUS_BAR = 1100 + 0 };
	enum { COLUMN_INDEX_NAME, COLUMN_INDEX_PATH, COLUMN_INDEX_SIZE, COLUMN_INDEX_SIZE_ON_DISK, COLUMN_INDEX_CREATION_TIME, COLUMN_INDEX_MODIFICATION_TIME, COLUMN_INDEX_ACCESS_TIME };
#ifndef LVN_INCREMENTALSEARCH
	enum
	{
		LVN_INCREMENTALSEARCH =
#ifdef UNICODE
			LVN_FIRST - 63
#else
			LVN_FIRST-62
#endif
	};
#endif

	struct CThemedListViewCtrl : public WTL::CListViewCtrl, public WTL::CThemeImpl<CThemedListViewCtrl> { using WTL::CListViewCtrl::Attach; };
	class Threads : public std::vector<uintptr_t>
	{
		Threads(Threads const &) { }
		Threads &operator =(Threads const &) { return *this; }
	public:
		Threads() { }
		~Threads()
		{
			while (!this->empty())
			{
				size_t n = std::min(this->size(), static_cast<size_t>(MAXIMUM_WAIT_OBJECTS));
				WaitForMultipleObjects(static_cast<unsigned long>(n), reinterpret_cast<void *const *>(&*this->begin() + this->size() - n), TRUE, INFINITE);
				while (n) { this->pop_back(); --n; }
			}
		}
	};
	static unsigned long get_num_threads()
	{
		unsigned long num_threads = 0;
#ifdef _OPENMP
#pragma omp parallel
#pragma omp atomic
		++num_threads;
#else
		TCHAR const *const omp_num_threads = _tgetenv(_T("OMP_NUM_THREADS"));
		if (int const n = omp_num_threads ? _ttoi(omp_num_threads) : 0)
		{
			num_threads = static_cast<int>(n);
		}
		else
		{
			SYSTEM_INFO sysinfo;
			GetSystemInfo(&sysinfo);
			num_threads = sysinfo.dwNumberOfProcessors;
		}
#endif
		return num_threads;
	}
	static unsigned int CALLBACK iocp_worker(void *iocp)
	{
		ULONG_PTR key;
		OVERLAPPED *overlapped_ptr;
		Overlapped *p;
		for (unsigned long nr; GetQueuedCompletionStatus(iocp, &nr, &key, &overlapped_ptr, INFINITE);)
		{
			p = static_cast<Overlapped *>(overlapped_ptr);
			boost::intrusive_ptr<Overlapped> overlapped(p, false);
			if (overlapped.get())
			{
				int r = (*overlapped)(static_cast<size_t>(nr), key);
				if (r > 0) { r = PostQueuedCompletionStatus(iocp, nr, key, overlapped_ptr) ? 0 : -1; }
				if (r >= 0) { overlapped.detach(); }
			}
			else if (!key) { break; }
		}
		return 0;
	}

	class CSearchPattern : public ATL::CWindowImpl<CSearchPattern, WTL::CEdit>
	{
		BEGIN_MSG_MAP_EX(CCustomDialogCode)
			MSG_WM_MOUSEMOVE(OnMouseMove)
			MSG_WM_MOUSELEAVE(OnMouseLeave)
			MSG_WM_MOUSEHOVER(OnMouseHover)
			MESSAGE_HANDLER_EX(EM_REPLACESEL, OnReplaceSel)
			MESSAGE_RANGE_HANDLER_EX(WM_KEYDOWN, WM_KEYUP, OnKey)
		END_MSG_MAP()
		bool tracking;
	public:
		CSearchPattern() : tracking() { }
		struct KeyNotify { NMHDR hdr; WPARAM vkey; LPARAM lParam; };
		enum { CUN_KEYDOWN, CUN_KEYUP };

		LRESULT OnReplaceSel(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM lParam)
		{
			int start = 0, end = 0;
			this->GetSel(start, end);
			TCHAR const *const sz = reinterpret_cast<TCHAR const *>(lParam);
			if ((!sz || !*sz) && start == 0 && end == this->GetWindowTextLength())
			{
				this->PostMessage(EM_SETSEL, start, end);
			}
			else { this->SetMsgHandled(FALSE); }
			return 0;
		}

		LRESULT OnKey(UINT uMsg, WPARAM wParam, LPARAM lParam)
		{
			if ((wParam == VK_UP || wParam == VK_DOWN) || (wParam == VK_PRIOR || wParam == VK_NEXT))
			{
				int id = this->GetWindowLong(GWL_ID);
				KeyNotify msg = { { *this, static_cast<unsigned int>(id), static_cast<unsigned int>(uMsg == WM_KEYUP ? CUN_KEYUP : CUN_KEYDOWN) }, wParam, lParam };
				HWND hWndParent = this->GetParent();
				return hWndParent == NULL || this->SendMessage(hWndParent, WM_NOTIFY, id, (LPARAM)&msg) ? this->DefWindowProc(uMsg, wParam, lParam) : 0;
			}
			else { return this->DefWindowProc(uMsg, wParam, lParam); }
		}

		void EnsureTrackingMouseHover()
		{
			if (!this->tracking)
			{
				TRACKMOUSEEVENT tme = { sizeof(tme), TME_HOVER | TME_LEAVE, this->m_hWnd, 0 };
				this->tracking = !!TrackMouseEvent(&tme);
			}
		}

		void OnMouseMove(UINT /*nFlags*/, WTL::CPoint /*point*/)
		{
			this->SetMsgHandled(FALSE);
			this->EnsureTrackingMouseHover();
		}

		void OnMouseLeave()
		{
			this->SetMsgHandled(FALSE);
			this->tracking = false;
			this->HideBalloonTip();
		}

		void OnMouseHover(WPARAM /*wParam*/, WTL::CPoint /*ptPos*/)
		{
			this->SetMsgHandled(FALSE);
			EDITBALLOONTIP tip = { sizeof(tip), _T("Search Pattern"), _T("Entern pattern to match against the file's name or path, such as:\r\nC:\\Windows\\*.exe\r\nPicture*.jpg"), TTI_INFO };
			this->ShowBalloonTip(&tip);
		}
	};

	struct CacheInfo
	{
		CacheInfo() : valid(false), iIconSmall(-1), iIconLarge(-1), iIconExtraLarge(-1) { this->szTypeName[0] = _T('\0'); }
		bool valid;
		int iIconSmall, iIconLarge, iIconExtraLarge;
		TCHAR szTypeName[80];
		std::tstring description;
	};
	static unsigned int const WM_TASKBARCREATED;
	enum { WM_NOTIFYICON = WM_USER + 100 };

#ifdef _MSC_VER
	__declspec(align(0x40))
#endif
	class ResultsBase : memheap_vector<SearchResult>
	{
		typedef ResultsBase this_type;
		typedef memheap_vector<value_type, allocator_type> base_type;
		typedef std::vector<boost::intrusive_ptr<NtfsIndex volatile const> > IndicesInUse;
		IndicesInUse indices_in_use /* to keep alive */;
		void post_insert(IndicesInUse::value_type::element_type *const index)
		{
			size_t found = 0;
			for (IndicesInUse::const_iterator j = this->indices_in_use.begin(); j != this->indices_in_use.end(); ++j)
			{
				if (index == j->get())
				{
					++found;
				}
			}
			if (!found)
			{
				this->indices_in_use.push_back(static_cast<IndicesInUse::value_type>(index));
			}
		}
	public:
		typedef base_type::allocator_type allocator_type;
		typedef base_type::value_type value_type;
		// typedef base_type::pointer pointer;
		// typedef base_type::const_pointer const_pointer;
		typedef base_type::reference reference;
		typedef base_type::const_reference const_reference;
		typedef base_type::iterator iterator;
		typedef base_type::const_iterator const_iterator;
		typedef base_type::reverse_iterator reverse_iterator;
		typedef base_type::const_reverse_iterator const_reverse_iterator;
		typedef base_type::size_type size_type;
		typedef base_type::difference_type difference_type;
		ResultsBase() : base_type() { }
		explicit ResultsBase(allocator_type const &alloc) : base_type(alloc) { }
		using base_type::begin;
		using base_type::end;
		using base_type::rbegin;
		using base_type::rend;
		using base_type::size;
		void reserve(size_t const n)
		{
			(void) n;
			this->base_type::reserve(n);
		}
		void insert_from(this_type const &other)
		{
			std::copy(other.base_type::begin(), other.base_type::end(), std::back_inserter(static_cast<base_type &>(*this)));
			for (IndicesInUse::const_iterator i = other.indices_in_use.begin(); i != other.indices_in_use.end(); ++i)
			{
				this->post_insert(i->get());
			}
		}
		void push_back(base_type::const_reference value)
		{
			this->base_type::push_back(value);
			this->post_insert(value.index);
		}
		void clear()
		{
			this->base_type::clear();
			this->indices_in_use.clear();
		}
		void swap(this_type &other)
		{
			this->base_type::swap(static_cast<base_type &>(other));
			this->indices_in_use.swap(other.indices_in_use);
		}
		friend void swap(this_type &a, this_type &b) { return a.swap(b); }
	};
	class Results
	{
		typedef Results this_type;
		typedef ResultsBase base_type;
		typedef std::vector<size_t> Ordering;
		base_type base;
		Ordering ordering /* represents an offset from the END of the base */;
		void check_unordered() const
		{
			if (!this->ordering.empty())
			{
				throw std::logic_error("cannot perform this operation when ordered");
			}
		}
	public:
		typedef base_type::value_type value_type;
		typedef base_type::iterator reverse_iterator;
		Results() { }
		explicit Results(base_type::allocator_type const &alloc) : base(alloc) { }
		void clear() { this->clear_ordering(); return this->base.clear(); }
		size_t size() { return this->base.size(); }
		void batch_and_reverse() { this->ordering.push_back(this->base.size()); }
		reverse_iterator rbegin() { this->check_unordered(); return this->base.begin(); }
		reverse_iterator rend() { this->check_unordered(); return this->base.end(); }
		void reserve(size_t const n) { return this->base.reserve(n); }
		value_type const &operator[](size_t i) const
		{
			Ordering::const_iterator const begin = this->ordering.begin(), end = this->ordering.end(), ub = std::upper_bound(begin, end, i);
			if (ub != end)
			{
				i = *ub - static_cast<ptrdiff_t>(i - (ub != begin ? *(ub - 1) : 0) + 1);
			}
			else
			{
				i = this->base.size() - (i + 1);
			}
			return *(this->base.begin() + static_cast<ptrdiff_t>(i));
		}
#if __cplusplus >= 201103L || defined(__GXX_EXPERIMENTAL_CXX0X__) || defined(_MSC_VER) && _MSC_VER >= 1600
#define X_HAS_MOVE_SEMANTICS
#elif defined(__clang)
#if __has_feature(cxx_rvalue_references)
#define X_HAS_MOVE_SEMANTICS
#endif
#endif
#ifdef  X_HAS_MOVE_SEMANTICS
		void push(value_type &&value) { return this->base.push_back(static_cast<value_type &&>(value)); }
#endif
#undef  X_HAS_MOVE_SEMANTICS
		void push(value_type const &value) { return this->base.push_back(value); }
		void insert_from(this_type const &other) { return this->base.insert_from(other.base); }
		void clear_ordering() { return this->ordering.clear(); }
	};

	template<class StrCmp>
	class NameComparator
	{
		StrCmp less;
	public:
		NameComparator(StrCmp const &less) : less(less) { }
		bool operator()(Results::value_type const &a, Results::value_type const &b)
		{
			bool less = this->less(a.file_name(), b.file_name());
			if (!less && !this->less(b.file_name(), a.file_name()))
			{ less = this->less(a.stream_name(), b.stream_name()); }
			return less;
		}
		bool operator()(Results::value_type const &a, Results::value_type const &b) const
		{
			bool less = this->less(a.file_name(), b.file_name());
			if (!less && !this->less(b.file_name(), a.file_name()))
			{ less = this->less(a.stream_name(), b.stream_name()); }
			return less;
		}
	};

	class RaiseIoPriority
	{
		uintptr_t _volume;
		winnt::FILE_IO_PRIORITY_HINT_INFORMATION _old;
		RaiseIoPriority(RaiseIoPriority const &);
		RaiseIoPriority &operator =(RaiseIoPriority const &);
	public:
		static winnt::FILE_IO_PRIORITY_HINT_INFORMATION set(uintptr_t const volume, winnt::IO_PRIORITY_HINT const value)
		{
			winnt::FILE_IO_PRIORITY_HINT_INFORMATION old = {};
			winnt::IO_STATUS_BLOCK iosb;
			winnt::NtQueryInformationFile(reinterpret_cast<HANDLE>(volume), &iosb, &old, sizeof(old), 43);
			winnt::FILE_IO_PRIORITY_HINT_INFORMATION io_priority = { value };
			winnt::NtSetInformationFile(reinterpret_cast<HANDLE>(volume), &iosb, &io_priority, sizeof(io_priority), 43);
			return old;
		}
		uintptr_t volume() const { return this->_volume; }
		RaiseIoPriority() : _volume(), _old() { }
		explicit RaiseIoPriority(uintptr_t const volume) : _volume(volume), _old(set(volume, winnt::IoPriorityNormal)) { }
		~RaiseIoPriority() { if (this->_volume) { set(this->_volume, this->_old.PriorityHint); } }
		void swap(RaiseIoPriority &other) { using std::swap; swap(this->_volume, other._volume); swap(this->_old, other._old); }
	};

	template<class StrCmp>
	static NameComparator<StrCmp> name_comparator(StrCmp const &cmp) { return NameComparator<StrCmp>(cmp); }

	size_t num_threads;
	CSearchPattern txtPattern;
	WTL::CButton btnOK;
	WTL::CRichEditCtrl richEdit;
	WTL::CStatusBarCtrl statusbar;
	WTL::CAccelerator accel;
	std::map<std::tstring, CacheInfo> cache;
	std::tstring lastRequestedIcon;
	HANDLE hRichEdit;
	bool autocomplete_called;
	Results results;
	WTL::CImageList _small_image_list;  // image list that is used as the "small" image list
	WTL::CImageList imgListSmall, imgListLarge, imgListExtraLarge;  // lists of small images
	WTL::CComboBox cmbDrive;
	int indices_created;
	CThemedListViewCtrl lvFiles;
	WTL::CMenu menu;
	boost::intrusive_ptr<BackgroundWorker> iconLoader;
	Handle closing_event;
	Handle iocp;
	Threads threads;
	std::locale loc;
	HANDLE hWait, hEvent;
	CoInit coinit;
	COLORREF deletedColor;
	COLORREF encryptedColor;
	COLORREF compressedColor;
	static DWORD WINAPI SHOpenFolderAndSelectItemsThread(IN LPVOID lpParameter)
	{
		std::auto_ptr<std::pair<std::pair<CShellItemIDList, ATL::CComPtr<IShellFolder> >, std::vector<CShellItemIDList> > > p(
			static_cast<std::pair<std::pair<CShellItemIDList, ATL::CComPtr<IShellFolder> >, std::vector<CShellItemIDList> > *>(lpParameter));
		// This is in a separate thread because of a BUG:
		// Try this with RmMetadata:
		// 1. Double-click it.
		// 2. Press OK when the error comes up.
		// 3. Now you can't access the main window, because SHOpenFolderAndSelectItems() hasn't returned!
		// So we put this in a separate thread to solve that problem.

		CoInit coInit;
		std::vector<LPCITEMIDLIST> relative_item_ids(p->second.size());
		for (size_t i = 0; i < p->second.size(); ++i)
		{
			relative_item_ids[i] = ILFindChild(p->first.first, p->second[i]);
		}
		return SHOpenFolderAndSelectItems(p->first.first, static_cast<UINT>(relative_item_ids.size()), relative_item_ids.empty() ? NULL : &relative_item_ids[0], 0);
	}
public:
	CMainDlg(HANDLE const hEvent) :
		num_threads(static_cast<size_t>(get_num_threads())), indices_created(),
		closing_event(CreateEvent(NULL, TRUE, FALSE, NULL)), iocp(CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0)),
		threads(), loc(get_numpunct_locale(std::locale(""))), hWait(), hEvent(hEvent),
		iconLoader(BackgroundWorker::create(true)), lastRequestedIcon(), hRichEdit(), autocomplete_called(false), _small_image_list(),
		deletedColor(RGB(0xFF, 0, 0)), encryptedColor(RGB(0, 0xFF, 0)), compressedColor(RGB(0, 0, 0xFF))
	{
	}
	void OnDestroy()
	{
		UnregisterWait(this->hWait);
		this->DeleteNotifyIcon();
		this->iconLoader->clear();
		for (size_t i = 0; i != this->threads.size(); ++i)
		{
			PostQueuedCompletionStatus(this->iocp, 0, 0, NULL);
		}
	}

	struct IconLoaderCallback
	{
		CMainDlg *this_;
		std::tstring path;
		SIZE iconSmallSize, iconLargeSize;
		unsigned long fileAttributes;
		int iItem;

		struct MainThreadCallback
		{
			CMainDlg *this_;
			std::tstring description, path;
			WTL::CIcon iconSmall, iconLarge;
			int iItem;
			TCHAR szTypeName[80];
			bool operator()()
			{
				WTL::CWaitCursor wait(true, IDC_APPSTARTING);
				CMainDlg::CacheInfo &cached = this_->cache[path];
				_tcscpy(cached.szTypeName, this->szTypeName);
				cached.description = description;

				if (cached.iIconSmall < 0) { cached.iIconSmall = this_->imgListSmall.AddIcon(iconSmall); }
				else { this_->imgListSmall.ReplaceIcon(cached.iIconSmall, iconSmall); }

				if (cached.iIconLarge < 0) { cached.iIconLarge = this_->imgListLarge.AddIcon(iconLarge); }
				else { this_->imgListLarge.ReplaceIcon(cached.iIconLarge, iconLarge); }

				cached.valid = true;

				this_->lvFiles.RedrawItems(iItem, iItem);
				return true;
			}
		};

		BOOL operator()()
		{
			RECT rcItem = { LVIR_BOUNDS };
			RECT rcFiles, intersection;
			this_->lvFiles.GetClientRect(&rcFiles);  // Blocks, but should be fast
			this_->lvFiles.GetItemRect(iItem, &rcItem, LVIR_BOUNDS);  // Blocks, but I'm hoping it's fast...
			if (IntersectRect(&intersection, &rcFiles, &rcItem))
			{
				std::tstring const normalizedPath = NormalizePath(path);
				SHFILEINFO shfi = {0};
				std::tstring description;
#if 0
				{
					std::vector<BYTE> buffer;
					DWORD temp;
					buffer.resize(GetFileVersionInfoSize(normalizedPath.c_str(), &temp));
					if (GetFileVersionInfo(normalizedPath.c_str(), NULL, static_cast<DWORD>(buffer.size()), buffer.empty() ? NULL : &buffer[0]))
					{
						LPVOID p;
						UINT uLen;
						if (VerQueryValue(buffer.empty() ? NULL : &buffer[0], _T("\\StringFileInfo\\040904E4\\FileDescription"), &p, &uLen))
						{ description = std::tstring((LPCTSTR)p, uLen); }
					}
				}
#endif
				Handle fileTemp;  // To prevent icon retrieval from changing the file time
				{
					std::tstring ntpath = _T("\\??\\") + path;
					winnt::UNICODE_STRING us = { static_cast<unsigned short>(ntpath.size() * sizeof(*ntpath.begin())), static_cast<unsigned short>(ntpath.size() * sizeof(*ntpath.begin())), ntpath.empty() ? NULL : &*ntpath.begin() };
					winnt::OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &us };
					winnt::IO_STATUS_BLOCK iosb;
					if (winnt::NtOpenFile(&fileTemp.value, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0x00200000 /* FILE_OPEN_REPARSE_POINT */ | 0x00000008 /*FILE_NO_INTERMEDIATE_BUFFERING*/) == 0)
					{
						FILETIME preserve = { ULONG_MAX, ULONG_MAX };
						SetFileTime(fileTemp, NULL, &preserve, NULL);
					}
				}
				BOOL success = FALSE;
				SetLastError(0);
				WTL::CIcon iconSmall, iconLarge;
				for (int pass = 0; pass < 2; ++pass)
				{
					WTL::CSize const size = pass ? iconLargeSize : iconSmallSize;
					ULONG const flags = SHGFI_ICON | SHGFI_SHELLICONSIZE | SHGFI_ADDOVERLAYS | //SHGFI_TYPENAME | SHGFI_SYSICONINDEX |
						(pass ? SHGFI_LARGEICON : SHGFI_SMALLICON);
					// CoInit com;  // MANDATORY!  Some files, like '.sln' files, won't work without it!
					success = SHGetFileInfo(normalizedPath.c_str(), fileAttributes, &shfi, sizeof(shfi), flags) != 0;
					if (!success && (flags & SHGFI_USEFILEATTRIBUTES) == 0)
					{ success = SHGetFileInfo(normalizedPath.c_str(), fileAttributes, &shfi, sizeof(shfi), flags | SHGFI_USEFILEATTRIBUTES) != 0; }
					(pass ? iconLarge : iconSmall).Attach(shfi.hIcon);
				}

				if (success)
				{
					std::tstring const path(path);
					int const iItem(iItem);
					MainThreadCallback callback = { this_, description, path, iconSmall.Detach(), iconLarge.Detach(), iItem };
					_tcscpy(callback.szTypeName, shfi.szTypeName);
					this_->InvokeAsync(callback);
					callback.iconLarge.Detach();
					callback.iconSmall.Detach();
				}
				else
				{
					_ftprintf(stderr, _T("Could not get the icon for file: %s\n"), normalizedPath.c_str());
				}
			}
			return true;
		}
	};

	static void remove_path_stream_and_trailing_sep(std::tstring &path)
	{
		for (;;)
		{
			size_t colon_or_sep = path.find_last_of(_T("\\:"));
			if (!~colon_or_sep || path[colon_or_sep] != _T(':')) { break; }
			path.erase(colon_or_sep, path.size() - colon_or_sep);
		}
		while (!path.empty() && isdirsep(*(path.end() - 1)) && path.find_first_of(_T('\\')) != path.size() - 1)
		{
			path.erase(path.end() - 1);
		}
		if (!path.empty() && *(path.end() - 1) == _T('.') && (path.size() == 1 || isdirsep(*(path.end() - 2))))
		{
			path.erase(path.end() - 1);
		}
	}

	int CacheIcon(std::tstring path, int const iItem, ULONG fileAttributes, bool lifo)
	{
		remove_path_stream_and_trailing_sep(path);
		if (this->cache.find(path) == this->cache.end())
		{
			this->cache[path] = CacheInfo();
		}

		CacheInfo const &entry = this->cache[path];

		if (!entry.valid && this->lastRequestedIcon != path)
		{
			SIZE iconSmallSize; this->imgListSmall.GetIconSize(iconSmallSize);
			SIZE iconSmallLarge; this->imgListLarge.GetIconSize(iconSmallLarge);

			IconLoaderCallback callback = { this, path, iconSmallSize, iconSmallLarge, fileAttributes, iItem };
			this->iconLoader->add(callback, lifo);
			this->lastRequestedIcon = path;
		}
		return entry.iIconSmall;
	}
	
	LRESULT OnMouseWheel(UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		return this->lvFiles.SendMessage(uMsg, wParam, lParam);
	}
	
	static VOID CALLBACK WaitCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
	{
		HWND const hWnd = reinterpret_cast<HWND>(lpParameter);
		if (!TimerOrWaitFired)
		{
			WINDOWPLACEMENT placement = { sizeof(placement) };
			if (::GetWindowPlacement(hWnd, &placement))
			{
				::ShowWindowAsync(hWnd, ::IsZoomed(hWnd) || (placement.flags & WPF_RESTORETOMAXIMIZED) != 0 ? SW_SHOWMAXIMIZED : SW_SHOWNORMAL);
			}
		}
	}

	WTL::CImageList small_image_list() const
	{
		return this->_small_image_list;
	}

	void small_image_list(WTL::CImageList imgList)
	{
		this->_small_image_list = imgList;
		this->lvFiles.SetImageList(imgList, LVSIL_SMALL);
	}

	BOOL OnInitDialog(CWindow /*wndFocus*/, LPARAM /*lInitParam*/)
	{
		_Module.GetMessageLoop()->AddMessageFilter(this);

		this->menu.Attach(this->GetMenu());
		this->lvFiles.Attach(this->GetDlgItem(IDC_LISTFILES));
		this->btnOK.Attach(this->GetDlgItem(IDOK));
		this->cmbDrive.Attach(this->GetDlgItem(IDC_LISTVOLUMES));
		this->accel.LoadAccelerators(IDR_ACCELERATOR1);
		this->txtPattern.SubclassWindow(this->GetDlgItem(IDC_EDITFILENAME));
		if (!this->txtPattern)
		{ this->txtPattern.Attach(this->GetDlgItem(IDC_EDITFILENAME)); }
		this->txtPattern.EnsureTrackingMouseHover();
		this->txtPattern.SetCueBannerText(_T("Search by name or path (hover for help)"), true);
		WTL::CHeaderCtrl hdr = this->lvFiles.GetHeader();
		// COLUMN_INDEX_NAME, COLUMN_INDEX_PATH, COLUMN_INDEX_SIZE, COLUMN_INDEX_SIZE_ON_DISK, COLUMN_INDEX_CREATION_TIME, COLUMN_INDEX_MODIFICATION_TIME, COLUMN_INDEX_ACCESS_TIME
		{ int const icol = COLUMN_INDEX_NAME; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_LEFT, 200, _T("Name") }; this->lvFiles.InsertColumn(icol, &column); HDITEM hditem = { HDI_LPARAM }; hditem.lParam = 0; hdr.SetItem(icol, &hditem); }
		{ int const icol = COLUMN_INDEX_PATH; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_LEFT, 340, _T("Path") }; this->lvFiles.InsertColumn(icol, &column); HDITEM hditem = { HDI_LPARAM }; hditem.lParam = 0; hdr.SetItem(icol, &hditem); }
		{ int const icol = COLUMN_INDEX_SIZE; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_RIGHT, 105, _T("Size") }; this->lvFiles.InsertColumn(icol, &column); HDITEM hditem = { HDI_LPARAM }; hditem.lParam = 0; hdr.SetItem(icol, &hditem); }
		{ int const icol = COLUMN_INDEX_SIZE_ON_DISK; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_RIGHT, 105, _T("Size on Disk") }; this->lvFiles.InsertColumn(icol, &column); HDITEM hditem = { HDI_LPARAM }; hditem.lParam = 0; hdr.SetItem(icol, &hditem); }
		{ int const icol = COLUMN_INDEX_CREATION_TIME; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_LEFT, 80, _T("Created") }; this->lvFiles.InsertColumn(icol, &column); HDITEM hditem = { HDI_LPARAM }; hditem.lParam = 0; hdr.SetItem(icol, &hditem); }
		{ int const icol = COLUMN_INDEX_MODIFICATION_TIME; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_LEFT, 80, _T("Written") }; this->lvFiles.InsertColumn(icol, &column); HDITEM hditem = { HDI_LPARAM }; hditem.lParam = 0; hdr.SetItem(icol, &hditem); }
		{ int const icol = COLUMN_INDEX_ACCESS_TIME; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_LEFT, 80, _T("Accessed") }; this->lvFiles.InsertColumn(icol, &column); HDITEM hditem = { HDI_LPARAM }; hditem.lParam = 0; hdr.SetItem(icol, &hditem); }

		this->cmbDrive.SetCueBannerText(_T("Search where?"));
		HINSTANCE hInstance = GetModuleHandle(NULL);
		this->SetIcon((HICON) LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0), FALSE);
		this->SetIcon((HICON) LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0), TRUE);

		{
			const int IMAGE_LIST_INCREMENT = 0x100;
			this->imgListSmall.Create(GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CXSMICON), ILC_COLOR32, 0, IMAGE_LIST_INCREMENT);
			this->imgListLarge.Create(GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CXICON), ILC_COLOR32, 0, IMAGE_LIST_INCREMENT);
			this->imgListExtraLarge.Create(48, 48, ILC_COLOR32, 0, IMAGE_LIST_INCREMENT);
		}

		this->lvFiles.OpenThemeData(VSCLASS_LISTVIEW);
		SetWindowTheme(this->lvFiles, _T("Explorer"), NULL);
		if (false)
		{
			WTL::CFontHandle font = this->txtPattern.GetFont();
			LOGFONT logFont;
			if (font.GetLogFont(logFont))
			{
				logFont.lfHeight = logFont.lfHeight * 100 / 85;
				this->txtPattern.SetFont(WTL::CFontHandle().CreateFontIndirect(&logFont));
			}
		}
		this->lvFiles.SetExtendedListViewStyle(LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP | LVS_EX_GRIDLINES | 0x80000000 /*LVS_EX_COLUMNOVERFLOW*/);
		{
			MENUITEMINFO mii = { sizeof(mii), MIIM_STATE };
			this->menu.GetMenuItemInfo(ID_VIEW_LARGEICONS, FALSE, &mii);
			this->small_image_list((mii.fState & MFS_CHECKED) ? this->imgListLarge : this->imgListSmall);
			this->lvFiles.SetImageList(this->imgListLarge, LVSIL_NORMAL);
			this->lvFiles.SetImageList(this->imgListExtraLarge, LVSIL_NORMAL);
		}
		this->SendMessage(WM_COMMAND, ID_VIEW_FITCOLUMNSTOWINDOW);

		this->statusbar = CreateStatusWindow(WS_CHILD | SBT_TOOLTIPS, NULL, *this, IDC_STATUS_BAR);
		int const rcStatusPaneWidths[] = { 360, -1 };
		if ((this->statusbar.GetStyle() & WS_VISIBLE) != 0)
		{
			RECT rect; this->lvFiles.GetWindowRect(&rect);
			this->ScreenToClient(&rect);
			{
				RECT sbRect; this->statusbar.GetWindowRect(&sbRect);
				rect.bottom -= (sbRect.bottom - sbRect.top);
			}
			this->lvFiles.MoveWindow(&rect);
		}
		this->statusbar.SetParts(sizeof(rcStatusPaneWidths) / sizeof(*rcStatusPaneWidths), const_cast<int *>(rcStatusPaneWidths));
		this->statusbar.SetText(0, _T("Type in a file name and press Enter."));
		WTL::CRect rcStatusPane1; this->statusbar.GetRect(1, &rcStatusPane1);
		//this->statusbarProgress.Create(this->statusbar, rcStatusPane1, NULL, WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 0);
		//this->statusbarProgress.SetRange(0, INT_MAX);
		//this->statusbarProgress.SetPos(INT_MAX / 2);
		this->statusbar.ShowWindow(SW_SHOW);
		WTL::CRect clientRect;
		if (this->lvFiles.GetWindowRect(&clientRect))
		{
			this->ScreenToClient(&clientRect);
			this->lvFiles.SetWindowPos(NULL, 0, 0, clientRect.Width(), clientRect.Height() - rcStatusPane1.Height(), SWP_NOMOVE | SWP_NOZORDER);
		}

		this->DlgResize_Init(false, false);
		// this->SetTimer(0, 15 * 60 * 60, );

		std::vector<std::tstring> path_names;
		{
			std::tstring buf;
			size_t prev;
			do
			{
				prev = buf.size();
				buf.resize(std::max(static_cast<size_t>(GetLogicalDriveStrings(static_cast<unsigned long>(buf.size()), buf.empty() ? NULL : &*buf.begin())), buf.size()));
			} while (prev < buf.size());
			for (size_t i = 0, n; n = std::char_traits<TCHAR>::length(&buf[i]), i < buf.size() && buf[i]; i += n + 1)
			{
				path_names.push_back(std::tstring(&buf[i], n));
			}
		}

		this->cmbDrive.SetCurSel(this->cmbDrive.AddString(_T("(All drives)")));
		for (size_t j = 0; j != path_names.size(); ++j)
		{
			this->cmbDrive.AddString(path_names[j].c_str());
		}
		return TRUE;
	}

	LRESULT OnFilesListColumnClick(LPNMHDR pnmh)
	{
		WTL::CWaitCursor wait;
		LPNM_LISTVIEW pLV = (LPNM_LISTVIEW)pnmh;
		WTL::CHeaderCtrl header = this->lvFiles.GetHeader();
		HDITEM hditem = { HDI_LPARAM };
		header.GetItem(pLV->iSubItem, &hditem);
		bool const ctrl_pressed = GetKeyState(VK_CONTROL) < 0;
		bool const shift_pressed = GetKeyState(VK_SHIFT) < 0;
		bool const alt_pressed = GetKeyState(VK_MENU) < 0;
		bool cancelled = false;
		if ((this->lvFiles.GetStyle() & LVS_OWNERDATA) != 0)
		{
			try
			{
				typedef NtfsIndex Index;
				std::vector<Index *> indices;
				for (size_t i = 0; i != this->results.size(); ++i)
				{
					Index *const pindex = const_cast<Index *>(this->results[i].index);
					if (std::find(indices.begin(), indices.end(), pindex) == indices.end())
					{ indices.push_back(pindex); }
				}
				std::vector<lock_guard<mutex> > indices_locks(indices.size());
				for (size_t i = 0; i != indices.size(); ++i)
				{ lock_guard<mutex>(indices[i]->get_mutex()).swap(indices_locks[i]); }
				std::vector<std::pair<std::tstring, std::tstring> > vnames(
#ifdef _OPENMP
					omp_get_max_threads()
#else
					1
#endif
					);
				int const subitem = pLV->iSubItem;
				bool const reversed = ! /* <- due to this->results.base */ !!hditem.lParam;
				this->results.clear_ordering();
				inplace_mergesort(this->results.rbegin(), this->results.rend(), [this, subitem, &vnames, reversed, shift_pressed, alt_pressed, ctrl_pressed](Results::value_type const &_a, Results::value_type const &_b)
				{
					Results::value_type const &a = reversed ? _b : _a, &b = reversed ? _a : _b;
					std::pair<std::tstring, std::tstring> &names = *(vnames.begin()
#ifdef _OPENMP
						+ omp_get_thread_num()
#endif
						);
					if (GetAsyncKeyState(VK_ESCAPE) < 0) { throw CStructured_Exception(ERROR_CANCELLED, NULL); }
					boost::remove_cv<Index>::type const
						*index1 = a.index->unvolatile(),
						*index2 = b.index->unvolatile();
					NtfsIndex::size_info a_size_info, b_size_info;
					bool less = false;
					bool further_test = true;
					if (shift_pressed)
					{
						size_t const
							a_depth = ctrl_pressed ? a.depth : a.depth / 2,
							b_depth = ctrl_pressed ? b.depth : b.depth / 2;
						if (a_depth < b_depth)
						{
							less = true;
							further_test = false;
						}
						else if (b_depth < a_depth)
						{
							less = false;
							further_test = false;
						}
					}
					if (!less && further_test)
					{
						switch (subitem)
						{
						case COLUMN_INDEX_NAME:
							names.first = index1->root_path(); index1->get_path(a.key, names.first, true);
							names.second = index2->root_path(); index2->get_path(b.key, names.second, true);
							less = names.first < names.second;
							break;
						case COLUMN_INDEX_PATH:
							names.first = index1->root_path(); index1->get_path(a.key, names.first, false);
							names.second = index2->root_path(); index2->get_path(b.key, names.second, false);
							less = names.first < names.second;
							break;
						case COLUMN_INDEX_SIZE:
							less = index1->get_sizes(a.key).length > index2->get_sizes(b.key).length;
							break;
						case COLUMN_INDEX_SIZE_ON_DISK:
							a_size_info = index1->get_sizes(a.key), b_size_info = index2->get_sizes(b.key);
							less = (alt_pressed ? a_size_info.bulkiness : a_size_info.allocated) > (alt_pressed ? b_size_info.bulkiness : b_size_info.allocated);
							break;
						case COLUMN_INDEX_CREATION_TIME:
							less = index1->get_stdinfo(a.key.frs).created > index2->get_stdinfo(b.key.frs).created;
							break;
						case COLUMN_INDEX_MODIFICATION_TIME:
							less = index1->get_stdinfo(a.key.frs).written > index2->get_stdinfo(b.key.frs).written;
							break;
						case COLUMN_INDEX_ACCESS_TIME:
							less = index1->get_stdinfo(a.key.frs).accessed > index2->get_stdinfo(b.key.frs).accessed;
							break;
						default: less = false; break;
						}
					}
					return less;
				}, false /* parallelism BREAKS exception handling, and therefore user-cancellation */);
			}
			catch (CStructured_Exception &ex)
			{
				cancelled = true;
				if (ex.GetSENumber() != ERROR_CANCELLED)
				{
					throw;
				}
			}
			this->lvFiles.SetItemCount(this->lvFiles.GetItemCount());
		}
		if (!cancelled)
		{
			hditem.lParam = !hditem.lParam;
			header.SetItem(pLV->iSubItem, &hditem);
		}
		return TRUE;
	}

	void clear()
	{
		WTL::CWaitCursor wait(true, IDC_APPSTARTING);
		this->lastRequestedIcon.resize(0);
		this->lvFiles.SetItemCount(0);
		this->results.clear();
	}

	void Search()
	{
		bool const ctrl_pressed = GetKeyState(VK_CONTROL) < 0;
		bool const shift_pressed = GetKeyState(VK_SHIFT) < 0;
		int const selected = this->cmbDrive.GetCurSel();
		if (selected != 0)
		{
			boost::intrusive_ptr<NtfsIndex> const p = static_cast<NtfsIndex *>(this->cmbDrive.GetItemDataPtr(selected));
			if (!p || p->failed())
			{
				this->MessageBox(_T("This does not appear to be a valid NTFS volume."), _T("Error"), MB_OK | MB_ICONERROR);
				return;
			}
		}
		this->clear();
		WTL::CWaitCursor wait;
		CProgressDialog dlg(*this);
		dlg.SetProgressTitle(_T("Searching..."));
		if (dlg.HasUserCancelled()) { return; }
		std::tstring pattern;
		{
			ATL::CComBSTR bstr;
			if (this->txtPattern.GetWindowText(bstr.m_str))
			{ pattern.assign(bstr, bstr.Length()); }
		}
		WTL::CRegKeyEx key;
		if (key.Open(HKEY_CURRENT_USER, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer")) == ERROR_SUCCESS)
		{
			key.QueryDWORDValue(_T("AltColor"), compressedColor);
			key.QueryDWORDValue(_T("AltEncryptedColor"), encryptedColor);
			key.Close();
		}
		bool const is_regex = !pattern.empty() && *pattern.begin() == _T('>');
		if (is_regex) { pattern.erase(pattern.begin()); }
		bool const is_path_pattern = is_regex || ~pattern.find(_T('\\'));
		bool const is_stream_pattern = is_regex || ~pattern.find(_T(':'));
		bool const requires_root_path_match = is_path_pattern && !pattern.empty() && (is_regex
			? *pattern.begin() != _T('.') && *pattern.begin() != _T('(') && *pattern.begin() != _T('[') && *pattern.begin() != _T('.')
			: *pattern.begin() != _T('*') && *pattern.begin() != _T('?'));
		typedef std::tstring::const_iterator It;
#ifdef BOOST_XPRESSIVE_DYNAMIC_HPP_EAN
		typedef boost::xpressive::basic_regex<It> RE;
		boost::xpressive::match_results<RE::iterator_type> mr;
		RE re;
		if (is_regex)
		{ 
			try { re = RE::compile(pattern.begin(), pattern.end(), boost::xpressive::regex_constants::nosubs | boost::xpressive::regex_constants::optimize | boost::xpressive::regex_constants::single_line | boost::xpressive::regex_constants::icase | boost::xpressive::regex_constants::collate); }
			catch (boost::xpressive::regex_error const &ex) { this->MessageBox(static_cast<WTL::CString>(ex.what()), _T("Regex Error"), MB_ICONERROR); return; }
		}
#else
		if (is_regex)
		{ this->MessageBox(_T("Regex support not included."), _T("Regex Error"), MB_ICONERROR); return; }
#endif
		if (!is_path_pattern && !~pattern.find(_T('*')) && !~pattern.find(_T('?'))) { pattern.insert(pattern.begin(), _T('*')); pattern.insert(pattern.end(), _T('*')); }
		clock_t const start = clock();
		std::vector<uintptr_t> wait_handles;
		std::vector<Results::value_type::first_type> wait_indices;
		// TODO: What if they exceed maximum wait objects?
		bool any_io_pending = false;
		size_t expected_results = 0;
		size_t overall_progress_numerator = 0, overall_progress_denominator = 0;
		for (int ii = 0; ii < this->cmbDrive.GetCount(); ++ii)
		{
			boost::intrusive_ptr<NtfsIndex> const p = static_cast<NtfsIndex *>(this->cmbDrive.GetItemDataPtr(ii));
			if (p && (selected == ii || selected == 0))
			{
				std::tstring const root_path = p->root_path();
				if (!requires_root_path_match || pattern.size() >= root_path.size() && std::equal(root_path.begin(), root_path.end(), pattern.begin()))
				{
					wait_handles.push_back(p->finished_event());
					wait_indices.push_back(p.get());
					expected_results += p->expected_records();
					size_t const records_so_far = p->records_so_far();
					any_io_pending |= records_so_far < p->mft_capacity;
					overall_progress_denominator += p->mft_capacity * 2;
				}
			}
		}
		if (!any_io_pending) { overall_progress_denominator /= 2; }
		if (any_io_pending) { dlg.ForceShow(); }
		try { this->results.reserve(this->results.size() + expected_results + expected_results / 8); }
		catch (std::bad_alloc &) { }
		RaiseIoPriority set_priority;
		while (!dlg.HasUserCancelled() && !wait_handles.empty())
		{
			if (uintptr_t const volume = reinterpret_cast<uintptr_t>(wait_indices.at(0)->volume()))
			{
				if (set_priority.volume() != volume)
				{ RaiseIoPriority(volume).swap(set_priority); }
			}
			unsigned long const wait_result = dlg.WaitMessageLoop(wait_handles.empty() ? NULL : &*wait_handles.begin(), wait_handles.size());
			if (wait_result == WAIT_TIMEOUT)
			{
				if (dlg.ShouldUpdate())
				{
					std::basic_ostringstream<TCHAR> ss;
					ss << _T("Reading file tables...");
					bool any = false;
					size_t temp_overall_progress_numerator = overall_progress_numerator;
					for (size_t i = 0; i != wait_indices.size(); ++i)
					{
						Results::value_type::first_type const j = wait_indices[i];
						size_t const records_so_far = j->records_so_far();
						temp_overall_progress_numerator += records_so_far;
						if (records_so_far != j->mft_capacity)
						{
							if (any) { ss << _T(", "); }
							else { ss << _T(" "); }
							ss << j->root_path() << _T(" ") << _T("(") << nformat(records_so_far, this->loc, true) << _T(" of ") << nformat(j->mft_capacity, this->loc, true) << _T(")");
							any = true;
						}
					}
					std::tstring const text = ss.str();
					dlg.SetProgressText(boost::iterator_range<TCHAR const *>(text.data(), text.data() + text.size()));
					dlg.SetProgress(static_cast<long long>(temp_overall_progress_numerator), static_cast<long long>(overall_progress_denominator));
					dlg.Flush();
				}
			}
			else
			{
				if (wait_result < wait_handles.size())
				{
					std::vector<Results> results_at_depths;
					results_at_depths.reserve(std::numeric_limits<unsigned short>::max() + 1);
					Results::value_type::first_type const i = wait_indices[wait_result];
					size_t current_progress_numerator = 0;
					size_t const current_progress_denominator = i->total_names_and_streams();
					std::tstring const root_path = i->root_path();
					std::tstring current_path = root_path;
					while (!current_path.empty() && *(current_path.end() - 1) == _T('\\')) { current_path.erase(current_path.end() - 1); }
					try
					{
						i->matches([&dlg, is_path_pattern, &results_at_depths, &root_path, &pattern, is_regex, shift_pressed, ctrl_pressed, this, i, &wait_indices, any_io_pending,
							&current_progress_numerator, current_progress_denominator,
							overall_progress_numerator, overall_progress_denominator
#ifdef BOOST_XPRESSIVE_DYNAMIC_HPP_EAN
							, &re
							, &mr
#endif
						](std::pair<It, It> const path, NtfsIndex::key_type const key, size_t const depth)
						{
							if (dlg.ShouldUpdate() || current_progress_denominator - current_progress_numerator <= 1)
							{
								if (dlg.HasUserCancelled()) { throw CStructured_Exception(ERROR_CANCELLED, NULL); }
								// this->lvFiles.SetItemCountEx(static_cast<int>(this->results.size()), 0), this->lvFiles.UpdateWindow();
								size_t temp_overall_progress_numerator = overall_progress_numerator;
								if (any_io_pending)
								{
									for (size_t k = 0; k != wait_indices.size(); ++k)
									{
										Results::value_type::first_type const j = wait_indices[k];
										size_t const records_so_far = j->records_so_far();
										temp_overall_progress_numerator += records_so_far;
									}
								}
								std::tstring text(0x100 + root_path.size() + static_cast<ptrdiff_t>(path.second - path.first), _T('\0'));
								text.resize(static_cast<size_t>(_stprintf(&*text.begin(), _T("Searching %.*s (%s of %s)...\r\n%.*s"),
									static_cast<int>(root_path.size()), root_path.c_str(),
									nformat(current_progress_numerator, this->loc, true).c_str(),
									nformat(current_progress_denominator, this->loc, true).c_str(),
									static_cast<int>(path.second - path.first), path.first == path.second ? NULL : &*path.first)));
								dlg.SetProgressText(boost::iterator_range<TCHAR const *>(text.data(), text.data() + text.size()));
								dlg.SetProgress(temp_overall_progress_numerator + static_cast<unsigned long long>(i->mft_capacity) * static_cast<unsigned long long>(current_progress_numerator) / static_cast<unsigned long long>(current_progress_denominator), static_cast<long long>(overall_progress_denominator));
								dlg.Flush();
							}
							++current_progress_numerator;
							if (current_progress_numerator > current_progress_denominator)
							{
								throw std::logic_error("current_progress_numerator > current_progress_denominator");
							}
							std::pair<It, It> needle = path;
							bool const match =
#ifdef BOOST_XPRESSIVE_DYNAMIC_HPP_EAN
								is_regex ? boost::xpressive::regex_match(needle.first, needle.second, mr, re) :
#endif
								wildcard(pattern.data(), pattern.data() + static_cast<ptrdiff_t>(pattern.size()), needle.first, needle.second, tchar_ci_traits())
								;
							if (match)
							{
								Results::value_type::third_type depth2 = static_cast<Results::value_type::third_type>(depth * 4) /* dividing by 2 later should not mess up the actual depths; it should only affect files vs. directory sub-depths */;
								if (ctrl_pressed && !(i->get_stdinfo(key.frs).attributes & FILE_ATTRIBUTE_DIRECTORY)) { ++depth2; }
								Results *to_insert_in = &this->results;
								if (shift_pressed)
								{
									if (depth2 >= results_at_depths.size()) { results_at_depths.resize(depth2 + 1); }
									to_insert_in = &results_at_depths[depth2];
								}
								Results::value_type item = { i, key, depth2 };
								to_insert_in->push(item);
							}
						}, current_path, is_path_pattern, is_stream_pattern);
					}
					catch (CStructured_Exception &ex)
					{
						if (ex.GetSENumber() != ERROR_CANCELLED) { throw; }
					}
					if (any_io_pending) { overall_progress_numerator += i->mft_capacity; }
					if (current_progress_denominator) { overall_progress_numerator += static_cast<size_t>(static_cast<unsigned long long>(i->mft_capacity) * static_cast<unsigned long long>(current_progress_numerator) / static_cast<unsigned long long>(current_progress_denominator)); }
					size_t size_to_reserve = 0;
					for (size_t j = 0; j != results_at_depths.size(); ++j)
					{
						size_to_reserve += results_at_depths[j].size();
					}
					this->results.reserve(this->results.size() + size_to_reserve);
					for (size_t j = results_at_depths.size(); j != 0 && (--j, true); )
					{
						this->results.insert_from(results_at_depths[j]);
					}
					this->results.batch_and_reverse();
					this->lvFiles.SetItemCountEx(static_cast<int>(this->results.size()), 0);
				}
				wait_indices.erase(wait_indices.begin() + static_cast<ptrdiff_t>(wait_result));
				wait_handles.erase(wait_handles.begin() + static_cast<ptrdiff_t>(wait_result));
			}
		}
		clock_t const end = clock();
		TCHAR buf[0x100];
		_stprintf(buf, _T("%s results in %.2lf seconds"), nformat(this->results.size(), this->loc, true).c_str(), (end - start) * 1.0 / CLOCKS_PER_SEC);
		this->statusbar.SetText(0, buf);
	}

	void OnBrowse(UINT /*uNotifyCode*/, int /*nID*/, HWND /*hWnd*/)
	{
		TCHAR path[MAX_PATH];
		BROWSEINFO info = { this->m_hWnd, NULL, path, _T("If you would like to filter the results such that they include only the subfolders and files of a specific folder, specify that folder here:"), BIF_NONEWFOLDERBUTTON | BIF_USENEWUI | BIF_RETURNONLYFSDIRS | BIF_DONTGOBELOWDOMAIN };
		if (LPITEMIDLIST const pidl = SHBrowseForFolder(&info))
		{
			bool const success = !!SHGetPathFromIDList(pidl, path);
			ILFree(pidl);
			if (success)
			{
				this->txtPattern.SetWindowText((std::tstring(path) + _T("\\*")).c_str());
				this->GotoDlgCtrl(this->txtPattern);
				this->txtPattern.SetSel(this->txtPattern.GetWindowTextLength(), this->txtPattern.GetWindowTextLength());
			}
		}
	}

	void OnOK(UINT /*uNotifyCode*/, int /*nID*/, HWND /*hWnd*/)
	{
		if (GetFocus() == this->lvFiles)
		{
			int const index = this->lvFiles.GetNextItem(-1, LVNI_FOCUSED);
			if (index >= 0 && (this->lvFiles.GetItemState(index, LVNI_SELECTED) & LVNI_SELECTED))
			{
				this->DoubleClick(index);
			}
			else
			{
				this->Search();
				if (index >= 0)
				{
					this->lvFiles.EnsureVisible(index, FALSE);
					this->lvFiles.SetItemState(index, LVNI_FOCUSED, LVNI_FOCUSED);
				}
			}
		}
		else if (GetFocus() == this->txtPattern || GetFocus() == this->btnOK)
		{
			this->Search();
		}
	}

	LRESULT OnContextMenu(UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		(void)uMsg;
		LRESULT result = 0;
		POINT point = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
		if ((HWND)wParam == this->lvFiles)
		{
			std::vector<int> indices;
			int index;
			if (point.x == -1 && point.y == -1)
			{
				index = this->lvFiles.GetSelectedIndex();
				RECT bounds = { };
				this->lvFiles.GetItemRect(index, &bounds, LVIR_SELECTBOUNDS);
				this->lvFiles.ClientToScreen(&bounds);
				point.x = bounds.left;
				point.y = bounds.top;
				indices.push_back(index);
			}
			else
			{
				POINT clientPoint = point;
				this->lvFiles.ScreenToClient(&clientPoint);
				index = this->lvFiles.HitTest(clientPoint, 0);
				if (index >= 0)
				{
					int i = -1;
					for (;;)
					{
						i = this->lvFiles.GetNextItem(i, LVNI_SELECTED);
						if (i < 0) { break; }
						indices.push_back(i);
					}
				}
			}
			int const focused = this->lvFiles.GetNextItem(-1, LVNI_FOCUSED);
			if (!indices.empty())
			{
				this->RightClick(indices, point, focused);
			}
		}
		return result;
	}

	void RightClick(std::vector<int> const &indices, POINT const &point, int const focused)
	{
		std::vector<Results::value_type const *> results;
		for (size_t i = 0; i < indices.size(); ++i)
		{
			if (indices[i] < 0) { continue; }
			results.push_back(&this->results[indices[i]]);
		}
		HRESULT volatile hr = S_OK;
		UINT const minID = 1000;
		WTL::CMenu menu;
		menu.CreatePopupMenu();
		ATL::CComPtr<IContextMenu> contextMenu;
		std::auto_ptr<std::pair<std::pair<CShellItemIDList, ATL::CComPtr<IShellFolder> >, std::vector<CShellItemIDList> > > p(
			new std::pair<std::pair<CShellItemIDList, ATL::CComPtr<IShellFolder> >, std::vector<CShellItemIDList> >());
		p->second.reserve(results.size());  // REQUIRED, to avoid copying CShellItemIDList objects (they're not copyable!)
		SFGAOF sfgao = 0;
		std::tstring common_ancestor_path;
		for (size_t i = 0; i < results.size(); ++i)
		{
			Results::value_type const &row = *results[i];
			Results::value_type::first_type const &index = row.index;
			std::tstring path = index->root_path();
			if (index->get_path(row.key, path, false))
			{
				remove_path_stream_and_trailing_sep(path);
			}
			if (i == 0)
			{
				common_ancestor_path = path;
			}
			CShellItemIDList itemIdList;
			if (SHParseDisplayName(path.c_str(), NULL, &itemIdList, sfgao, &sfgao) == S_OK)
			{
				p->second.push_back(CShellItemIDList());
				p->second.back().Attach(itemIdList.Detach());
				if (i != 0)
				{
					common_ancestor_path = path;
					size_t j;
					for (j = 0; j < (path.size() < common_ancestor_path.size() ? path.size() : common_ancestor_path.size()); j++)
					{
						if (path[j] != common_ancestor_path[j])
						{
							break;
						}
					}
					common_ancestor_path.erase(common_ancestor_path.begin() + static_cast<ptrdiff_t>(j), common_ancestor_path.end());
				}
			}
		}
		common_ancestor_path.erase(dirname(common_ancestor_path.begin(), common_ancestor_path.end()), common_ancestor_path.end());
		if (hr == S_OK)
		{
			hr = SHParseDisplayName(common_ancestor_path.c_str(), NULL, &p->first.first, sfgao, &sfgao);
		}
		if (hr == S_OK)
		{
			ATL::CComPtr<IShellFolder> desktop;
			hr = SHGetDesktopFolder(&desktop);
			if (hr == S_OK)
			{
				if (p->first.first.m_pidl->mkid.cb)
				{
					hr = desktop->BindToObject(p->first.first, NULL, IID_IShellFolder, reinterpret_cast<void **>(&p->first.second));
				}
				else
				{
					hr = desktop.QueryInterface(&p->first.second);
				}
			}
		}

		if (hr == S_OK)
		{
			std::vector<LPCITEMIDLIST> relative_item_ids(p->second.size());
			for (size_t i = 0; i < p->second.size(); ++i)
			{
				relative_item_ids[i] = ILFindChild(p->first.first, p->second[i]);
			}
			hr = p->first.second->GetUIObjectOf(
				*this,
				static_cast<UINT>(relative_item_ids.size()),
				relative_item_ids.empty() ? NULL : &relative_item_ids[0],
				IID_IContextMenu,
				NULL,
				&reinterpret_cast<void *&>(contextMenu.p));
		}
		if (hr == S_OK)
		{
			hr = contextMenu->QueryContextMenu(menu, 0, minID, UINT_MAX, 0x80 /*CMF_ITEMMENU*/);
		}

		unsigned int ninserted = 0;
		UINT const openContainingFolderId = minID - 1;

		if (results.size() == 1)
		{
			MENUITEMINFO mii2 = { sizeof(mii2), MIIM_ID | MIIM_STRING | MIIM_STATE, MFT_STRING, MFS_ENABLED, openContainingFolderId, NULL, NULL, NULL, NULL, _T("Open &Containing Folder") };
			menu.InsertMenuItem(ninserted++, TRUE, &mii2);

			if (false) { menu.SetMenuDefaultItem(openContainingFolderId, FALSE); }
		}
		if (0 <= focused && static_cast<size_t>(focused) < this->results.size())
		{
			std::basic_stringstream<TCHAR> ssName;
			ssName.imbue(this->loc);
			ssName << _T("File #") << this->results[static_cast<size_t>(focused)].key.frs;
			std::tstring name = ssName.str();
			if (!name.empty())
			{
				MENUITEMINFO mii1 = { sizeof(mii1), MIIM_ID | MIIM_STRING | MIIM_STATE, MFT_STRING, MFS_DISABLED, minID - 2, NULL, NULL, NULL, NULL, (name.c_str(), &name[0]) };
				menu.InsertMenuItem(ninserted++, TRUE, &mii1);
			}
		}
		if (contextMenu && ninserted)
		{
			MENUITEMINFO mii = { sizeof(mii), 0, MFT_MENUBREAK };
			menu.InsertMenuItem(ninserted, TRUE, &mii);
		}
		UINT id = menu.TrackPopupMenu(
			TPM_RETURNCMD | TPM_NONOTIFY | (GetKeyState(VK_SHIFT) < 0 ? CMF_EXTENDEDVERBS : 0) |
			(GetSystemMetrics(SM_MENUDROPALIGNMENT) ? TPM_RIGHTALIGN | TPM_HORNEGANIMATION : TPM_LEFTALIGN | TPM_HORPOSANIMATION),
			point.x, point.y, *this);
		if (!id)
		{
			// User cancelled
		}
		else if (id == openContainingFolderId)
		{
			if (QueueUserWorkItem(&SHOpenFolderAndSelectItemsThread, p.get(), WT_EXECUTEINUITHREAD))
			{
				p.release();
			}
		}
		else if (id >= minID)
		{
			CMINVOKECOMMANDINFO cmd = { sizeof(cmd), CMIC_MASK_ASYNCOK, *this, reinterpret_cast<LPCSTR>(static_cast<uintptr_t>(id - minID)), NULL, NULL, SW_SHOW };
			hr = contextMenu ? contextMenu->InvokeCommand(&cmd) : S_FALSE;
			if (hr == S_OK)
			{
			}
			else
			{
				this->MessageBox(GetAnyErrorText(hr), _T("Error"), MB_OK | MB_ICONERROR);
			}
		}
	}

	void DoubleClick(int index)
	{
		Results::value_type const &result = this->results[static_cast<size_t>(index)];
		Results::value_type::first_type const &i = result.index;
		std::tstring path;
		path = i->root_path(), i->get_path(result.key, path, false);
		remove_path_stream_and_trailing_sep(path);
		std::auto_ptr<std::pair<std::pair<CShellItemIDList, ATL::CComPtr<IShellFolder> >, std::vector<CShellItemIDList> > > p(
			new std::pair<std::pair<CShellItemIDList, ATL::CComPtr<IShellFolder> >, std::vector<CShellItemIDList> >());
		SFGAOF sfgao = 0;
		std::tstring const path_directory(path.begin(), dirname(path.begin(), path.end()));
		HRESULT hr = SHParseDisplayName(path_directory.c_str(), NULL, &p->first.first, 0, &sfgao);
		if (hr == S_OK)
		{
			ATL::CComPtr<IShellFolder> desktop;
			hr = SHGetDesktopFolder(&desktop);
			if (hr == S_OK)
			{
				if (p->first.first.m_pidl->mkid.cb)
				{
					hr = desktop->BindToObject(p->first.first, NULL, IID_IShellFolder, reinterpret_cast<void **>(&p->first.second));
				}
				else
				{
					hr = desktop.QueryInterface(&p->first.second);
				}
			}
		}
		if (hr == S_OK && basename(path.begin(), path.end()) != path.end())
		{
			p->second.resize(1);
			hr = SHParseDisplayName((path.c_str(), path.empty() ? NULL : &path[0]), NULL, &p->second.back().m_pidl, sfgao, &sfgao);
		}
		SHELLEXECUTEINFO shei = { sizeof(shei), SEE_MASK_INVOKEIDLIST | SEE_MASK_UNICODE, *this, NULL, NULL, p->second.empty() ? path_directory.c_str() : NULL, path_directory.c_str(), SW_SHOWDEFAULT, 0, p->second.empty() ? NULL : p->second.back().m_pidl };
		ShellExecuteEx(&shei);
	}

	LRESULT OnFilesDoubleClick(LPNMHDR pnmh)
	{
		// Wow64Disable wow64Disabled;
		WTL::CWaitCursor wait;
		if (this->lvFiles.GetSelectedCount() == 1)
		{
			this->DoubleClick(this->lvFiles.GetNextItem(-1, LVNI_SELECTED));
		}
		return 0;
	}

	void OnFileNameChange(UINT /*uNotifyCode*/, int /*nID*/, HWND /*hWnd*/)
	{
		if (!this->autocomplete_called)
		{
			if (SHAutoComplete(this->txtPattern, SHACF_FILESYS_ONLY | SHACF_USETAB) == S_OK)  // Needs CoInitialize() to have been called (use CoInit)
			{
				this->autocomplete_called = true;
			}
		}
	}

	LRESULT OnFileNameArrowKey(LPNMHDR pnmh)
	{
		CSearchPattern::KeyNotify *const p = (CSearchPattern::KeyNotify *)pnmh;
		if (p->vkey == VK_UP || p->vkey == VK_DOWN)
		{
			this->cmbDrive.SendMessage(p->hdr.code == CSearchPattern::CUN_KEYDOWN ? WM_KEYDOWN : WM_KEYUP, p->vkey, p->lParam);
		}
		else
		{
			if (p->hdr.code == CSearchPattern::CUN_KEYDOWN && p->vkey == VK_DOWN && this->lvFiles.GetItemCount() > 0)
			{
				this->lvFiles.SetFocus();
			}
			this->lvFiles.SendMessage(p->hdr.code == CSearchPattern::CUN_KEYDOWN ? WM_KEYDOWN : WM_KEYUP, p->vkey, p->lParam);
		}
		return 0;
	}

	LRESULT OnFilesKeyDown(LPNMHDR pnmh)
	{
		NMLVKEYDOWN *const p = (NMLVKEYDOWN *) pnmh;
		if (p->wVKey == VK_UP && this->lvFiles.GetNextItem(-1, LVNI_FOCUSED) == 0)
		{
			this->txtPattern.SetFocus();
		}
		return 0;
	}

	template<class Index>
	void GetSubItemText_impl(Index *const i, Results::value_type::second_type const key, int const subitem, std::tstring &text, bool const lock_index = true) const
	{
		text.erase(text.begin(), text.end());
		switch (subitem)
		{
		case COLUMN_INDEX_NAME: i->get_path(key, text, true); deldirsep(text); break;
		case COLUMN_INDEX_PATH: text = i->root_path(); i->get_path(key, text, false); break;
		case COLUMN_INDEX_SIZE: text = nformat(static_cast<unsigned long long>(i->get_sizes(key).length), this->loc, true); break;
		case COLUMN_INDEX_SIZE_ON_DISK: text = nformat(static_cast<unsigned long long>(i->get_sizes(key).allocated), this->loc, true); break;
		case COLUMN_INDEX_CREATION_TIME    : text.assign(0x100, _T('\0')); SystemTimeToString(i->get_stdinfo(key.frs).created, &text[0], text.size()); text = std::tstring(text.c_str()); break;
		case COLUMN_INDEX_MODIFICATION_TIME: text.assign(0x100, _T('\0')); SystemTimeToString(i->get_stdinfo(key.frs).written, &text[0], text.size()); text = std::tstring(text.c_str()); break;
		case COLUMN_INDEX_ACCESS_TIME      : text.assign(0x100, _T('\0')); SystemTimeToString(i->get_stdinfo(key.frs).accessed, &text[0], text.size()); text = std::tstring(text.c_str()); break;
		default: break;
		}
	}

	void GetSubItemText(Results::value_type const &result, int const subitem, std::tstring &text, bool const lock_index = true) const
	{
		lock_index
			? this->GetSubItemText_impl(result.index, result.key, subitem, text)
			: this->GetSubItemText_impl(const_cast<NtfsIndex const *>(result.index), result.key, subitem, text);
	}

	LRESULT OnFilesIncrementalSearch(LPNMHDR pnmh)
	{
		NMLVFINDITEM *const pLV = (NMLVFINDITEM *) pnmh;
		if (pLV->lvfi.flags & (LVFI_STRING | LVFI_PARTIAL))
		{
			int const n = this->lvFiles.GetItemCount();
			pLV->lvfi.lParam = this->lvFiles.GetNextItem(-1, LVNI_FOCUSED);
			typedef tchar_ci_traits char_traits;
			TCHAR const *needle = pLV->lvfi.psz;
			size_t needle_length = char_traits::length(needle);
			while (needle_length > 1 && *(needle + 1) == *needle)
			{
				++needle;
				--needle_length;
			}
			std::vector<lock_guard<mutex> > indices_locks;
			indices_locks.reserve(static_cast<size_t>(this->cmbDrive.GetCount()));  // ensure we don't copy lock_guard's
			std::tstring text;
			for (int i = 0; i < n; ++i)
			{
				int const iItem = (pLV->lvfi.lParam + (needle_length > 1 ? 0 : 1) + i) % n;
				if (!(pLV->lvfi.flags & LVFI_WRAP) && iItem == 0 && i != 0)
				{
					break;
				}
				Results::value_type const &result = this->results[static_cast<size_t>(iItem)];
				{
					mutex *const m = &result.index->get_mutex();
					bool found_lock = false;
					for (size_t j = 0; j != indices_locks.size(); ++j)
					{
						if (indices_locks[j].p == m)
						{
							found_lock = true;
							break;
						}
					}
					if (!found_lock)
					{
						indices_locks.push_back(lock_guard<mutex>());
						lock_guard<mutex>(m).swap(indices_locks.back());
					}
				}
				this->GetSubItemText(result, COLUMN_INDEX_NAME, text, false);
				bool const match = (pLV->lvfi.flags & (LVFI_PARTIAL | (0x0004 /*LVFI_SUBSTRING*/)))
					? text.size() >= needle_length && char_traits::compare(text.data(), needle, needle_length) == 0
					: text.size() == needle_length && char_traits::compare(text.data(), needle, needle_length) == 0;
				if (match)
				{
					pLV->lvfi.lParam = iItem;
					break;
				}
			}
		}

		return 0;
	}

	LRESULT OnFilesGetDispInfo(LPNMHDR pnmh)
	{
		NMLVDISPINFO *const pLV = (NMLVDISPINFO *) pnmh;

		if ((this->lvFiles.GetStyle() & LVS_OWNERDATA) != 0 && (pLV->item.mask & LVIF_TEXT) != 0)
		{
			Results::value_type const &result = this->results[static_cast<size_t>(pLV->item.iItem)];
			Results::value_type::first_type const &i = result.index;
			std::tstring text, path;
			this->GetSubItemText(result, pLV->item.iSubItem, text);
			this->GetSubItemText(result, COLUMN_INDEX_PATH, path);
			if (!text.empty()) { _tcsncpy(pLV->item.pszText, text.c_str(), pLV->item.cchTextMax); }
			if (pLV->item.iSubItem == 0)
			{
				int iImage = this->CacheIcon(path, static_cast<int>(pLV->item.iItem), i->get_stdinfo(result.key.frs).attributes, true);
				if (iImage >= 0) { pLV->item.iImage = iImage; }
			}
		}
		return 0;
	}

	void OnCancel(UINT /*uNotifyCode*/, int /*nID*/, HWND /*hWnd*/)
	{
		if (this->CheckAndCreateIcon(false))
		{
			this->ShowWindow(SW_HIDE);
		}
	}

	BOOL PreTranslateMessage(MSG* pMsg)
	{
		if (this->accel)
		{
			if (this->accel.TranslateAccelerator(this->m_hWnd, pMsg))
			{
				return TRUE;
			}
		}

		return this->CWindow::IsDialogMessage(pMsg);
	}
	
	LRESULT OnFilesListCustomDraw(LPNMHDR pnmh)
	{
		LRESULT result;
		COLORREF const deletedColor = RGB(0xFF, 0, 0);
		COLORREF encryptedColor = RGB(0, 0xFF, 0);
		COLORREF compressedColor = RGB(0, 0, 0xFF);
		COLORREF sparseColor = RGB(GetRValue(compressedColor), (GetGValue(compressedColor) + GetBValue(compressedColor)) / 2, (GetGValue(compressedColor) + GetBValue(compressedColor)) / 2);
		LPNMLVCUSTOMDRAW const pLV = (LPNMLVCUSTOMDRAW)pnmh;
		if (pLV->nmcd.dwItemSpec < this->results.size())
		{
			Results::value_type const &item = this->results[static_cast<size_t>(pLV->nmcd.dwItemSpec)];
			Results::value_type::first_type const &i = item.index;
			unsigned long const attrs = i->get_stdinfo(item.key.frs).attributes;
			switch (pLV->nmcd.dwDrawStage)
			{
			case CDDS_PREPAINT:
				result = CDRF_NOTIFYITEMDRAW;
				break;
			case CDDS_ITEMPREPAINT:
				result = CDRF_NOTIFYSUBITEMDRAW;
				break;
			case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
				if ((this->small_image_list() == this->imgListLarge || this->small_image_list() == this->imgListExtraLarge) && pLV->iSubItem == 1)
				{ result = 0x8 /*CDRF_DOERASE*/ | CDRF_NOTIFYPOSTPAINT; }
				else
				{
					if ((attrs & 0x40000000) != 0)
					{
						pLV->clrText = deletedColor;
					}
					else if ((attrs & FILE_ATTRIBUTE_ENCRYPTED) != 0)
					{
						pLV->clrText = encryptedColor;
					}
					else if ((attrs & FILE_ATTRIBUTE_COMPRESSED) != 0)
					{
						pLV->clrText = compressedColor;
					}
					else if ((attrs & FILE_ATTRIBUTE_SPARSE_FILE) != 0)
					{
						pLV->clrText = sparseColor;
					}
					result = CDRF_DODEFAULT;
				}
				break;
			case CDDS_ITEMPOSTPAINT | CDDS_SUBITEM:
				result = CDRF_SKIPDEFAULT;
				{
					Results::value_type const &row = this->results[static_cast<size_t>(pLV->nmcd.dwItemSpec)];
					std::tstring itemText;
					this->GetSubItemText(row, pLV->iSubItem, itemText);
					WTL::CDCHandle dc(pLV->nmcd.hdc);
					RECT rcTwips = pLV->nmcd.rc;
					rcTwips.left = (int) ((rcTwips.left + 6) * 1440 / dc.GetDeviceCaps(LOGPIXELSX));
					rcTwips.right = (int) (rcTwips.right * 1440 / dc.GetDeviceCaps(LOGPIXELSX));
					rcTwips.top = (int) (rcTwips.top * 1440 / dc.GetDeviceCaps(LOGPIXELSY));
					rcTwips.bottom = (int) (rcTwips.bottom * 1440 / dc.GetDeviceCaps(LOGPIXELSY));
					int const savedDC = dc.SaveDC();
					{
						std::replace(itemText.begin(), itemText.end(), _T(' '), _T('\u00A0'));
						replace_all(itemText, _T("\\"), _T("\\\u200B"));
						if (!this->richEdit)
						{
							this->hRichEdit = LoadLibrary(_T("riched20.dll"));
							this->richEdit.Create(this->lvFiles, NULL, 0, ES_MULTILINE, WS_EX_TRANSPARENT);
							this->richEdit.SetFont(this->lvFiles.GetFont());
						}
#ifdef _UNICODE
						this->richEdit.SetTextEx(itemText.c_str(), ST_DEFAULT, 1200);
#else
						this->richEdit.SetTextEx(itemText.c_str(), ST_DEFAULT, CP_ACP);
#endif
						CHARFORMAT format = { sizeof(format), CFM_COLOR, 0, 0, 0, 0 };
						if ((attrs & 0x40000000) != 0)
						{
							format.crTextColor = deletedColor;
						}
						else if ((attrs & FILE_ATTRIBUTE_ENCRYPTED) != 0)
						{
							format.crTextColor = encryptedColor;
						}
						else if ((attrs & FILE_ATTRIBUTE_COMPRESSED) != 0)
						{
							format.crTextColor = compressedColor;
						}
						else if ((attrs & FILE_ATTRIBUTE_SPARSE_FILE) != 0)
						{
							format.crTextColor = sparseColor;
						}
						else
						{
							bool const selected = (this->lvFiles.GetItemState(static_cast<int>(pLV->nmcd.dwItemSpec), LVIS_SELECTED) & LVIS_SELECTED) != 0;
							format.crTextColor = GetSysColor(selected && this->lvFiles.IsThemeNull() ? COLOR_HIGHLIGHTTEXT : COLOR_WINDOWTEXT);
						}
						this->richEdit.SetSel(0, -1);
						this->richEdit.SetSelectionCharFormat(format);
						if (false)
						{
							size_t last_sep = itemText.find_last_of(_T('\\'));
							if (~last_sep)
							{
								this->richEdit.SetSel(static_cast<long>(last_sep + 1), this->richEdit.GetTextLength());
								CHARFORMAT bold = { sizeof(bold), CFM_BOLD, CFE_BOLD, 0, 0, 0 };
								this->richEdit.SetSelectionCharFormat(bold);
							}
						}
						FORMATRANGE formatRange = { dc, dc, rcTwips, rcTwips, { 0, -1 } };
						this->richEdit.FormatRange(formatRange, FALSE);
						LONG height = formatRange.rc.bottom - formatRange.rc.top;
						formatRange.rc = formatRange.rcPage;
						formatRange.rc.top += (formatRange.rc.bottom - formatRange.rc.top - height) / 2;
						this->richEdit.FormatRange(formatRange, TRUE);

						this->richEdit.FormatRange(NULL);
					}
					dc.RestoreDC(savedDC);
				}
				break;
			default:
				result = CDRF_DODEFAULT;
				break;
			}
		}
		else { result = CDRF_DODEFAULT; }
		return result;
	}

	void OnClose(UINT /*uNotifyCode*/ = 0, int nID = IDCANCEL, HWND /*hWnd*/ = NULL)
	{
		this->DestroyWindow();
		PostQuitMessage(nID);
		// this->EndDialog(nID);
	}
	
	LRESULT OnDeviceChange(UINT /*uMsg*/, WPARAM wParam, LPARAM lParam)
	{
		switch (wParam)
		{
		case DBT_DEVICEQUERYREMOVEFAILED:
			{
			}
			break;
		case DBT_DEVICEQUERYREMOVE:
			{
				DEV_BROADCAST_HDR const &header = *reinterpret_cast<DEV_BROADCAST_HDR *>(lParam);
				if (header.dbch_devicetype == DBT_DEVTYP_HANDLE)
				{
					reinterpret_cast<DEV_BROADCAST_HANDLE const &>(header);
				}
			}
			break;
		case DBT_DEVICEREMOVECOMPLETE:
			{
				DEV_BROADCAST_HDR const &header = *reinterpret_cast<DEV_BROADCAST_HDR *>(lParam);
				if (header.dbch_devicetype == DBT_DEVTYP_HANDLE)
				{
					reinterpret_cast<DEV_BROADCAST_HANDLE const &>(header);
				}
			}
			break;
		case DBT_DEVICEARRIVAL:
			{
				DEV_BROADCAST_HDR const &header = *reinterpret_cast<DEV_BROADCAST_HDR *>(lParam);
				if (header.dbch_devicetype == DBT_DEVTYP_VOLUME)
				{
				}
			}
			break;
		default: break;
		}
		return TRUE;
	}

	void OnWindowPosChanged(LPWINDOWPOS lpWndPos)
	{
		if (lpWndPos->flags & SWP_SHOWWINDOW)
		{
			SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
			this->DeleteNotifyIcon();
			this->UpdateWindow();
			if (this->threads.empty())  // first-time initialization?
			{
				this->Refresh(true);
				for (size_t i = 0; i != this->num_threads; ++i)
				{
					unsigned int id;
					this->threads.push_back(_beginthreadex(NULL, 0, iocp_worker, this->iocp, 0, &id));
				}
				RegisterWaitForSingleObject(&this->hWait, hEvent, &WaitCallback, this->m_hWnd, INFINITE, WT_EXECUTEINUITHREAD);
			}
		}
		else if (lpWndPos->flags & SWP_HIDEWINDOW)
		{
			SetPriorityClass(GetCurrentProcess(), 0x100000 /*PROCESS_MODE_BACKGROUND_BEGIN*/);
			SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
		}
		this->SetMsgHandled(FALSE);
	}

	void DeleteNotifyIcon()
	{
		NOTIFYICONDATA nid = { sizeof(nid), *this, 0 };
		Shell_NotifyIcon(NIM_DELETE, &nid);
		SetPriorityClass(GetCurrentProcess(), 0x200000 /*PROCESS_MODE_BACKGROUND_END*/);
	}

	BOOL CheckAndCreateIcon(bool checkVisible)
	{
		NOTIFYICONDATA nid = { sizeof(nid), *this, 0, NIF_MESSAGE | NIF_ICON | NIF_TIP, WM_NOTIFYICON, this->GetIcon(FALSE), _T("SwiftSearch") };
		return (!checkVisible || !this->IsWindowVisible()) && Shell_NotifyIcon(NIM_ADD, &nid);
	}

	LRESULT OnTaskbarCreated(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/)
	{
		this->CheckAndCreateIcon(true);
		return 0;
	}

	LRESULT OnNotifyIcon(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM lParam)
	{
		if (lParam == WM_LBUTTONUP || lParam == WM_KEYUP)
		{
			this->ShowWindow(SW_SHOW);
		}
		return 0;
	}

	void OnHelpRegex(UINT /*uNotifyCode*/, int /*nID*/, CWindow /*wndCtl*/)
	{
		this->MessageBox(
			_T("To find a file, select the drive you want to search, enter part of the file name or path, and click Search.\r\n\r\n")
			_T("You can either use wildcards, which are the default, or regular expressions, which require starting the pattern with a '>' character.\r\n\r\n")
			_T("Wildcards work the same as in Windows; regular expressions are implemented using the Boost.Xpressive library.\r\n\r\n")
			_T("Some common regular expressions:\r\n")
			_T(".\t= A single character\r\n")
			_T("\\+\t= A plus symbol (backslash is the escape character)\r\n")
			_T("[a-cG-K]\t= A single character from a to c or from G to K\r\n")
			_T("(abc|def)\t= Either \"abc\" or \"def\"\r\n\r\n")
			_T("\"Quantifiers\" can follow any expression:\r\n")
			_T("*\t= Zero or more occurrences\r\n")
			_T("+\t= One or more occurrences\r\n")
			_T("{m,n}\t= Between m and n occurrences (n is optional)\r\n\r\n")
			_T("Examples of regular expressions:\r\n")
			_T("Hi{2,}.*Bye= At least two occurrences of \"Hi\", followed by any number of characters, followed by \"Bye\"\r\n")
			_T(".*\t= At least zero characters\r\n")
			_T("Hi.+\\+Bye\t= At least one character between \"Hi\" and \"+Bye\"\r\n")
		, _T("Regular expressions"), MB_ICONINFORMATION);
	}

	void OnViewLargeIcons(UINT /*uNotifyCode*/, int /*nID*/, CWindow /*wndCtl*/)
	{
		bool const large = this->small_image_list() != this->imgListLarge;
		this->small_image_list(large ? this->imgListLarge : this->imgListSmall);
		this->lvFiles.RedrawWindow();
		this->menu.CheckMenuItem(ID_VIEW_LARGEICONS, large ? MF_CHECKED : MF_UNCHECKED);
	}

	void OnViewGridlines(UINT /*uNotifyCode*/, int /*nID*/, CWindow /*wndCtl*/)
	{
		this->lvFiles.SetExtendedListViewStyle(this->lvFiles.GetExtendedListViewStyle() ^ LVS_EX_GRIDLINES);
		this->lvFiles.RedrawWindow();
		this->menu.CheckMenuItem(ID_VIEW_GRIDLINES, (this->lvFiles.GetExtendedListViewStyle() & LVS_EX_GRIDLINES) ? MF_CHECKED : MF_UNCHECKED);
	}

	void OnViewFitColumns(UINT /*uNotifyCode*/, int /*nID*/, CWindow /*wndCtl*/)
	{
		WTL::CListViewCtrl &wndListView = this->lvFiles;

		RECT rect;
		wndListView.GetClientRect(&rect);
		DWORD width;
		width = (std::max)(1, (int) (rect.right - rect.left) - GetSystemMetrics(SM_CXVSCROLL) - 2);
		WTL::CHeaderCtrl wndListViewHeader = wndListView.GetHeader();
		int oldTotalColumnsWidth;
		oldTotalColumnsWidth = 0;
		int columnCount;
		columnCount = wndListViewHeader.GetItemCount();
		CSetRedraw no_redraw(wndListView, false);
		for (int i = 0; i < columnCount; i++)
		{
			oldTotalColumnsWidth += wndListView.GetColumnWidth(i);
		}
		for (int i = 0; i < columnCount; i++)
		{
			int colWidth = wndListView.GetColumnWidth(i);
			int newWidth = MulDiv(colWidth, width, oldTotalColumnsWidth);
			newWidth = (std::max)(newWidth, 1);
			wndListView.SetColumnWidth(i, newWidth);
		}
	}

	void OnRefresh(UINT /*uNotifyCode*/, int /*nID*/, CWindow /*wndCtl*/)
	{
		return this->Refresh(false);
	}

	void Refresh(bool const initial)
	{
		if (!initial && this->indices_created < this->cmbDrive.GetCount() - 1)
		{
			// Ignore the request due to potential race condition... at least wait until all the threads have started!
			// Otherwise, if the user presses F5 we will delete some entries, which will invalidate threads' copies of their index in the combobox
			return;
		}
		this->clear();
		int const selected = this->cmbDrive.GetCurSel();
		for (int ii = 0; ii < this->cmbDrive.GetCount(); ++ii)
		{
			if (selected == 0 || ii == selected)
			{
				boost::intrusive_ptr<NtfsIndex> q = static_cast<NtfsIndex *>(this->cmbDrive.GetItemDataPtr(ii));
				if (q || initial && ii != 0)
				{
					std::tstring path_name;
					if (initial)
					{
						WTL::CString path_name_;
						this->cmbDrive.GetLBText(ii, path_name_);
						path_name = static_cast<LPCTSTR>(path_name_);
					}
					else
					{
						path_name = q->root_path();
						q->cancel();
						if (this->cmbDrive.SetItemDataPtr(ii, NULL) != CB_ERR)
						{
							--this->indices_created;
							intrusive_ptr_release(q.get());
						}
					}
					q.reset(new NtfsIndex(path_name), true);
					typedef OverlappedNtfsMftReadPayload T;
					boost::intrusive_ptr<T> p(new T(this->iocp, q, this->m_hWnd, this->closing_event));
					if (PostQueuedCompletionStatus(this->iocp, 0, static_cast<uintptr_t>(ii), &*p))
					{
						if (this->cmbDrive.SetItemDataPtr(ii, q.get()) != CB_ERR)
						{
							q.detach();
							++this->indices_created;
						}
						p.detach();
					}
				}
			}
		}
	}

	BEGIN_MSG_MAP_EX(CMainDlg)
		CHAIN_MSG_MAP(CInvokeImpl<CMainDlg>)
		CHAIN_MSG_MAP(CDialogResize<CMainDlg>)
		MSG_WM_DESTROY(OnDestroy)
		MSG_WM_INITDIALOG(OnInitDialog)
		MSG_WM_WINDOWPOSCHANGED(OnWindowPosChanged)
		MSG_WM_CLOSE(OnClose)
		MESSAGE_HANDLER_EX(WM_DEVICECHANGE, OnDeviceChange)  // Don't use MSG_WM_DEVICECHANGE(); it's broken (uses DWORD)
		MESSAGE_HANDLER_EX(WM_NOTIFYICON, OnNotifyIcon)
		MESSAGE_HANDLER_EX(WM_TASKBARCREATED, OnTaskbarCreated)
		MESSAGE_HANDLER_EX(WM_MOUSEWHEEL, OnMouseWheel)
		MESSAGE_HANDLER_EX(WM_CONTEXTMENU, OnContextMenu)
		COMMAND_ID_HANDLER_EX(ID_HELP_USINGREGULAREXPRESSIONS, OnHelpRegex)
		COMMAND_ID_HANDLER_EX(ID_VIEW_GRIDLINES, OnViewGridlines)
		COMMAND_ID_HANDLER_EX(ID_VIEW_LARGEICONS, OnViewLargeIcons)
		COMMAND_ID_HANDLER_EX(ID_VIEW_FITCOLUMNSTOWINDOW, OnViewFitColumns)
		COMMAND_ID_HANDLER_EX(ID_FILE_EXIT, OnClose)
		COMMAND_ID_HANDLER_EX(ID_ACCELERATOR40006, OnRefresh)
		COMMAND_HANDLER_EX(IDCANCEL, BN_CLICKED, OnCancel)
		COMMAND_HANDLER_EX(IDOK, BN_CLICKED, OnOK)
		COMMAND_HANDLER_EX(IDC_BUTTON_BROWSE, BN_CLICKED, OnBrowse)
		COMMAND_HANDLER_EX(IDC_EDITFILENAME, EN_CHANGE, OnFileNameChange)
		NOTIFY_HANDLER_EX(IDC_LISTFILES, NM_CUSTOMDRAW, OnFilesListCustomDraw)
		NOTIFY_HANDLER_EX(IDC_LISTFILES, LVN_INCREMENTALSEARCH, OnFilesIncrementalSearch)
		NOTIFY_HANDLER_EX(IDC_LISTFILES, LVN_GETDISPINFO, OnFilesGetDispInfo)
		NOTIFY_HANDLER_EX(IDC_LISTFILES, LVN_COLUMNCLICK, OnFilesListColumnClick)
		NOTIFY_HANDLER_EX(IDC_LISTFILES, NM_DBLCLK, OnFilesDoubleClick)
		NOTIFY_HANDLER_EX(IDC_EDITFILENAME, CSearchPattern::CUN_KEYDOWN, OnFileNameArrowKey)
		NOTIFY_HANDLER_EX(IDC_LISTFILES, LVN_KEYDOWN, OnFilesKeyDown)
		END_MSG_MAP()

	BEGIN_DLGRESIZE_MAP(CMainDlg)
		DLGRESIZE_CONTROL(IDC_LISTFILES, DLSZ_SIZE_X | DLSZ_SIZE_Y)
		DLGRESIZE_CONTROL(IDC_EDITFILENAME, DLSZ_SIZE_X)
		DLGRESIZE_CONTROL(IDC_STATUS_BAR, DLSZ_SIZE_X | DLSZ_MOVE_Y)
		DLGRESIZE_CONTROL(IDOK, DLSZ_MOVE_X)
		DLGRESIZE_CONTROL(IDC_BUTTON_BROWSE, DLSZ_MOVE_X)
	END_DLGRESIZE_MAP()
	enum { IDD = IDD_DIALOG1 };
};
unsigned int const CMainDlg::WM_TASKBARCREATED = RegisterWindowMessage(_T("TaskbarCreated"));

WTL::CAppModule _Module;

int _tmain(int argc, TCHAR* argv[])
{
	if (!IsDebuggerPresent())
	{
		HMODULE hKernel32 = NULL;
		GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCTSTR>(&GetSystemInfo), &hKernel32);
		typedef BOOL (WINAPI *PIsWow64Process)(IN HANDLE hProcess, OUT PBOOL Wow64Process);
		PIsWow64Process IsWow64Process = NULL;
		BOOL isWOW64 = FALSE;
		if (hKernel32 != NULL && (IsWow64Process = reinterpret_cast<PIsWow64Process>(GetProcAddress(hKernel32, "IsWow64Process"))) != NULL && IsWow64Process(GetCurrentProcess(), &isWOW64) && isWOW64)
		{
			HRSRC hRsrs = FindResourceEx(NULL, _T("BINARY"), _T("AMD64"), GetUserDefaultUILanguage());
			LPVOID pBinary = LockResource(LoadResource(NULL, hRsrs));
			if (pBinary)
			{
				std::basic_string<TCHAR> tempDir(32 * 1024, _T('\0'));
				tempDir.resize(GetTempPath(static_cast<DWORD>(tempDir.size()), &tempDir[0]));
				if (!tempDir.empty())
				{
					std::basic_string<TCHAR> fileName = tempDir + _T("SwiftSearch64_{3CACE9B1-EF40-4a3b-B5E5-3447F6A1E703}.exe");
					struct Deleter
					{
						std::basic_string<TCHAR> file;
						~Deleter() { if (!this->file.empty()) { _tunlink(this->file.c_str()); } }
					} deleter;
					bool success;
					{
						std::filebuf file;
						std::ios_base::openmode const openmode = std::ios_base::out | std::ios_base::trunc | std::ios_base::binary;
#if defined(_CPPLIB_VER)
						success = !!file.open(fileName.c_str(), openmode);
#else
						std::string fileNameChars;
						std::copy(fileName.begin(), fileName.end(), std::inserter(fileNameChars, fileNameChars.end()));
						success = !!file.open(fileNameChars.c_str(), openmode);
#endif
						if (success)
						{
							deleter.file = fileName;
							file.sputn(static_cast<char const *>(pBinary), static_cast<std::streamsize>(SizeofResource(NULL, hRsrs)));
							file.close();
						}
					}
					if (success)
					{
						STARTUPINFO si = { sizeof(si) };
						GetStartupInfo(&si);
						PROCESS_INFORMATION pi;
						HANDLE hJob = CreateJobObject(NULL, NULL);
						JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimits = { { { 0 }, { 0 }, JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE } };
						if (hJob != NULL
							&& SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jobLimits, sizeof(jobLimits))
							&& AssignProcessToJobObject(hJob, GetCurrentProcess()))
						{
							if (CreateProcess(fileName.c_str(), GetCommandLine(), NULL, NULL, FALSE, CREATE_PRESERVE_CODE_AUTHZ_LEVEL | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi))
							{
								jobLimits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
								SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jobLimits, sizeof(jobLimits));
								if (ResumeThread(pi.hThread) != -1)
								{
									WaitForSingleObject(pi.hProcess, INFINITE);
									DWORD exitCode = 0;
									GetExitCodeProcess(pi.hProcess, &exitCode);
									return exitCode;
								}
								else { TerminateProcess(pi.hProcess, GetLastError()); }
							}
						}
					}
				}
			}
			/* continue running in x86 mode... */
		}
	}
	HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, _T("Local\\SwiftSearch.{CB77990E-A78F-44dc-B382-089B01207F02}"));
	if (hEvent != NULL && GetLastError() != ERROR_ALREADY_EXISTS)
	{
		typedef long(WINAPI *PNtSetTimerResolution)(unsigned long DesiredResolution, bool SetResolution, unsigned long *CurrentResolution);
		if (PNtSetTimerResolution const NtSetTimerResolution = reinterpret_cast<PNtSetTimerResolution>(GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtSetTimerResolution")))
		{
			unsigned long prev; NtSetTimerResolution(1, true, &prev);
		}
		(void) argc;
		(void) argv;
		// pi();
		HINSTANCE const hInstance = GetModuleHandle(NULL);
		__if_exists(_Module) { _Module.Init(NULL, hInstance); }
		{
			WTL::CMessageLoop msgLoop;
			_Module.AddMessageLoop(&msgLoop);
			CMainDlg wnd(hEvent);
			wnd.Create(reinterpret_cast<HWND>(NULL), NULL);
			wnd.ShowWindow(SW_SHOWDEFAULT);
			msgLoop.Run();
			_Module.RemoveMessageLoop();
		}
		__if_exists(_Module) { _Module.Term(); }
		return 0;
	}
	else
	{
		AllowSetForegroundWindow(ASFW_ANY);
		PulseEvent(hEvent);  // PulseThread() is normally unreliable, but we don't really care here...
		return GetLastError();
	}
}

int __stdcall _tWinMain(HINSTANCE const hInstance, HINSTANCE /*hPrevInstance*/, LPTSTR /*lpCmdLine*/, int nShowCmd)
{
	(void) hInstance;
	(void) nShowCmd;
	return _tmain(__argc, __targv);
}

void pi()
{
	typedef long long Int;
	for (Int l = static_cast<Int>(1) << 23; !(l >> 28); l <<= 1)
	{
		Int num = 0, den = 0;
		clock_t const start = clock();
// #pragma omp parallel for schedule(static) reduction(+: num, den)
		for (Int x = 1; x <= l; x += 2)
		{
			Int const r = l * l - x * x;
			Int begin = 1, end = l + 1;
			while (begin != end)
			{
				Int const y = begin + (end - begin) / 2;
				if (y * y <= r) { begin = y + 1; }
				else { end = y + 0; }
			}
			num += begin / 2;
			den += (l + 1) / 2;
		}
		fprintf(
			stderr, "[%5u ms] %0.12f\n",
			static_cast<unsigned int>(clock() - start) * 1000 / CLOCKS_PER_SEC,
			(4.0 * num / den));
	}
}
