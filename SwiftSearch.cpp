#include "targetver.h"

#include <fcntl.h>
#include <intrin.h>
#include <io.h>
#include <process.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <tchar.h>
#include <time.h>
#include <wchar.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include <algorithm>
#include <cassert>
#include <map>
#include <fstream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace WTL { using std::min; using std::max; }

#include <Windows.h>
#include <Dbt.h>
#include <muiload.h>
#include <ProvExce.h>
#include <ShlObj.h>
#include <WinNLS.h>

#include <atlbase.h>
#include <atlapp.h>
#include <atlcrack.h>
#include <atlmisc.h>
extern WTL::CAppModule _Module;
#include <atlwin.h>
#include <atldlgs.h>
#include <atlframe.h>
#include <atlctrls.h>
#include <atlctrlx.h>
#include <atltheme.h>

#include "nformat.hpp"
#include "path.hpp"

#include "BackgroundWorker.hpp"
#include "ShellItemIDList.hpp"
#include "CModifiedDialogImpl.hpp"
#include "NtUserCallHook.hpp"
#include "string_matcher.hpp"

#include "resource.h"

template<class T, class Traits = std::char_traits<T>, class Ax = std::allocator<T> >
class basic_vector_based_string : public std::vector<T, Ax>
{
	typedef basic_vector_based_string this_type;
	typedef std::vector<T, Ax> base_type;
	typedef std::basic_string<T, Traits, Ax> string_type;
public:
	typedef Traits traits_type;
	typedef typename base_type::size_type size_type;
	typedef typename base_type::difference_type difference_type;
	typedef typename base_type::allocator_type allocator_type;
	typedef typename base_type::value_type const *const_pointer;
	typedef typename base_type::value_type value_type;
	typedef typename base_type::iterator iterator;
	typedef typename base_type::const_iterator const_iterator;
	using base_type::erase;
	using base_type::insert;
	static size_type const npos = ~size_type();
	this_type() : base_type() { }
	explicit this_type(const_pointer const value, size_t const n = npos) : base_type(value, value + static_cast<ptrdiff_t>(n == npos ? Traits::length(value) : n)) { }
	explicit this_type(size_type const n) : base_type(n) { }
	explicit this_type(size_type const n, value_type const &value) : base_type(n, value) { }
	explicit this_type(allocator_type const &ax) : base_type(ax) { }
	explicit this_type(size_type const n, allocator_type const &ax) : base_type(n, ax) { }
	explicit this_type(size_type const n, value_type const &value, allocator_type const &ax) : base_type(n, value, ax) { }
	void append(size_t const n, value_type const &value)
	{
		if (!n) { return; }
#if defined(_MSC_VER) && !defined(_CPPLIB_VER)
		if (this->_End - this->_Last < static_cast<ptrdiff_t>(n))
		{
			this->reserve(this->size() + n);
			for (size_t i = 0; i != n; ++i)
			{
				this->push_back(value);
			}
		}
		else
		{
			std::uninitialized_fill(this->_Last, this->_Last + static_cast<ptrdiff_t>(n), value);
			this->_Last += n;
		}
#else
		this->reserve(this->size() + n);
		for (size_t i = 0; i != n; ++i)
		{
			this->push_back(value);
		}
#endif
	}
	void append(const_pointer const begin, const_pointer const end)
	{
#if defined(_MSC_VER) && !defined(_CPPLIB_VER)
		ptrdiff_t const n = end - begin;
		if (this->_End - this->_Last < n)
		{
			this->insert(this->end(), begin, end);
		}
		else
		{
			std::uninitialized_copy(begin, end, this->_Last);
			this->_Last += n;
		}
#else
		this->insert(this->end(), begin, end);
#endif
	}
	void append(const_pointer const value, size_type n = npos) { return this->append(value, value + static_cast<ptrdiff_t>(n == npos ? Traits::length(value) : n)); }
	this_type &operator =(const_pointer const value) { this->clear(); this->append(value); return *this; }
	this_type &operator+=(base_type const &value) { if (!value.empty()) { this->append(&*value.begin(), &*(value.end() - 1) + 1); } return *this; }
	size_type find(value_type const &value, size_t const offset = 0) const { const_iterator begin = this->begin() + static_cast<difference_type>(offset), end = this->end(); size_type result = static_cast<size_type>(std::find(begin, end, value) - begin); if (result >= static_cast<size_type>(end - begin)) { result = npos; } return result; }
	const_pointer c_str() { const_pointer p; size_t const n = this->size(); if (n == 0 || this->capacity() <= n || *(&*this->begin() + static_cast<ptrdiff_t>(n)) != value_type()) { this->push_back(value_type()); p = &*this->begin(); this->pop_back(); } else { p = &*this->begin(); } return p; }
	const_pointer data() const { return this->empty() ? NULL :&*this->begin(); }
	iterator erase(size_t const pos, size_type const n = npos)
	{ return this->erase(this->begin() + static_cast<difference_type>(pos), this->begin() + static_cast<difference_type>(pos) + (n == npos ? this->size() - pos : n)); }
	iterator insert(iterator const i, const_pointer const value, size_type const n = npos)
	{ size_type const pos = static_cast<size_type>(i - this->begin()); this->insert(i, value, value + static_cast<ptrdiff_t>(n == npos ? Traits::length(value) : n)); return this->begin() + static_cast<difference_type>(pos); }
	iterator insert(size_t const pos, const_pointer const value, size_type const n = npos)
	{ return this->insert(this->begin() + static_cast<difference_type>(pos), value, n); }
	this_type operator +(base_type const &other) const { this_type result; result.reserve(this->size() + other.size()); result += *this; result += other; return result; }
#if defined(_MSC_VER) && !defined(_CPPLIB_VER)
	void push_back(value_type const &value)
	{
		if (this->_Last != this->_End)
		{
			this->allocator.construct(this->_Last, value);
			++this->_Last;
		}
		else
		{
			this->base_type::push_back(value);
		}
	}
#endif
	friend this_type operator +(const_pointer const left, base_type const &right) { size_t const nleft = Traits::length(left); this_type result; result.reserve(nleft + right.size()); result.append(left, nleft); result += right; return result; }
	template<class Ax2>
	friend std::basic_string<T, Traits, Ax2> &operator+=(std::basic_string<T, Traits, Ax2> &out, this_type const &me) { out.append(me.begin(), me.end()); return out; }
};

template<class It, class Less>
bool is_sorted_ex(It begin, It const end, Less less, bool const reversed = false)
{
	if (begin != end)
	{
		It i(begin);
		It const &left = reversed ? i : begin, &right = reversed ? begin : i;
		++i;
		while (i != end)
		{
			if (less(*right, *left))
			{
				return false;
			}
			begin = i;
			++i;
		}
	}
	return true;
}

template<class ValueType, class KeyComp>
struct stable_sort_by_key_comparator : KeyComp
{
	explicit stable_sort_by_key_comparator(KeyComp const &comp = KeyComp()) : KeyComp(comp) { }
	typedef ValueType value_type;
	bool operator()(value_type const &a, value_type const &b) const
	{
		return this->KeyComp::operator()(a.first, b.first) || (!this->KeyComp::operator()(b.first, a.first) && (a.second < b.second));
	}
};

template<class It, class Key, class Swapper>
void stable_sort_by_key(It begin, It end, Key key, Swapper swapper)
{
	typedef typename std::iterator_traits<It>::difference_type Diff;
	typedef std::less<typename Key::result_type> KeyComp;
	typedef std::vector<std::pair<typename Key::result_type, Diff> > Keys;
	Keys keys;
	Diff const n = std::distance(begin, end);
	keys.reserve(static_cast<typename Keys::size_type>(n));
	{
		Diff j = 0;
		for (It i = begin; i != end; ++i)
		{ keys.push_back(typename Keys::value_type(key(*i), j++)); }
	}
	std::stable_sort(keys.begin(), keys.end(), stable_sort_by_key_comparator<typename Keys::value_type, KeyComp>());
	for (Diff i = 0; i != n; ++i)
	{
		for (Diff j = i; ; )
		{
			using std::swap;
			swap(j, keys[j].second);
			swapper(*(begin + j), *(begin + j));
			if (j == i) { break; }
			using std::iter_swap;
			swapper(*(begin + j), *(begin + keys[j].second));
		}
	}
}

class DynamicAllocator
{
protected:
	~DynamicAllocator() { }
public:
	typedef void *pointer;
	typedef void const *const_pointer;
	virtual void deallocate(pointer const p, size_t const n) = 0;
	virtual pointer allocate(size_t const n, pointer const hint = NULL) = 0;
	virtual pointer reallocate(pointer const p, size_t const n, bool const allow_movement) = 0;
};

template<class T>
class dynamic_allocator : private std::allocator<T>
{
	typedef dynamic_allocator this_type;
	typedef std::allocator<T> base_type;
	typedef DynamicAllocator dynamic_allocator_type;
	dynamic_allocator_type *_alloc;  /* Keep this IMMUTABLE, since otherwise we need to share state via heap allocation */
public:
	typedef typename base_type::value_type value_type;
	typedef typename base_type::const_pointer const_pointer;
	typedef typename base_type::const_reference const_reference;
	typedef typename base_type::difference_type difference_type;
	typedef typename base_type::pointer pointer;
	typedef typename base_type::reference reference;
	typedef typename base_type::size_type size_type;
	dynamic_allocator() : base_type(), _alloc() { }
	explicit dynamic_allocator(dynamic_allocator_type *const alloc) : base_type(), _alloc(alloc) { }
	template<class U>
	dynamic_allocator(dynamic_allocator<U> const &other) : base_type(other.base()), _alloc(other.dynamic_alloc()) { }
	template<class U>
	struct rebind { typedef dynamic_allocator<U> other; };
	dynamic_allocator_type *dynamic_alloc() const { return this->_alloc; }
	base_type &base() { return static_cast<base_type &>(*this); }
	base_type const &base() const { return static_cast<base_type const &>(*this); }
	pointer allocate(size_type const n, void *const p = NULL) { pointer r; if (this->_alloc) { r = static_cast<pointer>(this->_alloc->allocate(n * sizeof(value_type), static_cast<typename dynamic_allocator_type::pointer>(p))); } else { r = this->base_type::allocate(n, p); } return r; }
	void deallocate(pointer const p, size_type const n) { if (this->_alloc) { this->_alloc->deallocate(p, n * sizeof(value_type)); } else { this->base_type::deallocate(p, n); } }
	pointer reallocate(pointer const p, size_t const n, bool const allow_movement) { if (this->_alloc) { return static_cast<pointer>(this->_alloc->reallocate(p, n * sizeof(value_type), allow_movement)); } else { return NULL; } }
	bool operator==(this_type const &other) const { return static_cast<base_type const &>(*this) == static_cast<base_type const &>(other); }
	template<class U>
	this_type &operator =(dynamic_allocator<U> const &other) { return static_cast<this_type &>(this->base_type::operator =(other.base())); }
	using base_type::construct;
	using base_type::destroy;
	using base_type::address;
	using base_type::max_size;
};

class SingleMovableGlobalAllocator : public DynamicAllocator
{
	SingleMovableGlobalAllocator(SingleMovableGlobalAllocator const &);
	SingleMovableGlobalAllocator &operator =(SingleMovableGlobalAllocator const &);
	HGLOBAL _recycled;
public:
	~SingleMovableGlobalAllocator() { if (this->_recycled) { GlobalFree(this->_recycled); this->_recycled = NULL; } }
	SingleMovableGlobalAllocator() : _recycled() { }
	void deallocate(pointer const p, size_t const n)
	{
		if (n)
		{
			if (HGLOBAL const h = GlobalHandle(p))
			{
				GlobalUnlock(h);
				if (!this->_recycled)
				{
					this->_recycled = h;
				}
				else
				{
					GlobalFree(h);
				}
			}
		}
	}
	pointer allocate(size_t const n, pointer const hint = NULL)
	{
		HGLOBAL mem = NULL;
		if (n)
		{
			if (this->_recycled)
			{
				mem = GlobalReAlloc(this->_recycled, n, GMEM_MOVEABLE);
				if (mem) { this->_recycled = NULL; }
			}
			if (!mem) { mem = GlobalAlloc(GMEM_MOVEABLE, n); }
		}
		pointer p = NULL;
		if (mem)
		{
			p = GlobalLock(mem);
		}
		return p;
	}
	pointer reallocate(pointer const p, size_t const n, bool const allow_movement)
	{
		pointer result = NULL;
		if (HGLOBAL h = GlobalHandle(p))
		{
			if (allow_movement || GlobalUnlock(h))
			{
				if (HGLOBAL const r = GlobalReAlloc(h, n, GMEM_MOVEABLE))
				{
					result = GlobalLock(r);
				}
			}
		}
		return result;
	}
};

namespace std { typedef basic_string<TCHAR> tstring; typedef basic_vector_based_string<TCHAR, std::char_traits<TCHAR>, dynamic_allocator<TCHAR> > tvstring; }
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
	template<class It, class T, class Traits, class Ax>
	back_insert_iterator<basic_vector_based_string<T, Traits, Ax> > copy(It begin, It end, back_insert_iterator<basic_vector_based_string<T, Traits, Ax> > out)
	{
		typedef back_insert_iterator<basic_vector_based_string<T, Traits, Ax> > Base;
		struct Derived : Base { using Base::container; };
		typename Base::container_type &container = *static_cast<Derived &>(out).container;
		container.append(begin, end);
		return out;
	}
}

namespace stdext
{
	template<class T> struct remove_const          { typedef T type; };
	template<class T> struct remove_const<const T> { typedef T type; };

	template<class T> struct remove_volatile             { typedef T type; };
	template<class T> struct remove_volatile<volatile T> { typedef T type; };

	template<class T>
	struct remove_cv { typedef typename remove_volatile<typename remove_const<T>::type>::type type; };
}

struct File
{
	typedef int handle_type;
	handle_type f;
	~File() { if (f) { _close(f); } }
	operator handle_type &() { return this->f; }
	operator handle_type () const { return this->f; }
	handle_type *operator &() { return &this->f; }
};

struct Hook_init { template<class Hook> Hook_init(Hook &hook, FARPROC const proc) { hook.init(proc); } };

#define X(F) static Hook_init const hook_##F##_init(hook_##F, GetProcAddress(GetModuleHandle(TEXT("win32u.dll")), #F))
HOOK_DEFINE(HANDLE __stdcall, NtUserGetProp, (HWND hWnd, ATOM PropId))
{
	return base_or_thread_like(hook)(hWnd, PropId);
}
X(NtUserGetProp);

HOOK_DEFINE(BOOL __stdcall, NtUserSetProp, (HWND hWnd, ATOM PropId, HANDLE value))
{
	return base_or_thread_like(hook)(hWnd, PropId, value);
}
X(NtUserSetProp);
#undef X

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

template<size_t N>
int safe_stprintf(TCHAR (&s)[N], TCHAR const *const format, ...)
{
	int result;
	va_list args;
	va_start(args, format);
	result = _vsntprintf(s, N - 1, format, args);
	va_end(args);
	if (result == N - 1) { s[result] = _T('\0'); }
	return result;
}

bool is_ascii(wchar_t const *const s, size_t const n)
{
	bool result = true;
	for (size_t i = 0; i != n; ++i)
	{
		wchar_t const ch = s[i];
		result &= (SCHAR_MIN <= ch) & (ch <= SCHAR_MAX);
	}
	return result;
}

static void append_directional(std::tvstring &str, TCHAR const sz[], size_t const cch, int const ascii_mode /* -1 = decompress ASCII, 0 = no change, +1 = compress ASCII */, bool const reverse = false)
{
	typedef std::tvstring Str;
	size_t const cch_in_str = ascii_mode > 0 ? (cch + 1) / 2 : cch;
	size_t const n = str.size();
#if defined(_MSC_VER) && !defined(_CPPLIB_VER)
	struct Derived : Str { using Str::_First; using Str::_Last; using Str::_End; using Str::allocator; };
	Derived &derived = static_cast<Derived &>(str);
#endif
	if (n + cch_in_str > str.capacity())
	{
#if defined(_MSC_VER) && !defined(_CPPLIB_VER)
		dynamic_allocator<TCHAR> &alloc /* ensure correct type of allocator! */ = derived.allocator;
		size_t const min_capacity = str.capacity() + str.capacity() / 2;
		size_t new_capacity = n + cch_in_str;
		if (new_capacity < min_capacity) { new_capacity = min_capacity; }
		if (TCHAR *const p = alloc.reallocate(derived._First, new_capacity, true /* TCHAR is movable */))
		{
			derived._First = p;
			derived._Last = derived._First + static_cast<ptrdiff_t>(n);
			derived._End = derived._First + static_cast<ptrdiff_t>(new_capacity);
		}
#endif
		str.reserve(n + n / 2 + cch_in_str * 2);
	}
#if defined(_MSC_VER) && !defined(_CPPLIB_VER)
	// we have enough capacity, so just extend
	derived._Last += static_cast<ptrdiff_t>(cch_in_str);
#else
	str.resize(n + cch_in_str);
#endif
	if (cch)
	{
		TCHAR *const o = &str[n];
		if (reverse)
		{
			if (ascii_mode < 0)
			{ std::reverse_copy(static_cast<char const *>(static_cast<void const *>(sz)), static_cast<char const *>(static_cast<void const *>(sz)) + static_cast<ptrdiff_t>(cch), o); }
			else if (ascii_mode > 0)
			{
				for (size_t i = 0; i != cch; ++i)
				{ static_cast<char *>(static_cast<void *>(o))[i] = static_cast<char>(sz[cch - 1 - i]); }
			}
			else
			{ std::reverse_copy(sz, sz + static_cast<ptrdiff_t>(cch), o); }
		}
		else
		{
			if (ascii_mode < 0)
			{ std::copy(static_cast<char const *>(static_cast<void const *>(sz)), static_cast<char const *>(static_cast<void const *>(sz)) + static_cast<ptrdiff_t>(cch), o); }
			else if (ascii_mode > 0)
			{
				for (size_t i = 0; i != cch; ++i)
				{ static_cast<char *>(static_cast<void *>(o))[i] = static_cast<char>(sz[i]); }
			}
			else
			{ std::copy(sz, sz + static_cast<ptrdiff_t>(cch), o); }
		}
	}
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
	struct SYSTEM_TIMEOFDAY_INFORMATION { LARGE_INTEGER BootTime; LARGE_INTEGER CurrentTime; LARGE_INTEGER TimeZoneBias; ULONG TimeZoneId; ULONG Reserved; };
	struct TIME_FIELDS { short Year; short Month; short Day; short Hour; short Minute; short Second; short Milliseconds; short Weekday; };

	template<class T> struct identity { typedef T type; };
	typedef long NTSTATUS;
	enum _SYSTEM_INFORMATION_CLASS { };
#define X(F, T) identity<T>::type &F = *reinterpret_cast<identity<T>::type *const &>(static_cast<FARPROC const &>(GetProcAddress(GetModuleHandle(_T("ntdll.dll")), #F)))
	X(NtOpenFile, NTSTATUS NTAPI(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN OBJECT_ATTRIBUTES *ObjectAttributes, OUT IO_STATUS_BLOCK *IoStatusBlock, IN ULONG ShareAccess, IN ULONG OpenOptions));
	X(NtQueryVolumeInformationFile, NTSTATUS NTAPI(HANDLE FileHandle, IO_STATUS_BLOCK *IoStatusBlock, PVOID FsInformation, unsigned long Length, unsigned long FsInformationClass));
	X(NtQueryInformationFile, NTSTATUS NTAPI(IN HANDLE FileHandle, OUT IO_STATUS_BLOCK *IoStatusBlock, OUT PVOID FileInformation, IN ULONG Length, IN unsigned long FileInformationClass));
	X(NtSetInformationFile, NTSTATUS NTAPI(IN HANDLE FileHandle, OUT IO_STATUS_BLOCK *IoStatusBlock, IN PVOID FileInformation, IN ULONG Length, IN unsigned long FileInformationClass));
	X(RtlInitUnicodeString, VOID NTAPI(UNICODE_STRING *DestinationString, PCWSTR SourceString));
	X(RtlNtStatusToDosError, unsigned long NTAPI(IN NTSTATUS NtStatus));
	X(RtlSystemTimeToLocalTime, NTSTATUS NTAPI(IN LARGE_INTEGER const *SystemTime, OUT PLARGE_INTEGER LocalTime));
	X(NtQuerySystemInformation, NTSTATUS NTAPI(IN enum _SYSTEM_INFORMATION_CLASS SystemInfoClass, OUT PVOID SystemInfoBuffer, IN ULONG SystemInfoBufferSize, OUT PULONG BytesReturned OPTIONAL));
	X(RtlTimeToTimeFields, VOID NTAPI(LARGE_INTEGER *Time, TIME_FIELDS *TimeFields));
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
		unsigned short Flags;  // 0x0001 = Compressed, 0x4000 = Encrypted, 0x8000 = Sparse
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
				long long LowestVCN;
				long long HighestVCN;
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

void remove_path_stream_and_trailing_sep(std::tvstring &path)
{
	size_t ifirstsep = 0;
	while (ifirstsep < path.size())
	{
		if (isdirsep(path[ifirstsep]))
		{
			break;
		}
		++ifirstsep;
	}
	while (!path.empty() && isdirsep(*(path.end() - 1)))
	{
		if (path.size() <= ifirstsep + 1)
		{
			break;
		}
		path.erase(path.end() - 1);
	}
	for (size_t i = path.size(); i != 0 && ((void)--i, true); )
	{
		if (path[i] == _T(':'))
		{
			path.erase(path.begin() + static_cast<ptrdiff_t>(i), path.end());
		}
		else if (isdirsep(path[i]))
		{
			break;
		}
	}
	while (!path.empty() && isdirsep(*(path.end() - 1)))
	{
		if (path.size() <= ifirstsep + 1)
		{
			break;
		}
		path.erase(path.end() - 1);
	}
	if (!path.empty() && *(path.end() - 1) == _T('.') && (path.size() == 1 || isdirsep(*(path.end() - 2))))
	{
		path.erase(path.end() - 1);
	}
}

std::tvstring NormalizePath(std::tvstring const &path)
{
	std::tvstring result;
	bool wasSep = false;
	bool isCurrentlyOnPrefix = true;
	for (size_t i = 0; i < path.size(); i++)
	{
		TCHAR const &c = path[i];
		isCurrentlyOnPrefix &= isdirsep(c);
		if (isCurrentlyOnPrefix || !wasSep || !isdirsep(c)) { result.push_back(c); }
		wasSep = isdirsep(c);
	}
	if (!isrooted(result.begin(), result.end()))
	{
		std::tvstring currentDir(32 * 1024, _T('\0'));
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

void CheckAndThrow(int const success) { if (!success) { unsigned long const last_error = GetLastError(); RaiseException(last_error, 0, 0, NULL); } }

LPTSTR GetAnyErrorText(DWORD errorCode, va_list* pArgList = NULL)
{
	static TCHAR buffer[1 << 15];
	ZeroMemory(buffer, sizeof(buffer));
	if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | (pArgList == NULL ? FORMAT_MESSAGE_IGNORE_INSERTS : 0), NULL, errorCode, 0, buffer, sizeof(buffer) / sizeof(*buffer), pArgList))
	{
		if (!FormatMessage(FORMAT_MESSAGE_FROM_HMODULE | (pArgList == NULL ? FORMAT_MESSAGE_IGNORE_INSERTS : 0), GetModuleHandle(_T("NTDLL.dll")), errorCode, 0, buffer, sizeof(buffer) / sizeof(*buffer), pArgList))
		{ safe_stprintf(buffer, _T("%#lx"), errorCode); }
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
	operator void *() const volatile { return this->value; }
	operator void *() const { return this->value; }
	void swap(Handle &other) { using std::swap; swap(this->value, other.value); }
	friend void swap(Handle &a, Handle &b) { return a.swap(b); }
};

class IoPriority
{
	uintptr_t _volume;
	winnt::IO_PRIORITY_HINT _old;
	IoPriority &operator =(IoPriority const &);
public:
	static winnt::IO_PRIORITY_HINT query(uintptr_t const file)
	{
		winnt::FILE_IO_PRIORITY_HINT_INFORMATION old = { winnt::IoPriorityNormal };
		winnt::IO_STATUS_BLOCK iosb;
		winnt::NtQueryInformationFile(reinterpret_cast<HANDLE>(file), &iosb, &old, sizeof(old), 43);
		return old.PriorityHint;
	}
	static void set(uintptr_t const volume, winnt::IO_PRIORITY_HINT const value)
	{
		if (value != winnt::MaxIoPriorityTypes)
		{
			winnt::IO_STATUS_BLOCK iosb;
			winnt::FILE_IO_PRIORITY_HINT_INFORMATION io_priority = { value };
			winnt::NTSTATUS const status = winnt::NtSetInformationFile(reinterpret_cast<HANDLE>(volume), &iosb, &io_priority, sizeof(io_priority), 43);
			if (status != 0 && status != 0xC0000003 /*STATUS_INVALID_INFO_CLASS*/ && status != 0xC0000008 /* STATUS_INVALID_HANDLE */ && status != 0xC0000024 /* STATUS_OBJECT_TYPE_MISMATCH */)
			{
				unsigned long const error = winnt::RtlNtStatusToDosError(status);
				if (error) { SetLastError(error); CheckAndThrow(!error); }
			}
		}
	}
	uintptr_t volume() const { return this->_volume; }
	IoPriority() : _volume(), _old() { }
	IoPriority(IoPriority const &other) : _volume(other._volume), _old() { this->_old = winnt::MaxIoPriorityTypes; }
	explicit IoPriority(uintptr_t const volume, winnt::IO_PRIORITY_HINT const priority) : _volume(volume), _old(query(volume)) { set(volume, priority); }
	~IoPriority() { if (this->_volume) { set(this->_volume, this->_old); } }
	void swap(IoPriority &other) { using std::swap; swap(this->_volume, other._volume); swap(this->_old, other._old); }
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
	void resize(size_type const size, value_type const &fill)
	{
		typename base_type::size_type const current_size = this->base_type::size();
		if (size > current_size) { this->_reserve(size - current_size); }
		return this->base_type::resize(size, fill);
	}
	void resize(size_type const size)
	{
		typename base_type::size_type const current_size = this->base_type::size();
		if (size > current_size) { this->_reserve(size - current_size); }
		return this->base_type::resize(size);
	}
};

unsigned int get_cluster_size(void *const volume)
{
	winnt::IO_STATUS_BLOCK iosb;
	winnt::FILE_FS_SIZE_INFORMATION info = {};
	if (winnt::NtQueryVolumeInformationFile(volume, &iosb, &info, sizeof(info), 3))
	{ SetLastError(ERROR_INVALID_FUNCTION), CheckAndThrow(false); }
	return info.BytesPerSector * info.SectorsPerAllocationUnit;
}

std::vector<std::pair<unsigned long long, long long> > get_mft_retrieval_pointers(void *const root_dir, TCHAR const path[], long long *const size, long long const mft_start_lcn, unsigned int const file_record_size)
{
	(void) mft_start_lcn;
	(void) file_record_size;
	typedef std::vector<std::pair<unsigned long long, long long> > Result;
	Result result;
	Handle handle;
	if (path)
	{
		size_t const cch = path ? std::char_traits<TCHAR>::length(path) : 0;
		winnt::UNICODE_STRING us = { static_cast<unsigned short>(cch * sizeof(*path)), static_cast<unsigned short>(cch * sizeof(*path)), const_cast<TCHAR *>(path) };
		winnt::OBJECT_ATTRIBUTES oa = { sizeof(oa), root_dir, &us };
		winnt::IO_STATUS_BLOCK iosb;
		unsigned long const error = winnt::RtlNtStatusToDosError(winnt::NtOpenFile(&handle.value, FILE_READ_ATTRIBUTES, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0x00200000 /* FILE_OPEN_REPARSE_POINT */));
		if (error == ERROR_FILE_NOT_FOUND) { handle.value = NULL; /* do nothing */ }
		else if (error) { SetLastError(error); CheckAndThrow(!error); }
	}
	void *const file = path ? handle : root_dir;
	if (file)
	{
		result.resize(1 + (sizeof(RETRIEVAL_POINTERS_BUFFER) - 1) / sizeof(Result::value_type));
		STARTING_VCN_INPUT_BUFFER input = {};
		BOOL success;
		for (unsigned long nr; !(success = DeviceIoControl(file, FSCTL_GET_RETRIEVAL_POINTERS, &input, sizeof(input), &*result.begin(), static_cast<unsigned long>(result.size()) * sizeof(*result.begin()), &nr, NULL), success) && GetLastError() == ERROR_MORE_DATA;)
		{
			size_t const n = result.size();
			Result(/* free old memory */).swap(result);
			Result(n * 2).swap(result);
		}
		CheckAndThrow(success);
		if (size)
		{
			LARGE_INTEGER large_size;
			CheckAndThrow(GetFileSizeEx(file, &large_size));
			*size = large_size.QuadPart;
		}
		result.erase(result.begin() + 1 + reinterpret_cast<unsigned long const &>(*result.begin()), result.end());
		result.erase(result.begin(), result.begin() + 1);
	}
	return result;
}

template<class From, class To> struct propagate_const { typedef To type; };
template<class From, class To> struct propagate_const<From const, To> : propagate_const<From, To const> { };
template<class From, class To> struct propagate_const<From &, To> : propagate_const<From, To> { };

namespace atomic_namespace
{
	enum memory_order
	{
		memory_order_relaxed,
		memory_order_consume,
		memory_order_acquire,
		memory_order_release,
		memory_order_acq_rel,
		memory_order_seq_cst
	};
	template<class T>
	class atomic
	{
		mutex _mutex;
		typedef T storage_type;
		typedef T value_type;
		storage_type value;
	public:
		atomic() { }
		explicit atomic(value_type const &value) : value(value) { }
		value_type exchange(value_type value, memory_order const order = memory_order_seq_cst) volatile { (void) order; lock_guard<mutex> const lock(const_cast<mutex &>(this->_mutex)); using std::swap; swap(const_cast<storage_type &>(this->value), value); return value; }
		value_type load(memory_order const order = memory_order_seq_cst) const volatile { (void) order; lock_guard<mutex> const lock(const_cast<mutex &>(this->_mutex)); return const_cast<storage_type &>(this->value); }
		value_type store(value_type const &value, memory_order const order = memory_order_seq_cst) volatile { (void) order; lock_guard<mutex> const lock(const_cast<mutex &>(this->_mutex)); const_cast<storage_type &>(this->value) = value; }
		value_type fetch_add(value_type const &value, memory_order const order = memory_order_seq_cst) volatile { (void) order; lock_guard<mutex> const lock(const_cast<mutex &>(this->_mutex)); value_type old = const_cast<storage_type &>(this->value); const_cast<storage_type &>(this->value) += value; return old; }
		value_type fetch_sub(value_type const &value, memory_order const order = memory_order_seq_cst) volatile { (void) order; lock_guard<mutex> const lock(const_cast<mutex &>(this->_mutex)); value_type old = const_cast<storage_type &>(this->value); const_cast<storage_type &>(this->value) -= value; return old; }
	};
	template<>
	class atomic<bool>
	{
		typedef char storage_type;
		typedef bool value_type;
		storage_type value;
	public:
		atomic() { }
		explicit atomic(value_type const value) : value(value) { }
		value_type exchange(value_type const value, memory_order const order = memory_order_seq_cst) volatile { (void) order; return !!_InterlockedExchange8(const_cast<storage_type *>(&this->value), static_cast<storage_type>(value)); }
		value_type load(memory_order const order = memory_order_seq_cst) const volatile { (void) order; return !!_InterlockedOr8(const_cast<storage_type *>(&this->value), storage_type()); }
		value_type store(value_type const value, memory_order const order = memory_order_seq_cst) volatile { (void) order; return !!_InterlockedExchange8(const_cast<storage_type *>(&this->value), static_cast<storage_type>(value)); }
	};
	template<>
	class atomic<unsigned int>
	{
		typedef long storage_type;
		typedef unsigned int value_type;
		storage_type value;
	public:
		atomic() { }
		explicit atomic(value_type const value) : value(value) { }
		value_type exchange(value_type const value, memory_order const order = memory_order_seq_cst) volatile { (void) order; return static_cast<value_type>(_InterlockedExchange(&this->value, static_cast<storage_type>(value))); }
		value_type load(memory_order const order = memory_order_seq_cst) const volatile { (void) order; return static_cast<value_type>(_InterlockedOr(const_cast<storage_type volatile *>(&this->value), storage_type())); }
		value_type store(value_type const value, memory_order const order = memory_order_seq_cst) volatile { (void) order; return static_cast<value_type>(_InterlockedExchange(&this->value, static_cast<storage_type>(value))); }
		value_type fetch_add(value_type const value, memory_order const order = memory_order_seq_cst) volatile { (void) order; return static_cast<value_type>(_InterlockedExchangeAdd(&this->value, static_cast<storage_type>(value))); }
		value_type fetch_sub(value_type const value, memory_order const order = memory_order_seq_cst) volatile { return this->fetch_add(value_type() - value, order); }
	};

	template<>
	class atomic<unsigned long long>
	{
		typedef long long storage_type;
		typedef unsigned long long value_type;
		storage_type value;
#ifdef _M_IX86
		static storage_type _InterlockedOr64(storage_type volatile *const result, storage_type const value) { storage_type prev, curr; _ReadWriteBarrier(); do { prev = *result; curr = prev | value; } while (prev != _InterlockedCompareExchange64(result, curr, prev)); _ReadWriteBarrier(); return prev; }
		static storage_type _InterlockedExchange64(storage_type volatile *const result, storage_type const value) { storage_type prev; _ReadWriteBarrier(); do { prev = *result; } while (prev != _InterlockedCompareExchange64(result, value, prev)); _ReadWriteBarrier();  return (prev); }
		static storage_type _InterlockedExchangeAdd64(storage_type volatile *const result, storage_type const value) { storage_type prev, curr; _ReadWriteBarrier(); do { prev = *result; curr = prev + value; } while (prev != _InterlockedCompareExchange64(result, curr, prev)); _ReadWriteBarrier(); return prev; }
#endif
	public:
		atomic() { }
		explicit atomic(value_type const value) : value(value) { }
		value_type exchange(value_type const value, memory_order const order = memory_order_seq_cst) volatile { }
		value_type load(memory_order const order = memory_order_seq_cst) const volatile { (void) order; return static_cast<value_type>(_InterlockedOr64(const_cast<storage_type volatile *>(&this->value), storage_type())); }
		value_type store(value_type const value, memory_order const order = memory_order_seq_cst) volatile { (void) order; return static_cast<value_type>(_InterlockedExchange64(&this->value, static_cast<storage_type>(value))); }
		value_type fetch_add(value_type const value, memory_order const order = memory_order_seq_cst) volatile { (void) order; return static_cast<value_type>(_InterlockedExchangeAdd64(&this->value, static_cast<storage_type>(value))); }
		value_type fetch_sub(value_type const value, memory_order const order = memory_order_seq_cst) volatile { return this->fetch_add(value_type() - value, order); }
	};
}

template<class T>
struct intrusive_ptr
{
	typedef T value_type, element_type;
	typedef intrusive_ptr this_type;
	typedef value_type const *const_pointer;
	typedef value_type *pointer;
	pointer p;
	~intrusive_ptr() { if (this->p) { intrusive_ptr_release(this->p); } }
	void ref() { if (this->p) { intrusive_ptr_add_ref(this->p); } }
	pointer detach() { pointer p_ = this->p; this->p = NULL; return p_; }
	intrusive_ptr(pointer const p = NULL, bool const addref = true) : p(p) { if (addref) { this->ref(); } }
	template<class U> intrusive_ptr(intrusive_ptr<U> const &p, bool const addref = true) : p(p.get()) { if (addref) { this->ref(); } }
	intrusive_ptr(this_type const &other) : p(other.p) { this->ref(); }
	this_type &operator =(this_type other) { return other.swap(*this), *this; }
	pointer operator->() const { return this->p; }
	pointer get() const { return this->p; }
	void reset(pointer const p = NULL, bool const add_ref = true) { this_type(p, add_ref).swap(*this); }
	operator pointer () { return this->p; }
	operator const_pointer() const { return this->p; }
	void swap(this_type &other) { using std::swap; swap(this->p, other.p); }
	friend void swap(this_type &a, this_type &b) { return a.swap(b); }
	bool operator==(const_pointer const p) const { return this->p == p; } friend bool operator==(const_pointer const p, this_type const &me) { return p == me.get(); }
	bool operator!=(const_pointer const p) const { return this->p != p; } friend bool operator!=(const_pointer const p, this_type const &me) { return p != me.get(); }
	bool operator<=(const_pointer const p) const { return this->p <= p; } friend bool operator<=(const_pointer const p, this_type const &me) { return p <= me.get(); }
	bool operator>=(const_pointer const p) const { return this->p >= p; } friend bool operator>=(const_pointer const p, this_type const &me) { return p >= me.get(); }
	bool operator< (const_pointer const p) const { return this->p <  p; } friend bool operator< (const_pointer const p, this_type const &me) { return p <  me.get(); }
	bool operator> (const_pointer const p) const { return this->p >  p; } friend bool operator> (const_pointer const p, this_type const &me) { return p >  me.get(); }
};

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

static struct negative_one
{
	template<class T>
	operator T() const { return static_cast<T>(~T()); }
} const negative_one;

template<class T>
struct value_initialized
{
	typedef value_initialized this_type, type;
	T value;
	value_initialized() : value() { }
	value_initialized(T const &value) : value(value) { }
	operator T &() { return this->value; }
	operator T const &() const { return this->value; }
	operator T volatile &() volatile { return this->value; }
	operator T const volatile &() const volatile { return this->value; }
	T *operator &() { return &this->value; }
	T const *operator &() const { return &this->value; }
	T volatile *operator &() volatile { return &this->value; }
	T const volatile *operator &() const volatile { return &this->value; }
};

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

template<class T, class Ax = std::allocator<T> >
class vector_with_fast_size : std::vector<T, Ax>
{
	typedef std::vector<T, Ax> base_type;
	typename base_type::size_type _size;
public:
	vector_with_fast_size() : _size() { }
	typedef typename base_type::const_iterator const_iterator;
	typedef typename base_type::iterator iterator;
	typedef typename base_type::size_type size_type;
	typedef typename base_type::value_type value_type;
	using base_type::at;
	using base_type::back;
	using base_type::begin;
	using base_type::capacity;
	using base_type::empty;
	using base_type::end;
	using base_type::front;
	using base_type::reserve;
	using base_type::operator[];
	size_type size() const
	{
		return this->_size;
	}
	void resize(size_type const size)
	{
		this->base_type::resize(size);
		this->_size = size;
	}
	void resize(size_type const size, value_type const &default_value)
	{
		this->base_type::resize(size, default_value);
		this->_size = size;
	}
	void push_back(value_type const &value)
	{
		this->base_type::push_back(value);
		++this->_size;
	}
};

struct Speed : std::pair<unsigned long long, clock_t>
{
	Speed() { }
	Speed(first_type const &first, second_type const &second) : std::pair<first_type, second_type>(first, second) { }
	Speed &operator+=(Speed const &other) { this->first += other.first; this->second += other.second; return *this; }
};

template<class T> struct remove_volatile             { typedef T type; };
template<class T> struct remove_volatile<T volatile> { typedef T type; };

template<class T>
struct mutable_
{
	mutable T value;
};

template<class T>
class lock_ptr : lock_guard<mutex>
{
	typedef lock_ptr this_type;
	T *me;
	lock_ptr(this_type const &);
	this_type &operator =(this_type const &);
public:
	~lock_ptr() { }
	lock_ptr(T volatile *const me, bool const do_lock = true) : lock_guard<mutex_type>(do_lock && me ? &me->get_mutex() : NULL), me(const_cast<T *>(me)) { }
	lock_ptr(T *const me, bool const do_lock = false) : lock_guard<mutex_type>(do_lock && me ? me->get_mutex() : NULL), me(me) { }
	lock_ptr() : lock_guard<mutex_type>(), me() { }
	T *operator->() const { return me; }
	T &operator *() const { return *me; }
	void swap(this_type &other)
	{
		using std::swap;
		swap(static_cast<lock_guard<mutex_type> &>(*this), static_cast<lock_guard<mutex_type> &>(other));
		swap(this->me, other.me);
	}
	this_type &init(T volatile *const me) { this_type(me).swap(*this); return *this; }
	this_type &init(T *const me) { this_type(me).swap(*this); return *this; }
};

template<class T>
lock_ptr<typename remove_volatile<T>::type> &lock(T *const value, mutable_<lock_ptr<typename remove_volatile<T>::type> > const &holder = mutable_<lock_ptr<typename remove_volatile<T>::type> >())
{
	return holder.value.init(value);
}

template<class T>
lock_ptr<typename remove_volatile<T>::type> &lock(intrusive_ptr<T> const &value, mutable_<lock_ptr<typename remove_volatile<T>::type> > const &holder = mutable_<lock_ptr<typename remove_volatile<T>::type> >())
{
	return lock<T>(value.get(), holder);
}

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
		unsigned long long
			created,
			written,
			accessed : 0x40 - 6,
			is_system : 1,
			is_directory : 1,
			is_sparse : 1,
			is_compressed : 1,
			is_encrypted : 1,
			is_reparse : 1;

		unsigned long attributes() const
		{
			return (this->is_system ? FILE_ATTRIBUTE_SYSTEM : 0U) |
				(this->is_directory ? FILE_ATTRIBUTE_DIRECTORY : 0U) |
				(this->is_sparse ? FILE_ATTRIBUTE_SPARSE_FILE : 0U) |
				(this->is_compressed ? FILE_ATTRIBUTE_COMPRESSED : 0U) |
				(this->is_encrypted ? FILE_ATTRIBUTE_ENCRYPTED : 0U) |
				(this->is_reparse ? FILE_ATTRIBUTE_REPARSE_POINT : 0U);
		}

		void attributes(unsigned long const value)
		{
			this->is_system = !!(value & FILE_ATTRIBUTE_SYSTEM);
			this->is_directory = !!(value & FILE_ATTRIBUTE_DIRECTORY);
			this->is_sparse = !!(value & FILE_ATTRIBUTE_SPARSE_FILE);
			this->is_compressed = !!(value & FILE_ATTRIBUTE_COMPRESSED);
			this->is_encrypted = !!(value & FILE_ATTRIBUTE_ENCRYPTED);
			this->is_reparse = !!(value & FILE_ATTRIBUTE_REPARSE_POINT);
		}
	};
	struct SizeInfo
	{
		file_size_type length, allocated, bulkiness;
		value_initialized<unsigned int>::type treesize;
	};
	friend struct std::is_scalar<StandardInfo>;
	struct NameInfo
	{
		small_t<size_t>::type _offset;
		bool ascii() const { return !!(this->_offset & 1U); }
		void ascii(bool const value) { this->_offset = static_cast<small_t<size_t>::type>((this->_offset & static_cast<small_t<size_t>::type>(~static_cast<small_t<size_t>::type>(1U))) | (value ? 1U : small_t<size_t>::type())); }
		small_t<size_t>::type offset() const { small_t<size_t>::type result = this->_offset >> 1; if (result == (static_cast<small_t<size_t>::type>(negative_one) >> 1)) { result = static_cast<small_t<size_t>::type>(negative_one); } return result; }
		void offset(small_t<size_t>::type const value) { this->_offset = (value << 1) | (this->_offset & 1U); }
		unsigned char length;
	};
	friend struct std::is_scalar<NameInfo>;
	struct LinkInfo
	{
		LinkInfo() : next_entry(negative_one) { this->name.offset(negative_one); }
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
	typedef vector_with_fast_size<LinkInfo> LinkInfos;
	typedef vector_with_fast_size<StreamInfo> StreamInfos;
	struct Record;
	typedef vector_with_fast_size<Record> Records;
	typedef std::vector<unsigned int> RecordsLookup;
	struct ChildInfo
	{
		ChildInfo() : next_entry(negative_one), record_number(negative_one), name_index(negative_one) { }
		typedef small_t<size_t>::type next_entry_type; next_entry_type next_entry;
		small_t<Records::size_type>::type record_number;
		unsigned short name_index;
	};
	typedef vector_with_fast_size<ChildInfo> ChildInfos;
	struct Record
	{
		StandardInfo stdinfo;
		unsigned short name_count /* <= 1024 < 2048 */, stream_count /* <= 4106? < 8192 */;
		ChildInfos::value_type::next_entry_type first_child;
		LinkInfos::value_type first_name;
		StreamInfos::value_type first_stream;
		Record() : stdinfo(), name_count(), stream_count(), first_name(), first_stream(), first_child(negative_one)
		{
			this->first_stream.name.offset(negative_one);
			this->first_stream.next_entry = negative_one;
		}
	};
#pragma pack(pop)
	friend struct std::is_scalar<Record>;
	mutable mutex _mutex;
	value_initialized<clock_t> _tbegin;
	value_initialized<bool> _init_called, _failed;
	std::tvstring _root_path;
	Handle _volume;
	std::tvstring names;
	Records records_data;
	RecordsLookup records_lookup;
	LinkInfos nameinfos;
	StreamInfos streaminfos;
	ChildInfos childinfos;
	Handle _finished_event;
	atomic_namespace::atomic<size_t> _total_names_and_streams;
	value_initialized<unsigned int> _expected_records;
	atomic_namespace::atomic<bool> _cancelled;
	atomic_namespace::atomic<unsigned int> _records_so_far, _preprocessed_so_far;
	std::vector<Speed> _perf_reports_circ /* circular buffer */; value_initialized<size_t> _perf_reports_begin;
	atomic_namespace::atomic<Speed> _perf_avg_speed;
#pragma pack(push, 1)
	struct key_type_internal
	{
		// max 1023 hardlinks
		// max 4107 streams
		enum { name_info_bits = 10, stream_info_bits = 13, index_bits = sizeof(unsigned int) * CHAR_BIT - (name_info_bits + stream_info_bits)  };
		typedef unsigned int frs_type;
		typedef unsigned short name_info_type;
		typedef unsigned short stream_info_type;
		typedef unsigned short index_type;
		frs_type frs() const { frs_type const result = this->_frs; return result; }
		name_info_type name_info() const { name_info_type const result = this->_name_info; return result == ((static_cast<name_info_type>(1) << name_info_bits) - 1) ? ~name_info_type() : result; }
		name_info_type stream_info() const { stream_info_type const result = this->_stream_info; return result == ((static_cast<stream_info_type>(1) << stream_info_bits) - 1) ? ~stream_info_type() : result; }
		void stream_info(name_info_type const value) { this->_stream_info = value; }
		index_type index() const { index_type const result = this->_index; return result == ((static_cast<index_type>(1) << index_bits) - 1) ? ~index_type() : result; }
		void index(name_info_type const value) { this->_index = value; }
		explicit key_type_internal(frs_type const frs, name_info_type const name_info, stream_info_type const stream_info)
			: _frs(frs), _name_info(name_info), _stream_info(stream_info), _index(negative_one) { }
		bool operator==(key_type_internal const &other) const { return this->_frs == other._frs && this->_name_info == other._name_info && this->_stream_info == other._stream_info; }
	private:
		frs_type _frs;
		name_info_type _name_info : name_info_bits;
		stream_info_type _stream_info : stream_info_bits;
		index_type _index : index_bits;
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

	Records::value_type *find(key_type_internal::frs_type const frs) { return this->_find(this, frs); }
	Records::value_type const *find(key_type_internal::frs_type const frs) const { return this->_find(this, frs); }

	ChildInfos::value_type *childinfo(Records::value_type *const i) { return this->childinfo(i->first_child); }
	ChildInfos::value_type const *childinfo(Records::value_type const *const i) const { return this->childinfo(i->first_child); }
	ChildInfos::value_type *childinfo(ChildInfo::next_entry_type const i) { return !~i ? NULL : fast_subscript(this->childinfos.begin(), i); }
	ChildInfos::value_type const *childinfo(ChildInfo::next_entry_type const i) const { return !~i ? NULL : fast_subscript(this->childinfos.begin(), i); }
	LinkInfos::value_type *nameinfo(LinkInfo::next_entry_type const i) { return !~i ? NULL : fast_subscript(this->nameinfos.begin(), i); }
	LinkInfos::value_type const *nameinfo(LinkInfo::next_entry_type const i) const { return !~i ? NULL : fast_subscript(this->nameinfos.begin(), i); }
	LinkInfos::value_type *nameinfo(Records::value_type *const i) { return ~i->first_name.name.offset() ? &i->first_name : NULL; }
	LinkInfos::value_type const *nameinfo(Records::value_type const *const i) const { return ~i->first_name.name.offset() ? &i->first_name : NULL; }
	StreamInfos::value_type *streaminfo(StreamInfo::next_entry_type const i) { return !~i ? NULL : fast_subscript(this->streaminfos.begin(), i); }
	StreamInfos::value_type const *streaminfo(StreamInfo::next_entry_type const i) const { return !~i ? NULL : fast_subscript(this->streaminfos.begin(), i); }
	StreamInfos::value_type *streaminfo(Records::value_type *const i) { assert(~i->first_stream.name.offset() || (!i->first_stream.name.length && !i->first_stream.length)); return ~i->first_stream.name.offset() ? &i->first_stream : NULL; }
	StreamInfos::value_type const *streaminfo(Records::value_type const *const i) const { assert(~i->first_stream.name.offset() || (!i->first_stream.name.length && !i->first_stream.length)); return ~i->first_stream.name.offset() ? &i->first_stream : NULL; }
public:
	typedef key_type_internal key_type;
	typedef StandardInfo standard_info;
	typedef NameInfo name_info;
	typedef SizeInfo size_info;
	value_initialized<unsigned int> cluster_size;
	value_initialized<unsigned int> mft_record_size;
	value_initialized<unsigned int> mft_capacity;
	NtfsIndex(std::tvstring value) : _root_path(value), _finished_event(CreateEvent(NULL, TRUE, FALSE, NULL)), _total_names_and_streams(0), _records_so_far(0), _preprocessed_so_far(0), _perf_reports_circ(1 << 6), _cancelled(false)
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
		try
		{
			std::tvstring path_name = this->_root_path;
			deldirsep(path_name);
			std::tvstring ntpath = !path_name.empty() && *path_name.begin() != _T('\\') && *path_name.begin() != _T('/') ? _T("\\??\\") + path_name : path_name;
			winnt::UNICODE_STRING us = { static_cast<unsigned short>(ntpath.size() * sizeof(*ntpath.begin())), static_cast<unsigned short>(ntpath.size() * sizeof(*ntpath.begin())), ntpath.empty() ? NULL : &*ntpath.begin() };
			winnt::OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &us };
			winnt::IO_STATUS_BLOCK iosb;
			Handle volume;
			if (winnt::NtOpenFile(&volume.value, FILE_READ_ATTRIBUTES | FILE_READ_DATA, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0) == 0)
			{
				struct : winnt::FILE_FS_ATTRIBUTE_INFORMATION { unsigned char buf[MAX_PATH]; } info = {};
				if (winnt::NtQueryVolumeInformationFile(volume.value, &iosb, &info, sizeof(info), 5) ||
					info.FileSystemNameLength != 4 * sizeof(*info.FileSystemName) || std::char_traits<TCHAR>::compare(info.FileSystemName, _T("NTFS"), 4))
				{ throw std::invalid_argument("invalid volume"); }
				if (false) { IoPriority::set(reinterpret_cast<uintptr_t>(volume.value), winnt::IoPriorityLow); }
				volume.swap(this->_volume);
				success = true;
			}
		}
		catch (std::invalid_argument &) {}
		this->_failed = !success;
		if (!success) { SetEvent(this->_finished_event); }
		this->_tbegin = clock();
	}
	NtfsIndex *unvolatile() volatile { return const_cast<NtfsIndex *>(this); }
	NtfsIndex const *unvolatile() const volatile { return const_cast<NtfsIndex *>(this); }
	size_t total_names_and_streams() const { return this->_total_names_and_streams.load(atomic_namespace::memory_order_relaxed); }
	size_t total_names_and_streams() const volatile { return this->_total_names_and_streams.load(atomic_namespace::memory_order_acquire); }
	size_t total_names() const { return this->nameinfos.size(); }
	size_t expected_records() const { return this->_expected_records; }
	size_t preprocessed_so_far() const volatile { return this->_preprocessed_so_far.load(atomic_namespace::memory_order_acquire); }
	size_t preprocessed_so_far() const { return this->_preprocessed_so_far.load(atomic_namespace::memory_order_relaxed); }
	size_t records_so_far() const volatile { return this->_records_so_far.load(atomic_namespace::memory_order_acquire); }
	size_t records_so_far() const { return this->_records_so_far.load(atomic_namespace::memory_order_relaxed); }
	void *volume() const volatile { return this->_volume.value; }
	mutex &get_mutex() const volatile { return this->unvolatile()->_mutex; }
	Speed speed() const volatile
	{
		Speed total;
		total = this->_perf_avg_speed.load(atomic_namespace::memory_order_acquire);
		return total;
	}
	std::tvstring const &root_path() const volatile { return const_cast<std::tvstring const &>(this->_root_path); }
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
	uintptr_t finished_event() const
	{
		return reinterpret_cast<uintptr_t>(this->_finished_event.value);
	}
	void reserve(unsigned int records)
	{
		if (!records) { mft_capacity = this->mft_capacity; }
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
	void load(unsigned long long const virtual_offset, void *const buffer, size_t const size, unsigned long long const skipped_begin, unsigned long long const skipped_end)
	{
		if (size % this->mft_record_size)
		{ throw std::runtime_error("Cluster size is smaller than MFT record size; split MFT records (over multiple clusters) not supported. Defragmenting your MFT may sometimes avoid this condition."); }
		if (skipped_begin || skipped_end) { this->_records_so_far.fetch_add(static_cast<unsigned int>((skipped_begin + skipped_end) / this->mft_record_size)); }
		ChildInfo const empty_child_info;
		for (size_t i = virtual_offset % this->mft_record_size ? this->mft_record_size - virtual_offset % this->mft_record_size : 0; i + this->mft_record_size <= size; i += this->mft_record_size, this->_records_so_far.fetch_add(1, atomic_namespace::memory_order_acq_rel))
		{
			unsigned int const frs = static_cast<unsigned int>((virtual_offset + i) / this->mft_record_size);
			ntfs::FILE_RECORD_SEGMENT_HEADER *const frsh = reinterpret_cast<ntfs::FILE_RECORD_SEGMENT_HEADER *>(&static_cast<unsigned char *>(buffer)[i]);
			if (frsh->MultiSectorHeader.Magic == 'ELIF' && frsh->MultiSectorHeader.unfixup(this->mft_record_size) && !!(frsh->Flags & ntfs::FRH_IN_USE))
			{
				unsigned int const frs_base = frsh->BaseFileRecordSegment ? static_cast<unsigned int>(frsh->BaseFileRecordSegment) : frs;
				Records::iterator base_record = this->at(frs_base);
				void const *const frsh_end = frsh->end(this->mft_record_size);
				for (ntfs::ATTRIBUTE_RECORD_HEADER const
					*ah = frsh->begin(); ah < frsh_end && ah->Type != ntfs::AttributeTypeCode() && ah->Type != ntfs::AttributeEnd; ah = ah->next())
				{
					switch (ah->Type)
					{
					case ntfs::AttributeStandardInformation:
						if (ntfs::STANDARD_INFORMATION const *const fn = static_cast<ntfs::STANDARD_INFORMATION const *>(ah->Resident.GetValue()))
						{
							base_record->stdinfo.created = fn->CreationTime;
							base_record->stdinfo.written = fn->LastModificationTime;
							base_record->stdinfo.accessed = fn->LastAccessTime;
							base_record->stdinfo.attributes(fn->FileAttributes | ((frsh->Flags & ntfs::FRH_DIRECTORY) ? FILE_ATTRIBUTE_DIRECTORY : 0));
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
									base_record->first_name.next_entry = static_cast<LinkInfos::value_type::next_entry_type>(link_index);
								}
								LinkInfo *const info = &base_record->first_name;
								info->name.offset(static_cast<unsigned int>(this->names.size()));
								info->name.length = static_cast<unsigned char>(fn->FileNameLength);
								bool const ascii = is_ascii(fn->FileName, fn->FileNameLength);
								info->name.ascii(ascii);
								info->parent = frs_parent;
								append_directional(this->names, fn->FileName, fn->FileNameLength, ascii ? 1 : 0);
								if (frs_parent != frs_base)
								{
									Records::iterator const parent = this->at(frs_parent, &base_record);
									size_t const child_index = this->childinfos.size();
									this->childinfos.push_back(empty_child_info);
									ChildInfo *const child_info = &this->childinfos.back();
									child_info->record_number = frs_base;
									child_info->name_index = base_record->name_count;
									child_info->next_entry = parent->first_child;
									parent->first_child = static_cast<ChildInfos::value_type::next_entry_type>(child_index);
								}
								this->_total_names_and_streams.fetch_add(base_record->stream_count, atomic_namespace::memory_order_acq_rel);
								++base_record->name_count;
							}
						}
						break;
					// case ntfs::AttributeAttributeList:
					// case ntfs::AttributeLoggedUtilityStream:
					case ntfs::AttributeObjectId:
					// case ntfs::AttributeSecurityDescriptor:
					case ntfs::AttributePropertySet:
					case ntfs::AttributeBitmap:
					case ntfs::AttributeIndexAllocation:
					case ntfs::AttributeIndexRoot:
					case ntfs::AttributeData:
					case ntfs::AttributeReparsePoint:
					case ntfs::AttributeEA:
					case ntfs::AttributeEAInformation:
					{
						unsigned long long nonresident_size;
						bool const sparse = !!(ah->Flags & 0x8000);
						if (ah->IsNonResident)
						{
							if (sparse)
							{
								nonresident_size = 0;
								typedef long long T;
								T next_vcn = ah->NonResident.LowestVCN, current_vcn = next_vcn, current_lcn = T();
								unsigned char const *const mapping_pairs = reinterpret_cast<unsigned char const *>(ah) + static_cast<ptrdiff_t>(ah->NonResident.MappingPairsOffset);
								void const *const ah_end = reinterpret_cast<unsigned char const *>(ah) + ah->Length;
								for (size_t j = 0; mapping_pairs[j] && &mapping_pairs[j] < ah_end && &mapping_pairs[j] < frsh_end /* also check we don't go outside of buffer... */; )
								{
									unsigned char const lv = mapping_pairs[j++];
									{
										unsigned char v = static_cast<unsigned char>(lv & ((1U << (CHAR_BIT / 2)) - 1));
										T delta = v && (mapping_pairs[j + v - 1] >> (CHAR_BIT - 1)) ? ~T() << (v * CHAR_BIT) : T();
										for (unsigned char k = 0; k != v; ++k) { delta |= static_cast<T>(mapping_pairs[j++]) << (CHAR_BIT * k); }
										next_vcn += delta;
									}
									{
										unsigned char l = static_cast<unsigned char>(lv >> (CHAR_BIT / 2));
										T delta = l && (mapping_pairs[j + l - 1] >> (CHAR_BIT - 1)) ? ~T() << (l * CHAR_BIT) : T();
										for (unsigned char k = 0; k != l; ++k) { delta |= static_cast<T>(mapping_pairs[j++]) << (CHAR_BIT * k); }
										current_lcn += delta;
									}
									if (current_lcn)
									{
										nonresident_size += next_vcn - current_vcn;
									}
									current_vcn = next_vcn;
								}
								nonresident_size *= this->cluster_size;
							}
							else { nonresident_size = (ah->Flags & 0x0001) ? ah->NonResident.CompressedSize : (frs_base == 0x000000000008 /* $BadClus */ ? ah->NonResident.InitializedSize : ah->NonResident.AllocatedSize); }
						}
						else { nonresident_size = 0; }
						bool const is_primary_attribute = !(ah->IsNonResident && ah->NonResident.LowestVCN);
						if (is_primary_attribute || sparse)
						{
							bool const isI30 = ah->NameLength == 4 && memcmp(ah->name(), _T("$I30"), sizeof(*ah->name()) * 4) == 0;
							if (ah->Type == (isI30 ? ntfs::AttributeIndexAllocation : ntfs::AttributeIndexRoot))
							{
								// Skip this -- for $I30, index header will take care of index allocation; for others, no point showing index root anyway
							}
							else if (!(isI30 && ah->Type == ntfs::AttributeBitmap))
							{
								bool const isdir = (ah->Type == ntfs::AttributeIndexRoot || ah->Type == ntfs::AttributeIndexAllocation) && isI30;
								unsigned char const name_length = isdir ? static_cast<unsigned char>(0) : ah->NameLength;
								unsigned char const type_name_id = static_cast<unsigned char>(isdir ? 0 : ah->Type >> (CHAR_BIT / 2));
								StreamInfo *info = NULL;
								if (StreamInfos::value_type *const si = this->streaminfo(&*base_record))
								{
									if (sparse)
									{
										for (StreamInfos::value_type *k = si; k; k = this->streaminfo(k->next_entry))
										{
											if (k->type_name_id == type_name_id && k->name.length == name_length &&
												(name_length == 0 || std::equal(ah->name(), ah->name() + static_cast<ptrdiff_t>(ah->NameLength), this->names.begin() + static_cast<ptrdiff_t>(k->name.offset()))))
											{
												info = k;
												break;
											}
										}
									}
									if (!info)
									{
										size_t const stream_index = this->streaminfos.size();
										this->streaminfos.push_back(*si);
										si->next_entry = static_cast<small_t<size_t>::type>(stream_index);
									}
								}
								if (!info)
								{
									info = &base_record->first_stream;
									info->allocated = 0;  // We have to initialize this because we add to it later

									// We also have to initialize the name because it _identifies_ the attribute
									info->type_name_id = type_name_id;
									info->name.length = name_length;
									if (isdir)
									{
										// Suppress name
										info->name.offset(0);
									}
									else
									{
										info->name.offset(static_cast<unsigned int>(this->names.size()));
										bool const ascii = is_ascii(ah->name(), ah->NameLength);
										info->name.ascii(ascii);
										append_directional(this->names, ah->name(), ah->NameLength, ascii ? 1 : 0);
									}
									++base_record->stream_count;
									this->_total_names_and_streams.fetch_add(base_record->name_count, atomic_namespace::memory_order_acq_rel);
								}
								info->allocated += nonresident_size;
								if (is_primary_attribute)
								{
									if (!sparse)
									{
										info->allocated = ah->IsNonResident
											? ah->NonResident.CompressionUnit
											? static_cast<file_size_type>(ah->NonResident.CompressedSize)
											: static_cast<file_size_type>(frs_base == 0x000000000008 /* $BadClus */
												? ah->NonResident.InitializedSize /* actually this is still wrong... should be looking at VCNs */
												: ah->NonResident.AllocatedSize)
											: 0;
									}
									info->length = ah->IsNonResident ? static_cast<file_size_type>(frs_base == 0x000000000008 /* $BadClus */ ? ah->NonResident.InitializedSize /* actually this is still wrong... */ : ah->NonResident.DataSize) : ah->Resident.ValueLength;
									info->bulkiness = info->allocated;
									info->treesize = isdir;
								}
							}
						}
						break;
					}
					}
				}
				// fprintf(stderr, "%llx\n", frsh->BaseFileRecordSegment);
			}
		}
		unsigned int const records_so_far = this->_records_so_far.load(atomic_namespace::memory_order_acquire);
		bool const finished = records_so_far >= this->mft_capacity;
		if (finished && !this->_root_path.empty())
		{
			TCHAR buf[2048];
			size_t names_wasted_bytes = 0;
			for (size_t i = 0; i != this->names.size(); ++i)
			{
				if ((this->names[i] | SCHAR_MAX) == SCHAR_MAX)
				{
					++names_wasted_bytes;
				}
			}
			_stprintf(buf,
				_T("%s\trecords_data\twidth = %2u\tsize = %8I64u\tcapacity = %8I64u\n")
				_T("%s\trecords_lookup\twidth = %2u\tsize = %8I64u\tcapacity = %8I64u\n")
				_T("%s\tnames\twidth = %2u\tsize = %8I64u\tcapacity = %8I64u\t%8I64u bytes wasted\n")
				_T("%s\tnameinfos\twidth = %2u\tsize = %8I64u\tcapacity = %8I64u\n")
				_T("%s\tstreaminfos\twidth = %2u\tsize = %8I64u\tcapacity = %8I64u\n")
				_T("%s\tchildinfos\twidth = %2u\tsize = %8I64u\tcapacity = %8I64u\n"),
				this->_root_path.c_str(), static_cast<unsigned>(sizeof(*this->records_data  .begin())), static_cast<unsigned long long>(this->records_data  .size()), static_cast<unsigned long long>(this->records_data  .capacity()),
				this->_root_path.c_str(), static_cast<unsigned>(sizeof(*this->records_lookup.begin())), static_cast<unsigned long long>(this->records_lookup.size()), static_cast<unsigned long long>(this->records_lookup.capacity()),
				this->_root_path.c_str(), static_cast<unsigned>(sizeof(*this->names         .begin())), static_cast<unsigned long long>(this->names         .size()), static_cast<unsigned long long>(this->names         .capacity()), static_cast<unsigned long long>(names_wasted_bytes),
				this->_root_path.c_str(), static_cast<unsigned>(sizeof(*this->nameinfos     .begin())), static_cast<unsigned long long>(this->nameinfos     .size()), static_cast<unsigned long long>(this->nameinfos     .capacity()),
				this->_root_path.c_str(), static_cast<unsigned>(sizeof(*this->streaminfos   .begin())), static_cast<unsigned long long>(this->streaminfos   .size()), static_cast<unsigned long long>(this->streaminfos   .capacity()),
				this->_root_path.c_str(), static_cast<unsigned>(sizeof(*this->childinfos    .begin())), static_cast<unsigned long long>(this->childinfos    .size()), static_cast<unsigned long long>(this->childinfos    .capacity()));
			OutputDebugString(buf);
			struct
			{
				typedef SizeInfo PreprocessResult;
				NtfsIndex *me;
				typedef std::vector<unsigned long long> Scratch;
				Scratch scratch;
				PreprocessResult operator()(Records::value_type *const fr, key_type::name_info_type const name_info, unsigned short const total_names)
				{
					size_t const old_scratch_size = scratch.size();
					PreprocessResult result;
					if (fr)
					{
						PreprocessResult children_size;
						for (ChildInfos::value_type *i = me->childinfo(fr); i && ~i->record_number; i = me->childinfo(i->next_entry))
						{
							Records::value_type *const fr2 = me->find(i->record_number);
							if (fr2 != fr)  /* root directory is the only one that is a child of itself */
							{
								PreprocessResult const
									subresult = this->operator()(fr2, fr2->name_count - static_cast<size_t>(1) - i->name_index, fr2->name_count);
								scratch.push_back(subresult.bulkiness);
								children_size.length += subresult.length;
								children_size.allocated += subresult.allocated;
								children_size.bulkiness += subresult.bulkiness;
								children_size.treesize += subresult.treesize;
							}
						}
						std::make_heap(scratch.begin() + static_cast<ptrdiff_t>(old_scratch_size), scratch.end());
						unsigned long long const threshold = children_size.allocated / 100;
						for (Scratch::iterator i = scratch.end(); i != scratch.begin() + static_cast<ptrdiff_t>(old_scratch_size); )
						{
							std::pop_heap(scratch.begin() + static_cast<ptrdiff_t>(old_scratch_size), i);
							--i;
							if (*i < threshold) { break; }
							children_size.bulkiness = children_size.bulkiness - *i;
						}
						result = children_size;
						for (StreamInfos::value_type *k = me->streaminfo(fr); k; k = me->streaminfo(k->next_entry))
						{
							result.length += k->length * (name_info + 1) / total_names - k->length * name_info / total_names;
							result.allocated += k->allocated * (name_info + 1) / total_names - k->allocated * name_info / total_names;
							result.bulkiness += k->bulkiness * (name_info + 1) / total_names - k->bulkiness * name_info / total_names;
							result.treesize += 1;
							if (!k->type_name_id)
							{
								k->length += children_size.length;
								k->allocated += children_size.allocated;
								k->bulkiness += children_size.bulkiness;
								k->treesize += children_size.treesize;
							}
							me->_preprocessed_so_far.fetch_add(1, atomic_namespace::memory_order_acq_rel);
						}
					}
					scratch.erase(scratch.begin() + static_cast<ptrdiff_t>(old_scratch_size), scratch.end());
					return result;
				}
			} preprocessor = { this };
			clock_t const tbefore_preprocess = clock();
			preprocessor(this->find(0x000000000005), 0, 1);
			clock_t const tfinish = clock();
			Handle().swap(this->_volume);
			_ftprintf(stderr, _T("Finished: %s (%I64u ms total, %I64u ms preprocessing)\n"), this->_root_path.c_str(), (tfinish - this->_tbegin) * 1000ULL / CLOCKS_PER_SEC, (tfinish - tbefore_preprocess) * 1000ULL / CLOCKS_PER_SEC);
		}
		finished ? SetEvent(this->_finished_event) : ResetEvent(this->_finished_event);
	}

	void report_speed(unsigned long long const size, clock_t const tfrom, clock_t const tto)
	{
		clock_t const duration = tto - tfrom;
		Speed const speed(size, duration);
		this->_perf_avg_speed.fetch_add(speed, atomic_namespace::memory_order_acq_rel);
		Speed const prev = this->_perf_reports_circ[this->_perf_reports_begin];
		this->_perf_reports_circ[this->_perf_reports_begin] = speed;
		this->_perf_reports_begin = (this->_perf_reports_begin + 1) % this->_perf_reports_circ.size();
	}

	struct file_pointers
	{
		Records::value_type const *record;
		LinkInfos::value_type const *link;
		StreamInfos::value_type const *stream;
		key_type parent() const
		{
			return key_type(link->parent /* ... | 0 | 0 (since we want the first name of all ancestors)*/, static_cast<key_type::name_info_type>(~key_type::name_info_type()), static_cast<key_type::stream_info_type>(~key_type::stream_info_type()));
		}
	};

	file_pointers get_file_pointers(key_type key) const
	{
		bool wait_for_finish = false;  // has performance penalty
		if (wait_for_finish && WaitForSingleObject(this->_finished_event, 0) == WAIT_TIMEOUT) { throw std::logic_error("Need to wait for indexing to be finished"); }
		file_pointers result;
		result.record = NULL;
		if (~key.frs())
		{
			Records::value_type const *const fr = this->find(key.frs());
			unsigned short ji = 0;
			for (LinkInfos::value_type const *j = this->nameinfo(fr); j; j = this->nameinfo(j->next_entry), ++ji)
			{
				key_type::name_info_type const name_info = key.name_info();
				if (name_info == USHRT_MAX || ji == name_info)
				{
					unsigned short ki = 0;
					for (StreamInfos::value_type const *k = this->streaminfo(fr); k; k = this->streaminfo(k->next_entry), ++ki)
					{
						key_type::stream_info_type const stream_info = key.stream_info();
						if (stream_info == USHRT_MAX ? !k->type_name_id : ki == stream_info)
						{
							result.record = fr;
							result.link = j;
							result.stream = k;
							goto STOP;
						}
					}
				}
			}
		STOP:
			if (!result.record)
			{
				throw std::logic_error("could not find a file attribute");
			}
		}
		return result;
	}

	class ParentIterator
	{
		typedef ParentIterator this_type;
		struct value_type_internal
		{
			void const *first;
			size_t second : sizeof(size_t) * CHAR_BIT - 1;
			size_t ascii : 1;
		};
		NtfsIndex const *index;
		key_type key;
		unsigned char state;
		unsigned short iteration;
		file_pointers ptrs;
		value_type_internal result;
		bool is_root() const
		{
			return key.frs() == 0x000000000005;
		}
		bool is_attribute() const
		{
			return ptrs.stream->type_name_id && (ptrs.stream->type_name_id << (CHAR_BIT / 2)) != ntfs::AttributeData;
		}
	public:
		typedef value_type_internal value_type;
		struct value_type_compare
		{
			bool operator()(value_type const &a, value_type const &b) const
			{
				bool result;
				if (a.ascii)
				{
					if (b.ascii)
					{
						result = std::lexicographical_compare(
							static_cast<char const *>(a.first), static_cast<char const *>(a.first) + static_cast<ptrdiff_t>(a.second),
							static_cast<char const *>(b.first), static_cast<char const *>(b.first) + static_cast<ptrdiff_t>(b.second));
					}
					else
					{
						result = std::lexicographical_compare(
							static_cast<char const *>(a.first), static_cast<char const *>(a.first) + static_cast<ptrdiff_t>(a.second),
							static_cast<wchar_t const *>(b.first), static_cast<wchar_t const *>(b.first) + static_cast<ptrdiff_t>(b.second));
					}
				}
				else
				{
					if (b.ascii)
					{
						result = std::lexicographical_compare(
							static_cast<wchar_t const *>(a.first), static_cast<wchar_t const *>(a.first) + static_cast<ptrdiff_t>(a.second),
							static_cast<char const *>(b.first), static_cast<char const *>(b.first) + static_cast<ptrdiff_t>(b.second));
					}
					else
					{
						result = std::lexicographical_compare(
							static_cast<wchar_t const *>(a.first), static_cast<wchar_t const *>(a.first) + static_cast<ptrdiff_t>(a.second),
							static_cast<wchar_t const *>(b.first), static_cast<wchar_t const *>(b.first) + static_cast<ptrdiff_t>(b.second));
					}
				}
				return result;
			}
		};
		explicit ParentIterator(NtfsIndex const *const index, key_type const &key)
			: index(index), key(key), state(0), iteration(0)
		{
		}
		bool empty() const { return !this->index; }
		bool next() { return ++*this, !this->empty(); }
		value_type const &operator *() const { return this->result; }
		value_type const *operator->() const { return &this->result; }
		unsigned short icomponent() const { return this->iteration; }
		bool operator==(this_type const &other) const { return this->index == other.index && this->key == other.key && this->state == other.state; }
		bool operator!=(this_type const &other) const { return !(*this == other); }
		this_type &operator++()
		{
			switch (state)
			{
				for (; ; )
				{
			case 0:;
					ptrs = index->get_file_pointers(key);
					if (!is_root())
					{
						if (!ptrs.stream->type_name_id)
						{
							result.first = _T("\\"); result.second = 1; result.ascii = false;
							if (result.second) { state = 1; break; }
			case 1:;
						}
					}
					if (!this->iteration)
					{
						if (is_attribute() && ptrs.stream->type_name_id < sizeof(ntfs::attribute_names) / sizeof(*ntfs::attribute_names))
						{
							result.first = ntfs::attribute_names[ptrs.stream->type_name_id].data; result.second = ntfs::attribute_names[ptrs.stream->type_name_id].size; result.ascii = false;
							if (result.second) { state = 2; break; }
			case 2:;
							result.first = _T(":"); result.second = 1; result.ascii = false;
							if (result.second) { state = 3; break; }
			case 3:;
						}
						if (ptrs.stream->name.length)
						{
							result.first = &index->names[ptrs.stream->name.offset()]; result.second = ptrs.stream->name.length; result.ascii = ptrs.stream->name.ascii();
							if (result.second) { state = 4; break; }
			case 4:;
						}
						if (ptrs.stream->name.length || is_attribute())
						{
							result.first = _T(":"); result.second = 1; result.ascii = false;
							if (result.second) { state = 5; break; }
			case 5:;
						}
					}
					if (!this->iteration || !is_root())
					{
						result.first = &index->names[ptrs.link->name.offset()]; result.second = ptrs.link->name.length; result.ascii = ptrs.link->name.ascii();
						if (result.second) { state = 6; break; }
					}
			case 6:;
					if (is_root()) { this->index = NULL; break; }
					state = 0;
					key = ptrs.parent();
					++this->iteration;
				}
			default:;
			}
			return *this;
		}
	};

	size_t get_path(key_type key, std::tvstring &result, bool const name_only) const
	{
		size_t const old_size = result.size();
		for (ParentIterator pi(this, key); pi.next() && !(name_only && pi.icomponent()); )
		{
			TCHAR const *const s = static_cast<TCHAR const *>(pi->first);
			if (name_only || !(pi->second == 1 && (pi->ascii ? *static_cast<char const *>(static_cast<void const *>(s)) : *s) == _T('.')))
			{
				append_directional(result, s, pi->second, pi->ascii ? -1 : 0, true);
			}
		}
		std::reverse(result.begin() + static_cast<ptrdiff_t>(old_size), result.end());
		return result.size() - old_size;
	}

	size_info const &get_sizes(key_type const &key) const
	{
		StreamInfos::value_type const *k;
		Records::value_type const *const fr = this->find(key.frs());
		unsigned short ki = 0;
		for (k = this->streaminfo(fr); k; k = this->streaminfo(k->next_entry), ++ki)
		{
			if (ki == key.stream_info())
			{
				break;
			}
		}
		assert(k);
		return *k;
	}

	standard_info const &get_stdinfo(unsigned int const frn) const
	{
		return this->find(frn)->stdinfo;
	}

	template<class F>
	void matches(F func, std::tvstring &path, bool const match_paths, bool const match_streams, bool const match_attributes) const
	{
		Matcher<F &> matcher = { this, func, match_paths, match_streams, match_attributes, &path, 0 };
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
		bool match_attributes;
		std::tvstring *path;
		size_t basename_index_in_path;
		NameInfo name;
		size_t depth;

		void operator()(key_type::frs_type const frs)
		{
			if (frs < me->records_lookup.size())
			{
				std::tvstring temp;
				Records::value_type const *const i = me->find(frs);
				unsigned short ji = 0;
				for (LinkInfos::value_type const *j = me->nameinfo(i); j; j = me->nameinfo(j->next_entry), ++ji)
				{
					size_t const old_basename_index_in_path = basename_index_in_path;
					basename_index_in_path = path->size();
					temp.clear();
					append_directional(temp, &me->names[j->name.offset()], j->name.length, j->name.ascii() ? -1 : 0);
					this->operator()(frs, ji, temp.data(), temp.size());
					basename_index_in_path = old_basename_index_in_path;
				}
			}
		}

		void operator()(key_type::frs_type const frs, key_type::name_info_type const name_info, TCHAR const stream_prefix [], size_t const stream_prefix_size)
		{
			bool const match_paths_or_streams = match_paths || match_streams || match_attributes;
			bool const buffered_matching = stream_prefix_size || match_paths_or_streams;
			if (frs < me->records_lookup.size() && (frs == 0x00000005 || frs >= 0x00000010 || this->match_attributes))
			{
				Records::value_type const *const fr = me->find(frs);
				{
					size_t const old_size = path->size();
					NameInfo const old_name = name;
					size_t const old_basename_index_in_path = basename_index_in_path;
					++depth;
					if (buffered_matching)
					{
						if (match_paths_or_streams) { path->push_back(_T('\\')); }
						basename_index_in_path = path->size();
					}
					unsigned short ii = 0;
					for (ChildInfos::value_type const *i = me->childinfo(fr); i && ~i->record_number; i = me->childinfo(i->next_entry), ++ii)
					{
						Records::value_type const *const fr2 = me->find(i->record_number);
						unsigned short const ji_target = fr2->name_count - static_cast<size_t>(1) - i->name_index;
						unsigned short ji = 0;
						for (LinkInfos::value_type const *j = me->nameinfo(fr2); j; j = me->nameinfo(j->next_entry), ++ji)
						{
							if (j->parent == frs && ji == ji_target)
							{
								if (buffered_matching)
								{
									append_directional(*path, &me->names[j->name.offset()], j->name.length, j->name.ascii() ? -1 : 0);
								}
								name = j->name;
								this->operator()(static_cast<key_type::frs_type>(i->record_number), ji, NULL, 0);
								if (buffered_matching)
								{
									path->erase(path->end() - static_cast<ptrdiff_t>(j->name.length), path->end());
								}
							}
						}
					}
					--depth;
					basename_index_in_path = old_basename_index_in_path;
					name = old_name;
					if (buffered_matching)
					{
						path->erase(old_size, path->size() - old_size);
					}
				}
				key_type new_key(frs, name_info, 0);
				for (StreamInfos::value_type const *k = me->streaminfo(fr); k; k = me->streaminfo(k->next_entry), new_key.stream_info(new_key.stream_info() + 1))
				{
					assert(k->name.offset() <= me->names.size());
					bool const is_attribute = k->type_name_id && (k->type_name_id << (CHAR_BIT / 2)) != ntfs::AttributeData;
					if (!match_attributes && is_attribute) { continue; }
					size_t const old_size = path->size();
					if (stream_prefix_size)
					{
						path->append(stream_prefix, stream_prefix_size);
					}
					if (match_paths_or_streams)
					{
						if ((fr->stdinfo.attributes() & FILE_ATTRIBUTE_DIRECTORY) && frs != 0x00000005)
						{
							path->push_back(_T('\\'));
						}
					}
					if (match_streams || match_attributes)
					{
						if (k->name.length)
						{
							path->push_back(_T(':'));
							append_directional(*path, k->name.length ? &me->names[k->name.offset()] : NULL, k->name.length, k->name.ascii() ? -1 : 0);
						}
						if (is_attribute)
						{
							if (!k->name.length) { path->push_back(_T(':')); }
							path->push_back(_T(':')), path->append(ntfs::attribute_names[k->type_name_id].data, ntfs::attribute_names[k->type_name_id].size);
						}
					}
					bool ascii;
					size_t name_offset, name_length;
					if (buffered_matching)
					{
						name_offset = match_paths ? 0 : static_cast<unsigned int>(basename_index_in_path);
						name_length = path->size() - name_offset;
						ascii = false;
					}
					else
					{
						name_offset = name.offset();
						name_length = name.length;
						ascii = name.ascii();
					}
					func((buffered_matching ? path->data() : &*me->names.begin()) + static_cast<ptrdiff_t>(name_offset), name_length, ascii, new_key, depth);
					if (buffered_matching)
					{
						path->erase(old_size, path->size() - old_size);
					}
				}
			}
		}
	};
};

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

class RefCountedCString : public WTL::CString  // ref-counted in order to ensure that copying doesn't move the buffer (e.g. in case a containing vector resizes)
{
	typedef RefCountedCString this_type;
	typedef WTL::CString base_type;
	void check_same_buffer(this_type const &other) const
	{
		if (this->GetData() != other.GetData())
		{
			throw std::logic_error("expected the same buffer for both strings");
		}
	}
public:
	RefCountedCString() : base_type() { }
	RefCountedCString(this_type const &other) : base_type(other)
	{
		this->check_same_buffer(other);
	}
	this_type &operator =(this_type const &other)
	{
		this_type &result = static_cast<this_type &>(this->base_type::operator =(static_cast<base_type const &>(other)));
		result.check_same_buffer(other);
		return result;
	}
	LPTSTR data()
	{
		return this->base_type::GetBuffer(this->base_type::GetLength());
	}
	LPTSTR c_str()
	{
		int const n = this->base_type::GetLength();
		LPTSTR const result = this->base_type::GetBuffer(n + 1);
		if (result[n] != _T('\0'))
		{
			result[n] = _T('\0');
		}
		return result;
	}
	operator LPTSTR()
	{
		return this->c_str();
	}
	friend std::basic_ostream<TCHAR> &operator<<(std::basic_ostream<TCHAR> &ss, this_type &me);  // Do NOT implement this. Turns out DDK's implementation doesn't handle embedded null characters correctly. Just use a basic_string directly instead.
};

extern HMODULE mui_module;

class StringLoader
{
	class SwapModuleResource
	{
		SwapModuleResource(SwapModuleResource const &);
		SwapModuleResource &operator =(SwapModuleResource const &);
		HINSTANCE prev;
	public:
		~SwapModuleResource() { InterlockedExchangePointer(reinterpret_cast<void **>(&_Module.m_hInstResource), prev); }
		SwapModuleResource(HINSTANCE const instance) : prev() { InterlockedExchangePointer(reinterpret_cast<void **>(&_Module.m_hInstResource), mui_module); }
	};
	DWORD thread_id;
	std::vector<RefCountedCString> strings;
public:
	StringLoader() : thread_id(GetCurrentThreadId()) { }
	RefCountedCString &operator()(unsigned short const id)
	{
		if (id >= this->strings.size())
		{
			assert(GetCurrentThreadId() && this->thread_id && "cannot expand string table from another thread");
			this->strings.resize(id + 1);
		}
		if (this->strings[id].IsEmpty())
		{
			assert(GetCurrentThreadId() && this->thread_id && "cannot modify string table from another thread");
			RefCountedCString &str = this->strings[id];
			bool success = mui_module && (SwapModuleResource(mui_module), !!str.LoadString(id));
			if (!success)
			{
				str.LoadString(id);
			}
		}
		return this->strings[id];
	}
};

class ImageListAdapter
{
	WTL::CImageList me;
public:
	ImageListAdapter(WTL::CImageList const me) : me(me) { }
	ImageListAdapter *operator->() { return this; }
	ImageListAdapter const *operator->() const { return this; }
	int GetImageCount() const { return me.GetImageCount(); }
	bool GetSize(int const index, int &width, int &height) const
	{
		IMAGEINFO imginfo;
		bool const result = !!me.GetImageInfo(index, &imginfo);
		width = imginfo.rcImage.right - imginfo.rcImage.left;
		height = imginfo.rcImage.bottom - imginfo.rcImage.top;
		return result;
	}
	operator bool() const { return !!me; }
};
class ListViewAdapter
{
	WTL::CListViewCtrl *me;
	WTL::CString temp1;
public:
	typedef std::tvstring String;
	String temp2;
	typedef std::map<String, int> CachedColumnHeaderWidths;
	typedef ptrdiff_t text_getter_type(void *const me, int const item, int const subitem, String &result);
	CachedColumnHeaderWidths *cached_column_header_widths;
	text_getter_type *text_getter;
	class Freeze
	{
		Freeze(Freeze const &);
		Freeze &operator =(Freeze const &);
		ListViewAdapter *me;
	public:
		~Freeze() { }
		explicit Freeze(ListViewAdapter &me) : me(&me) { }
	};
	struct Column : HDITEM
	{
		String text;
		void SetMask(int const mask) { this->mask = mask; }
		String &GetText() { return text; }
	};
	struct Size : WTL::CSize
	{
		Size(WTL::CSize const &size) : WTL::CSize(size) { }
		int GetWidth() const { return this->cx; }
		int GetHeight() const { return this->cy; }
	};
	enum { LIST_MASK_TEXT = 0x0002 };
	struct ClientDC : WTL::CClientDC
	{
		HFONT old_font;
		ClientDC(ClientDC const &);
		ClientDC &operator =(ClientDC const &);
		~ClientDC() { this->old_font = this->SelectFont(this->old_font); }
		explicit ClientDC(HWND const wnd) : WTL::CClientDC(wnd), old_font()
		{
			this->old_font = this->SelectFont(static_cast<ATL::CWindow>(wnd).GetFont());
		}
		int GetTextWidth(String const &string) const
		{
			WTL::CSize sizeRect;
			this->GetTextExtent(string.data(), static_cast<int>(string.size()), &sizeRect);
			return sizeRect.cx;
		}
	};
	ListViewAdapter(WTL::CListViewCtrl &me, CachedColumnHeaderWidths &cached_column_header_widths, text_getter_type *const text_getter)
		: me(&me), cached_column_header_widths(&cached_column_header_widths), text_getter(text_getter) { }
	ListViewAdapter *operator->() { return this; }
	ListViewAdapter const *operator->() const { return this; }
	typedef ImageListAdapter ImageList;
	bool GetColumn(int const j, Column &col)
	{
		bool result = false;
		WTL::CHeaderCtrl header = me->GetHeader();
		if (col.text.empty())
		{
			col.text.resize(16);
		}
		for (;;)
		{
			col.pszText = col.text.empty() ? NULL : &*col.text.begin();
			col.cchTextMax = static_cast<int>(col.text.size());
			if (!header.GetItem(j, &col)) { break; }
			size_t n = 0;
			while (static_cast<int>(n) < col.cchTextMax && col.pszText[n])
			{
				++n;
			}
			if (n < static_cast<size_t>(col.cchTextMax))
			{
				col.text.assign(col.pszText, col.pszText + static_cast<ptrdiff_t>(n));
				result = true;
				break;
			}
			n = n ? n * 2 : 1;
			if (n < col.text.capacity()) { n = col.text.capacity(); }
			col.text.resize(n);
		}
		if (!result) { col.text.clear(); }
		return !!result;
	}
	int GetColumnCount() const { return me->GetHeader().GetItemCount(); }
	std::pair<int, int> GetVisibleItems() const
	{
		std::pair<int, int> result(0, me->GetItemCount());
		WTL::CRect rc;
		if (me->GetClientRect(&rc))
		{
			result.first = me->GetTopIndex();
			WTL::CRect rcitem;
			for (int i = result.first; i < result.second; ++i)
			{
				if (me->GetItemRect(i, &rcitem, LVIR_BOUNDS) && !rcitem.IntersectRect(&rcitem, &rc))
				{
					result.second = i;
					break;
				}
			}
		}
		return result;
	}
	bool DeleteColumn(int const i)
	{
		return !!me->DeleteColumn(i);
	}
	int InsertColumn(int const i, String &text)
	{
		return me->InsertColumn(i, text.c_str());
	}
	int GetColumnWidth(int const i) const
	{
		WTL::CRect rc;
		return me->GetHeader().GetItemRect(i, &rc) ? rc.Width() : 0;
	}
	int GetItemCount() const { return me->GetItemCount(); }
	String *GetItemText(int const item, int const subitem)
	{
		bool success = false;
		if (text_getter)
		{
			success = text_getter(me, item, subitem, temp2) >= 0;
		}
		else
		{
			if (me->GetItemText(item, subitem, temp1) >= 0)
			{
				success = true;
				temp2 = temp1;
			}
		}
		if (!success)
		{
			temp2.clear();
		}
		return success ? &temp2 : NULL;
	}
	Size GetClientSize() const { WTL::CRect rc; return me->GetClientRect(rc) ? rc.Size() : WTL::CSize(); }
	ImageList GetImageList()
	{
		unsigned long const view = me->GetView();
		return ImageList(me->GetImageList(view == LV_VIEW_DETAILS || view == LV_VIEW_LIST || view == LV_VIEW_SMALLICON ? LVSIL_SMALL : LVSIL_NORMAL));
	}
	bool SetColumnWidth(int const column, int const width /* -1 = autosize, -2 = use header */) { return !!me->SetColumnWidth(column, width); }
	bool SetColumnText(int const column, String &text)
	{
		LVCOLUMN col;
		col.mask = LVCF_TEXT;
		col.pszText = const_cast<TCHAR *>(text.c_str());
		return !!me->SetColumn(column, &col);
	}
	operator HWND() const { return *me; }
};

void autosize_columns(ListViewAdapter list)
{
	// Autosize columns
	size_t const m = static_cast<size_t>(list->GetColumnCount());
	size_t const n = static_cast<size_t>(list->GetItemCount());
	if (m && n)
	{
		{
			ListViewAdapter::String empty, text;
			int itemp1 = -1;
			int itemp2 = -1;
			for (int i = 0; i < static_cast<int>(m); ++i)
			{
				ListViewAdapter::Column col;
				col.SetMask(ListViewAdapter::LIST_MASK_TEXT);
				if (list->GetColumn(static_cast<int>(i), col))
				{
					text = col.GetText();
				}
				else { text.clear(); }
				if (list->cached_column_header_widths->find(text) == list->cached_column_header_widths->end())
				{
					if (itemp1 < 0) { itemp1 = static_cast<int>(list->InsertColumn(static_cast<int>(m), empty)); }
					if (itemp2 < 0) { itemp2 = static_cast<int>(list->InsertColumn(static_cast<int>(m), empty)); }
					int cx = -1;
					if (text.empty())
					{
						cx = 0;
					}
					else
					{
						int const old_cx = list->GetColumnWidth(static_cast<int>(i));
						list->SetColumnText(static_cast<int>(m), text);
						if (list->SetColumnWidth(static_cast<int>(itemp2), -2 /*AUTOSIZE_USEHEADER*/))
						{
							cx = list->GetColumnWidth(static_cast<int>(itemp2));
						}
						list->SetColumnWidth(static_cast<int>(i), old_cx);
					}
					if (cx > 0 || (cx == 0 && text.empty()))
					{
						(*list->cached_column_header_widths)[text] = cx;
					}
				}
			}
			if (itemp2 >= 0) { list->DeleteColumn(itemp2); }
			if (itemp1 >= 0) { list->DeleteColumn(itemp1); }
		}
		std::vector<std::pair<std::pair<int /* priority */, int /* width */>, int /* column */> > sizes;
		std::vector<int> max_column_widths(m, 0);
		std::vector<int> column_slacks(m, 0);
		std::vector<int> column_widths(m, 0);
		{
			std::pair<int, int> visible = list->GetVisibleItems();
			int const feather = 1;
			visible.first = visible.first >= feather ? visible.first - feather : 0;
			visible.second = visible.second + feather <= static_cast<ptrdiff_t>(n) ? visible.second + feather : static_cast<int>(n);
			int cximg = 0;
			if (ListViewAdapter::ImageList imagelist = list->GetImageList())
			{
				int cyimg;
				if (!(imagelist->GetImageCount() > 0 && imagelist->GetSize(visible.first, cximg, cyimg)))
				{
					cximg = 0;
				}
			}
			sizes.reserve(static_cast<size_t>(n * m));
			ListViewAdapter::ClientDC dc(list);
			wchar_t const breaks [] = { L'\u200B', L'\u200C', L'\u200D' };
			for (size_t j = 0; j != m; ++j)
			{
				{
					ListViewAdapter::Column col;
					col.SetMask(ListViewAdapter::LIST_MASK_TEXT);
					int cxheader;
					if (list->GetColumn(static_cast<int>(j), col))
					{
						ListViewAdapter::String text(col.GetText());
						int const cx_full = dc.GetTextWidth(text);
						ListViewAdapter::CachedColumnHeaderWidths::const_iterator const found = list->cached_column_header_widths->find(text);
						size_t ibreak = std::find_first_of(text.begin(), text.end(), &breaks[0], &breaks[sizeof(breaks) / sizeof(*breaks)]) - text.begin();
						if (ibreak < text.size())
						{
							text.erase(text.begin() + static_cast<ptrdiff_t>(ibreak), text.end());
							for (int k = 0; k != 3; ++k)
							{
								text.push_back('.');
							}
						}
						int cx = dc.GetTextWidth(text);
						if (found != list->cached_column_header_widths->end())
						{
							cxheader = found->second;
							int const slack = cx_full - cx;
							column_slacks[j] = cxheader - cx_full;
							using std::max;
							cx = max(cxheader - slack, 0);
						}
						else
						{
							cxheader = 0;
							cx += 22;
						}
						column_widths[j] = cx;
					}
					else { cxheader = 0; }
					sizes.push_back(std::make_pair(std::make_pair(SHRT_MAX, cxheader), static_cast<int>(j)));
				}
				for (size_t i = visible.first >= 0 ? static_cast<size_t>(visible.first) : 0; i != (visible.second >= 0 ? static_cast<size_t>(visible.second) : 0); ++i)
				{
					int cx = 0;
					if (ListViewAdapter::String const *const text = list->GetItemText(static_cast<long>(i), static_cast<long>(j)))
					{
						cx = (j == 0 ? cximg : 0) + dc.GetTextWidth(*text) + column_slacks[static_cast<size_t>(j)];
					}
					sizes.push_back(std::make_pair(std::make_pair(0, cx), static_cast<int>(j)));
				}
			}
		}
		for (size_t i = 0; i != sizes.size(); ++i)
		{
			size_t const c = static_cast<size_t>(sizes[i].second);
			if (sizes[i].first.first < SHRT_MAX)
			{
				using std::max;
				max_column_widths[c] = max(max_column_widths[c], sizes[i].first.second);
			}
		}
		int remaining = list->GetClientSize().GetWidth();
		{
			using std::min;
			remaining -= min(remaining, 0);
		}
		for (size_t i = 0; i != column_widths.size(); ++i)
		{
			remaining -= column_widths[i];
		}
		std::sort(sizes.begin(), sizes.end());
		for (size_t i = 0; i != sizes.size() && remaining > 0; ++i)
		{
			int const item_width = sizes[i].first.second;
			size_t const column = static_cast<size_t>(sizes[i].second);
			int const old_column_width = column_widths[column];
			if (old_column_width < item_width)
			{
				using std::min;
				int const diff = min(item_width - old_column_width, remaining);
				assert(diff >= 0);
				column_widths[column] += diff;
				remaining -= diff;
			}
		}
		for (size_t i = column_widths.size(); i > 0 && ((void)--i, true); )
		{
			list->SetColumnWidth(static_cast<int>(i), column_widths[i]);
		}
	}
	else if (false)
	{
		for (size_t i = m; i > 0 && ((void)--i, true); )
		{
			list->SetColumnWidth(static_cast<int>(i), -1 /*AUTOSIZE*/);
		}
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
#pragma warning(suppress: 4555)
		BEGIN_MSG_MAP(CUnselectableWindow)
			MESSAGE_HANDLER(WM_NCHITTEST, OnNcHitTest)
		END_MSG_MAP()
		LRESULT OnNcHitTest(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL&)
		{
			LRESULT result = this->DefWindowProc(uMsg, wParam, lParam);
			return result == HTCLIENT ? HTTRANSPARENT : result;
		}
	};

	WTL::CButton btnPause, btnStop;
	CUnselectableWindow progressText;
	WTL::CProgressBarCtrl progressBar;
	bool canceled;
	bool invalidated;
	DWORD creationTime;
	DWORD lastUpdateTime;
	HWND parent;
	std::tstring lastProgressText, lastProgressTitle;
	bool windowCreated;
	bool windowCreateAttempted;
	int lastProgress, lastProgressTotal;
	StringLoader LoadString;

	BOOL OnInitDialog(CWindow /*wndFocus*/, LPARAM /*lInitParam*/)
	{
		(this->progressText.SubclassWindow)(this->GetDlgItem(IDC_RICHEDITPROGRESS));
		// SetClassLongPtr(this->m_hWnd, GCLP_HBRBACKGROUND, reinterpret_cast<LONG_PTR>(GetSysColorBrush(COLOR_3DFACE)));
		this->btnPause.Attach(this->GetDlgItem(IDRETRY));
		this->btnPause.SetWindowText(this->LoadString(IDS_BUTTON_PAUSE));
		this->btnStop.Attach(this->GetDlgItem(IDCANCEL));
		this->btnStop.SetWindowText(this->LoadString(IDS_BUTTON_STOP));
		this->progressBar.Attach(this->GetDlgItem(IDC_PROGRESS1));
		this->DlgResize_Init(false, false, 0);
		ATL::CComBSTR bstr;
		this->progressText.GetWindowText(&bstr);
		this->lastProgressText.assign(static_cast<LPCTSTR>(bstr), bstr ? bstr.Length() : 0);

		return TRUE;
	}

	void OnPause(UINT uNotifyCode, int nID, CWindow wndCtl)
	{
		UNREFERENCED_PARAMETER(uNotifyCode);
		UNREFERENCED_PARAMETER(nID);
		UNREFERENCED_PARAMETER(wndCtl);
		__debugbreak();
	}

	void OnCancel(UINT uNotifyCode, int nID, CWindow wndCtl)
	{
		UNREFERENCED_PARAMETER(uNotifyCode);
		UNREFERENCED_PARAMETER(nID);
		UNREFERENCED_PARAMETER(wndCtl);
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

#pragma warning(suppress: 4555)
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
			unsigned long result;
			if (this->windowCreated)
			{ result = MsgWaitForMultipleObjectsEx(static_cast<unsigned int>(nhandles), reinterpret_cast<HANDLE const *>(handles), UPDATE_INTERVAL, QS_ALLINPUT, MWMO_INPUTAVAILABLE); }
			else
			{ result = WaitForMultipleObjectsEx(static_cast<unsigned int>(nhandles), reinterpret_cast<HANDLE const *>(handles), FALSE, UPDATE_INTERVAL, FALSE); }
			if (result < WAIT_OBJECT_0 + nhandles || result == WAIT_TIMEOUT)
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
	enum { UPDATE_INTERVAL = 1000 / 64 };
	CProgressDialog(ATL::CWindow parent)
		: Base(true, !!(parent.GetExStyle() & WS_EX_LAYOUTRTL)), parent(parent), lastUpdateTime(0), creationTime(GetTickCount()), lastProgress(0), lastProgressTotal(1), invalidated(false), canceled(false), windowCreated(false), windowCreateAttempted(false)
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

	unsigned long Elapsed(unsigned long const now = GetTickCount()) const
	{
		return now - this->lastUpdateTime;
	}

	bool ShouldUpdate(unsigned long const now = GetTickCount()) const
	{
		return this->Elapsed(now) >= UPDATE_INTERVAL;
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

	void refresh_marquee()
	{
		bool const marquee = this->lastProgressTotal == 0;
		this->progressBar.ModifyStyle(marquee ? 0 : PBS_MARQUEE, marquee ? PBS_MARQUEE : 0, 0);
		this->progressBar.SetMarquee(marquee, UPDATE_INTERVAL);
	}

	void ForceShow()
	{
		if (!this->windowCreateAttempted)
		{
			this->windowCreated = !!this->Create(parent);
			this->windowCreateAttempted = true;
			::EnableWindow(parent, FALSE);
			if (this->windowCreated) { this->refresh_marquee(); }
			this->Flush();
		}
	}

	bool HasUserCancelled(unsigned long const now = GetTickCount())
	{
		bool justCreated = false;
		if (abs(static_cast<int>(now - this->creationTime)) >= static_cast<int>(this->GetMinDelay()))
		{
			this->ForceShow();
		}
		if (this->windowCreated && (justCreated || this->ShouldUpdate(now)))
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
				if (this->lastProgressTotal == 0)
				{ this->progressBar.StepIt(); }
				else
				{
					this->progressBar.SetRange32(0, this->lastProgressTotal);
					this->progressBar.SetPos(this->lastProgress);
				}
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
		bool const marquee_invalidated = this->invalidated && ((this->lastProgressTotal == 0) ^ (total == 0));
		this->lastProgressTotal = static_cast<int>(total);
		this->lastProgress = static_cast<int>(current);
		if (marquee_invalidated) { this->refresh_marquee(); }
	}

	void SetProgressTitle(LPCTSTR title)
	{
		this->invalidated |= this->lastProgressTitle != title;
		this->lastProgressTitle = title;
	}

	void SetProgressText(std::tvstring const &text)
	{
		this->invalidated |= this->lastProgressText.size() != text.size() || !std::equal(this->lastProgressText.begin(), this->lastProgressText.end(), text.begin());
		this->lastProgressText.assign(text.begin(), text.end());
	}

	void SetProgressText(std::tstring const &text)
	{
		this->invalidated |= this->lastProgressText.size() != text.size() || !std::equal(this->lastProgressText.begin(), this->lastProgressText.end(), text.begin());
		this->lastProgressText.assign(text.begin(), text.end());
	}
};

class IoCompletionPort : public RefCounted<IoCompletionPort>
{
	typedef IoCompletionPort this_type;
	IoCompletionPort(this_type const &);
	this_type &operator =(this_type const &);
	struct Task
	{
		HANDLE file;
		void *buffer;
		unsigned long cb;
		intrusive_ptr<Overlapped> overlapped;
		Task() : file(), buffer(), cb() { }
		explicit Task(void *const buffer, unsigned long const cb, intrusive_ptr<Overlapped> const &overlapped) : buffer(buffer), cb(cb), overlapped(overlapped) { }
	};
	typedef std::vector<Task> Pending;
	static unsigned int CALLBACK iocp_worker(void *me)
	{
		return static_cast<this_type volatile *>(me)->worker();
	}
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
	unsigned int worker() volatile
	{
		ULONG_PTR key;
		OVERLAPPED *overlapped_ptr;
		Overlapped *p;
		HANDLE const handle = this->_handle;
		for (unsigned long nr; GetQueuedCompletionStatus(handle, &nr, &key, &overlapped_ptr, INFINITE);)
		{
			p = static_cast<Overlapped *>(overlapped_ptr);
			intrusive_ptr<Overlapped> overlapped(p, false);
			if (overlapped.get())
			{
				int r = (*overlapped)(static_cast<size_t>(nr), key);
				if (r > 0) { r = PostQueuedCompletionStatus(handle, nr, key, overlapped_ptr) ? 0 : -1; }
				if (r >= 0) { overlapped.detach(); }
			}
			else if (key == 1)
			{
				size_t found = ~size_t();
				Task task;
				{
					lock_ptr<this_type> const me_lock(this);
					size_t &pending_scan_offset = const_cast<size_t &>(this->_pending_scan_offset);
					Pending &pending = const_cast<Pending &>(this->_pending);
					winnt::IO_PRIORITY_HINT found_priority = winnt::MaxIoPriorityTypes;
					for (size_t o = 0; o != pending.size(); ++o)
					{
						if (pending_scan_offset == 0 || pending_scan_offset > pending.size()) { pending_scan_offset = pending.size(); }
						--pending_scan_offset;
						size_t const i = pending_scan_offset;
						winnt::IO_PRIORITY_HINT const curr_priority = IoPriority::query(reinterpret_cast<uintptr_t>(pending[i].file));
						if (found_priority == winnt::MaxIoPriorityTypes || curr_priority > found_priority)
						{
							found = i;
							found_priority = curr_priority;
						}
					}
					if (found < pending.size())
					{
						pending_scan_offset = found;
						task = pending[found];
						pending.erase(pending.begin() + static_cast<ptrdiff_t>(found));
					}
				}
				if (~found)
				{
					this->enqueue(task);
				}
			}
			else if (key == 0) { break; }
		}
		return 0;
	}
	void enqueue(Task &task) volatile
	{
		if (!task.cb || ReadFile(task.file, task.buffer, task.cb, NULL, task.overlapped.get()))
		{
			this->post(task.cb, 0, task.overlapped);
		}
		else
		{
			CheckAndThrow(GetLastError() == ERROR_IO_PENDING);
			task.overlapped.detach();
		}
	}
	Handle _handle;
	atomic_namespace::atomic<bool> _initialized;
	std::vector<uintptr_t> _threads;
	mutable mutex _mutex;
	Pending _pending;
	size_t _pending_scan_offset;
public:
	~IoCompletionPort() { this->close(); }
	IoCompletionPort() : _handle(CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0)), _initialized(false), _pending_scan_offset() { }
	this_type *unvolatile() volatile { return const_cast<this_type *>(this); }
	this_type const *unvolatile() const volatile { return const_cast<this_type *>(this); }
	mutex &get_mutex() const volatile { return this->unvolatile()->_mutex; }
	void ensure_initialized()
	{
		if (this->_threads.empty())
		{
			for (size_t i = static_cast<size_t>(get_num_threads()); i != 0; --i)
			{
				unsigned int id;
				this->_threads.push_back(_beginthreadex(NULL, 0, iocp_worker, this, 0, &id));
			}
			this->_initialized.store(true, atomic_namespace::memory_order_release);
		}
	}
	void ensure_initialized() volatile
	{
		if (!this->_initialized.load(atomic_namespace::memory_order_acquire))
		{
			lock(this)->ensure_initialized();
		}
	}
	void post(unsigned long cb, uintptr_t const key, intrusive_ptr<Overlapped> overlapped) volatile
	{
		this->ensure_initialized();
		CheckAndThrow(!!PostQueuedCompletionStatus(this->_handle, cb, key, overlapped.get()));
		overlapped.detach();
	}
	void read_file(HANDLE const file, void *const buffer, unsigned long const cb, intrusive_ptr<Overlapped> const &overlapped) volatile
	{
		// This part needs a lock
		{
			lock_ptr<this_type> const me_lock(this);
			Pending &pending = const_cast<Pending &>(this->_pending);
			pending.push_back(Task());
			Task &task = pending.back();
			task.file = file;
			task.buffer = buffer;
			task.cb = cb;
			task.overlapped = overlapped;
		}
		this->post(0, 1, NULL);
	}
	void associate(HANDLE const file, uintptr_t const key) volatile
	{
		this->ensure_initialized();
		CheckAndThrow(!!CreateIoCompletionPort(file, this->_handle, key, 0));
	}
	void close() volatile { return lock(this)->close(); }
	void close()
	{
		for (size_t i = 0; i != this->_threads.size(); ++i)
		{ this->post(0, 0, NULL); }
		while (!this->_threads.empty())
		{
			size_t n = std::min(this->_threads.size(), static_cast<size_t>(MAXIMUM_WAIT_OBJECTS));
			WaitForMultipleObjects(static_cast<unsigned long>(n), reinterpret_cast<void *const *>(&*this->_threads.begin() + this->_threads.size() - n), TRUE, INFINITE);
			while (n) { this->_threads.pop_back(); --n; }
		}
		this->_initialized.store(false, atomic_namespace::memory_order_release);
	}
};

class OverlappedNtfsMftReadPayload : public Overlapped
{
	struct RetPtr
	{
		unsigned long long vcn, cluster_count;
		long long lcn;
		atomic_namespace::atomic<unsigned long long> skip_begin, skip_end;
		RetPtr(unsigned long long const vcn, unsigned long long const cluster_count, unsigned long long const lcn) : vcn(vcn), cluster_count(cluster_count), lcn(lcn), skip_begin(0), skip_end(0) { }
		RetPtr(RetPtr const &other) : vcn(other.vcn), cluster_count(other.cluster_count), lcn(other.lcn), skip_begin(other.skip_begin.load(atomic_namespace::memory_order_relaxed)), skip_end(other.skip_end.load(atomic_namespace::memory_order_relaxed)) { }
		RetPtr &operator =(RetPtr const &other)
		{
			this->vcn = other.vcn;
			this->cluster_count = other.cluster_count;
			this->lcn = other.lcn;
			this->skip_begin.store(other.skip_begin.load(atomic_namespace::memory_order_relaxed));
			this->skip_end.store(other.skip_end.load(atomic_namespace::memory_order_relaxed));
			return *this;
		}
	};
	typedef std::vector<RetPtr> RetPtrs;
	typedef std::vector<unsigned char> Bitmap;
	intrusive_ptr<IoCompletionPort volatile> iocp;
	HWND m_hWnd;
	Handle closing_event;
	RetPtrs bitmap_ret_ptrs, data_ret_ptrs;
	unsigned int cluster_size;
	unsigned long long read_block_size;
	atomic_namespace::atomic<RetPtrs::size_type> jbitmap, nbitmap_chunks_left, jdata;
	atomic_namespace::atomic<unsigned int> valid_records;
	Bitmap mft_bitmap;  // may be unavailable -- don't fail in that case!
	intrusive_ptr<NtfsIndex volatile> p;
public:
	class ReadOperation;
	~OverlappedNtfsMftReadPayload()
	{
	}
	OverlappedNtfsMftReadPayload(intrusive_ptr<IoCompletionPort> const &iocp, intrusive_ptr<NtfsIndex volatile> p, HWND const m_hWnd, Handle const &closing_event)
		: Overlapped(), iocp(iocp), m_hWnd(m_hWnd), closing_event(closing_event), valid_records(0), cluster_size(), read_block_size(1 << 20), jbitmap(0), nbitmap_chunks_left(0), jdata(0)
	{
		using std::swap; swap(p, this->p);
	}
	void queue_next() volatile;
	int operator()(size_t const /*size*/, uintptr_t const /*key*/);
};
class OverlappedNtfsMftReadPayload::ReadOperation : public Overlapped
{
	unsigned long long _voffset, _skipped_begin, _skipped_end;
	clock_t _time;
	static mutex recycled_mutex;
	static std::vector<std::pair<size_t, void *> > recycled;
	bool _is_bitmap;
	intrusive_ptr<OverlappedNtfsMftReadPayload volatile> q;
	static void *operator new(size_t n)
	{
		void *p;
		if (true)
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
		if (true)
		{
			lock_guard<mutex>(recycled_mutex), recycled.push_back(std::pair<size_t, void *>(_msize(p), p));
		}
		else
		{
			return ::operator delete(p);
		}
	}
	static void operator delete(void *p, size_t /*m*/) { return operator delete(p); }
	explicit ReadOperation(intrusive_ptr<OverlappedNtfsMftReadPayload volatile> const &q, bool const is_bitmap)
		: Overlapped(), _voffset(), _skipped_begin(), _skipped_end(), _time(clock()), q(q), _is_bitmap(is_bitmap) { }
	unsigned long long voffset() { return this->_voffset; }
	void voffset(unsigned long long const value) { this->_voffset = value; }
	unsigned long long skipped_begin() { return this->_skipped_begin; }
	void skipped_begin(unsigned long long const value) { this->_skipped_begin = value; }
	unsigned long long skipped_end() { return this->_skipped_end; }
	void skipped_end(unsigned long long const value) { this->_skipped_end = value; }
	clock_t time() { return this->_time; }
	void time(clock_t const value) { this->_time = value; }
	int operator()(size_t const size, uintptr_t const /*key*/)
	{
		OverlappedNtfsMftReadPayload *const q = const_cast<OverlappedNtfsMftReadPayload *>(static_cast<OverlappedNtfsMftReadPayload volatile *>(this->q.get()));
		if (!q->p->cancelled())
		{
			this->q->queue_next();
			void *const buffer = this + 1;
			if (this->_is_bitmap)
			{
				size_t const records_per_bitmap_word = sizeof(*q->mft_bitmap.begin()) * CHAR_BIT;
				if (this->voffset() * CHAR_BIT <= q->p->mft_capacity)
				{
					static unsigned char const popcount [] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
					unsigned int nrecords = 0;
					size_t n = size;
					if (this->voffset() + n >= q->p->mft_capacity / CHAR_BIT)
					{
						n = static_cast<size_t>(q->p->mft_capacity / CHAR_BIT - this->voffset());
					}
					for (size_t i = 0; i < n; ++i)
					{
						unsigned char const
							v = static_cast<unsigned char const *>(buffer)[i],
							vlow = static_cast<unsigned char>(v >> (CHAR_BIT / 2)),
							vhigh = static_cast<unsigned char>(v ^ (vlow << (CHAR_BIT / 2)));
						nrecords += popcount[vlow];
						nrecords += popcount[vhigh];
					}
					std::copy(static_cast<unsigned char const *>(buffer), static_cast<unsigned char const *>(buffer) + static_cast<ptrdiff_t>(n), q->mft_bitmap.begin() + static_cast<ptrdiff_t>(this->voffset()));
					q->valid_records.fetch_add(nrecords, atomic_namespace::memory_order_acq_rel);
				}
				if (q->nbitmap_chunks_left.fetch_sub(1, atomic_namespace::memory_order_acq_rel) == 1)
				{
					unsigned int const valid_records = q->valid_records.exchange(0 /* make sure this doesn't happen twice */, atomic_namespace::memory_order_acq_rel);
					lock(q->p)->reserve(valid_records);

					// Now, go remove records from the queue that we know are invalid...
					for (RetPtrs::iterator i = q->data_ret_ptrs.begin(); i != q->data_ret_ptrs.end(); ++i)
					{
						size_t const
							irecord = static_cast<size_t>(i->vcn * q->cluster_size / q->p->mft_record_size),
							nrecords = static_cast<size_t>(i->cluster_count * q->cluster_size / q->p->mft_record_size);
						size_t skip_records_begin, skip_records_end;
						// TODO: We're doing a bitmap search bit-by-bit here, which is slow...
						// maybe improve it at some point... but OTOH it's still much faster than I/O anyway, so whatever...
						for (skip_records_begin = 0; skip_records_begin != nrecords; ++skip_records_begin)
						{
							size_t const j = irecord + skip_records_begin, j1 = j / records_per_bitmap_word, j2 = j % records_per_bitmap_word;
							if (q->mft_bitmap[j1] & (1 << j2)) { break; }
						}
						for (skip_records_end = 0; skip_records_end != nrecords - skip_records_begin; ++skip_records_end)
						{
							size_t const j = irecord + nrecords - 1 - skip_records_end, j1 = j / records_per_bitmap_word, j2 = j % records_per_bitmap_word;
							if (q->mft_bitmap[j1] & (1 << j2)) { break; }
							skip_records_end = skip_records_end;
						}
						size_t
							skip_clusters_begin = static_cast<size_t>(static_cast<unsigned long long>(skip_records_begin) * q->p->mft_record_size / q->cluster_size),
							skip_clusters_end = static_cast<size_t>(static_cast<unsigned long long>(skip_records_end) * q->p->mft_record_size / q->cluster_size);
						if (skip_clusters_begin + skip_clusters_end > i->cluster_count) { throw std::logic_error("we should never be skipping more clusters than there are"); }
						i->skip_begin.store(skip_clusters_begin, atomic_namespace::memory_order_release);
						i->skip_end.store(skip_clusters_end, atomic_namespace::memory_order_release);
					}
				}
			}
			else
			{
				lock(q->p)->load(this->voffset(), buffer, size, this->skipped_begin(), this->skipped_end());
			}
			{
				lock(q->p)->report_speed(size, this->time(), clock());
			}
		}
		return -1;
	}
};
mutex OverlappedNtfsMftReadPayload::ReadOperation::recycled_mutex;
std::vector<std::pair<size_t, void *> > OverlappedNtfsMftReadPayload::ReadOperation::recycled;

void OverlappedNtfsMftReadPayload::queue_next() volatile
{
	OverlappedNtfsMftReadPayload const *const me = const_cast<OverlappedNtfsMftReadPayload const *>(this);
	bool handled = false;
	if (!handled)
	{
		size_t const jbitmap = this->jbitmap.fetch_add(1, atomic_namespace::memory_order_acq_rel);
		if (jbitmap < me->bitmap_ret_ptrs.size())
		{
			handled = true;
			RetPtrs::const_iterator const j = me->bitmap_ret_ptrs.begin() + static_cast<ptrdiff_t>(jbitmap);
			unsigned long long const
				skip_begin = j->skip_begin.load(atomic_namespace::memory_order_acquire),
				skip_end = j->skip_end.load(atomic_namespace::memory_order_acquire);
			unsigned int const cb = static_cast<unsigned int>((j->cluster_count - (skip_begin + skip_end)) * me->cluster_size);
			intrusive_ptr<ReadOperation> p(new(cb) ReadOperation(this, true));
			p-> offset((j->lcn + skip_begin) * static_cast<long long>(me->cluster_size));
			p->voffset((j->vcn + skip_begin) * me->cluster_size);
			p->skipped_begin(skip_begin * me->cluster_size);
			p->skipped_end(skip_end * me->cluster_size);
			p->time(clock());
			me->iocp->read_file(me->p->volume(), p.get() + 1, cb, p);
		}
		else if (jbitmap > me->bitmap_ret_ptrs.size())
		{
			// oops, increased multiple times... decrease to keep at max
			this->jbitmap.fetch_sub(1, atomic_namespace::memory_order_acq_rel);
		}
	}
	if (!handled)
	{
		size_t const jdata = this->jdata.fetch_add(1, atomic_namespace::memory_order_acq_rel);
		if (jdata < me->data_ret_ptrs.size())
		{
			handled = true;
			RetPtrs::const_iterator const j = me->data_ret_ptrs.begin() + static_cast<ptrdiff_t>(jdata);
			unsigned long long const
				skip_begin = j->skip_begin.load(atomic_namespace::memory_order_acquire),
				skip_end = j->skip_end.load(atomic_namespace::memory_order_acquire);
			unsigned int const cb = static_cast<unsigned int>((j->cluster_count - (skip_begin + skip_end)) * me->cluster_size);
			intrusive_ptr<ReadOperation> p(new(cb) ReadOperation(this, false));
			p-> offset((j->lcn + skip_begin) * static_cast<long long>(me->cluster_size));
			p->voffset((j->vcn + skip_begin) * me->cluster_size);
			p->skipped_begin(skip_begin * me->cluster_size);
			p->skipped_end(skip_end * me->cluster_size);
			p->time(clock());
			me->iocp->read_file(me->p->volume(), p.get() + 1, cb, p);
		}
		else if (jdata > me->data_ret_ptrs.size())
		{
			// oops, increased multiple times... decrease to keep at max
			this->jdata.fetch_sub(1, atomic_namespace::memory_order_acq_rel);
		}
	}
}
int OverlappedNtfsMftReadPayload::operator()(size_t const /*size*/, uintptr_t const key)
{
	int result = -1;
	intrusive_ptr<NtfsIndex> p = this->p->unvolatile();
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
		p->cluster_size = info.BytesPerCluster;
		p->mft_record_size = info.BytesPerFileRecordSegment;
		p->mft_capacity = static_cast<unsigned int>(info.MftValidDataLength.QuadPart / info.BytesPerFileRecordSegment);
		this->iocp->associate(volume, reinterpret_cast<uintptr_t>(&*p));
		typedef std::vector<std::pair<unsigned long long, long long> > RP;
		{
			Handle root_dir;
			{
				unsigned long long root_dir_id = 0x0005000000000005;
				winnt::UNICODE_STRING us = { sizeof(root_dir_id), sizeof(root_dir_id), reinterpret_cast<wchar_t *>(&root_dir_id) };
				winnt::OBJECT_ATTRIBUTES oa = { sizeof(oa), volume, &us };
				winnt::IO_STATUS_BLOCK iosb;
				unsigned long const error = winnt::RtlNtStatusToDosError(winnt::NtOpenFile(&root_dir.value, FILE_READ_ATTRIBUTES, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0x00002000 /* FILE_OPEN_BY_FILE_ID */));
				if (error) { SetLastError(error); CheckAndThrow(!error); }
			}
			{
				long long llsize = 0;
				RP const ret_ptrs = get_mft_retrieval_pointers(root_dir, _T("$MFT::$BITMAP"), &llsize, info.MftStartLcn.QuadPart, this->p->mft_record_size);
				unsigned long long prev_vcn = 0;
				for (RP::const_iterator i = ret_ptrs.begin(); i != ret_ptrs.end(); ++i)
				{
					long long const clusters_left = static_cast<long long>(std::max(i->first, prev_vcn) - prev_vcn);
					unsigned long long n;
					for (long long m = 0; m < clusters_left; m += static_cast<long long>(n))
					{
						n = std::min(i->first - prev_vcn, 1 + (static_cast<unsigned long long>(this->read_block_size) - 1) / this->cluster_size);
						this->bitmap_ret_ptrs.push_back(RetPtrs::value_type(prev_vcn, n, i->second + m));
						prev_vcn += n;
					}
				}
				this->mft_bitmap.resize(static_cast<size_t>(llsize), static_cast<Bitmap::value_type>(~Bitmap::value_type()) /* default should be to read unused slots too */);
				this->nbitmap_chunks_left.store(this->bitmap_ret_ptrs.size(), atomic_namespace::memory_order_release);
			}
			{
				long long llsize = 0;
				RP const ret_ptrs = get_mft_retrieval_pointers(root_dir, _T("$MFT::$DATA"), &llsize, info.MftStartLcn.QuadPart, p->mft_record_size);
				unsigned long long prev_vcn = 0;
				for (RP::const_iterator i = ret_ptrs.begin(); i != ret_ptrs.end(); ++i)
				{
					long long const clusters_left = static_cast<long long>(std::max(i->first, prev_vcn) - prev_vcn);
					unsigned long long n;
					for (long long m = 0; m < clusters_left; m += static_cast<long long>(n))
					{
						n = std::min(i->first - prev_vcn, 1 + (static_cast<unsigned long long>(this->read_block_size) - 1) / this->cluster_size);
						this->data_ret_ptrs.push_back(RetPtrs::value_type(prev_vcn, n, i->second + m));
						prev_vcn += n;
					}
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
	typedef unsigned short index_type;
	typedef unsigned short depth_type;
	explicit SearchResult(NtfsIndex::key_type const key, depth_type const depth)
		: _key(key), _depth(depth) { }
	NtfsIndex::key_type key() const { return this->_key; }
	depth_type depth() const { return static_cast<depth_type>(this->_depth); }
	NtfsIndex::key_type::index_type index() const { return this->_key.index(); }
	void index(NtfsIndex::key_type::index_type const value) { this->_key.index(value); }
private:
	NtfsIndex::key_type _key;
	depth_type _depth;
};
#pragma pack(pop)

extern "C" IMAGE_DOS_HEADER __ImageBase;

unsigned long long get_version(IMAGE_DOS_HEADER const *const image_base)
{
	return reinterpret_cast<IMAGE_NT_HEADERS const *>(reinterpret_cast<unsigned char const *>(image_base) + image_base->e_lfanew)->FileHeader.TimeDateStamp * 10000000ULL + 0x019db1ded53e8000ULL;
}

class CMainDlg : public CModifiedDialogImpl<CMainDlg>, public WTL::CDialogResize<CMainDlg>, public CInvokeImpl<CMainDlg>, private WTL::CMessageFilter
{
	enum { IDC_STATUS_BAR = 1100 + 0 };
	enum { COLUMN_INDEX_NAME, COLUMN_INDEX_PATH, COLUMN_INDEX_SIZE, COLUMN_INDEX_SIZE_ON_DISK, COLUMN_INDEX_CREATION_TIME, COLUMN_INDEX_MODIFICATION_TIME, COLUMN_INDEX_ACCESS_TIME, COLUMN_INDEX_DESCENDENTS };
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
	template<class Container> struct NFormatBase { typedef basic_iterator_ios<std::back_insert_iterator<Container>, typename Container::traits_type> type; };
	class NFormat : public NFormatBase<std::tstring>::type, public NFormatBase<std::tvstring>::type
	{
		typedef NFormat this_type;
	public:
		explicit NFormat(std::locale const &loc) : NFormatBase<std::tstring>::type(loc), NFormatBase<std::tvstring>::type(loc) { }

		template<class T>
		struct lazy
		{
			this_type const *me;
			T const *value;
			explicit lazy(this_type const *const me, T const &value) : me(me), value(&value) { }
			operator std::tstring() const
			{
				std::tstring result;
				me->typename NFormatBase<std::tstring>::type::put(std::back_inserter(result), *value);
				return result;
			}
			operator std::tvstring() const
			{
				std::tvstring result;
				me->typename NFormatBase<std::tvstring>::type::put(std::back_inserter(result), *value);
				return result;
			}
			template<class String>
			friend String &operator+=(String &out, lazy const &this_)
			{
				this_.me->typename NFormatBase<String>::type::put(std::back_inserter(out), *this_.value);
				return out;
			}
		};
		template<class T>
		lazy<T> operator()(T const &value) const { return lazy<T>(this, value); }
	};
	struct CThemedListViewCtrl : public WTL::CListViewCtrl, public WTL::CThemeImpl<CThemedListViewCtrl> { using WTL::CListViewCtrl::Attach; };
	class CSearchPattern : public ATL::CWindowImpl<CSearchPattern, WTL::CEdit>
	{
#pragma warning(suppress: 4555)
		BEGIN_MSG_MAP_EX(CCustomDialogCode)
			MSG_WM_MOUSEMOVE(OnMouseMove)
			MSG_WM_MOUSELEAVE(OnMouseLeave)
			MSG_WM_MOUSEHOVER(OnMouseHover)
			MESSAGE_HANDLER_EX(EM_REPLACESEL, OnReplaceSel)
			MESSAGE_RANGE_HANDLER_EX(WM_KEYDOWN, WM_KEYUP, OnKey)
		END_MSG_MAP()
		bool tracking;
		StringLoader LoadString;
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
			WTL::CString sysdir;
			{
				LPTSTR buf = sysdir.GetBufferSetLength(SHRT_MAX);
				unsigned int const cch = GetWindowsDirectory(buf, sysdir.GetAllocLength());
				sysdir.Delete(cch, sysdir.GetLength() - static_cast<int>(cch));
			}
			WTL::CString const
				title = this->LoadString(IDS_SEARCH_PATTERN_TITLE),
				body = this->LoadString(IDS_SEARCH_PATTERN_BODY) + _T("\r\n") + sysdir + getdirsep() + _T("**") + getdirsep() + _T("*.exe") + _T("\r\n") + _T("Picture*.jpg");
			EDITBALLOONTIP tip = { sizeof(tip), title, body, TTI_INFO };
			this->ShowBalloonTip(&tip);
		}
	};

	struct CacheInfo
	{
		explicit CacheInfo(size_t const counter) : counter(counter), valid(false), iIconSmall(-1), iIconLarge(-1), iIconExtraLarge(-1) { this->szTypeName[0] = _T('\0'); }
		size_t counter;
		bool valid;
		int iIconSmall, iIconLarge, iIconExtraLarge;
		TCHAR szTypeName[80];
		std::tvstring description;
	};
	static unsigned int const WM_TASKBARCREATED;
	enum { WM_NOTIFYICON = WM_USER + 100 };

#ifdef _MSC_VER
	__declspec(align(0x40))
#endif
	class Results : memheap_vector<SearchResult>
	{
		typedef Results this_type;
		typedef memheap_vector<value_type, allocator_type> base_type;
		typedef std::vector<intrusive_ptr<NtfsIndex volatile const> > Indexes;
		typedef std::vector<std::pair<Indexes::value_type::value_type *, SearchResult::index_type> > IndicesInUse;
		Indexes indexes /* to keep alive */;
		IndicesInUse indices_in_use /* to keep alive */;
	public:
		typedef base_type::allocator_type allocator_type;
		typedef base_type::value_type value_type;
		typedef base_type::reverse_iterator iterator;
		typedef base_type::const_reverse_iterator const_iterator;
		typedef base_type::size_type size_type;
		Results() : base_type() { }
		explicit Results(allocator_type const &alloc) : base_type(alloc) { }
		iterator begin() { return this->base_type::rbegin(); }
		const_iterator begin() const { return this->base_type::rbegin(); }
		iterator end() { return this->base_type::rend(); }
		const_iterator end() const { return this->base_type::rend(); }
		using base_type::capacity;
		size_type size() const { return this->end() - this->begin(); }
		SearchResult::index_type save_index(Indexes::value_type::element_type *const index)
		{
			IndicesInUse::iterator j = std::lower_bound(this->indices_in_use.begin(), this->indices_in_use.end(), std::make_pair(index, IndicesInUse::value_type::second_type()));
			if (j == this->indices_in_use.end() || j->first != index)
			{
				this->indexes.push_back(index);
				j = this->indices_in_use.insert(j, IndicesInUse::value_type(index, static_cast<IndicesInUse::value_type::second_type>(this->indexes.size() - 1)));
			}
			return j->second;
		}
		Indexes::value_type::element_type *item_index(size_t const i) const { return this->ith_index((*this)[i].index()); }
		Indexes::value_type::element_type *ith_index(value_type::index_type const i) const { return this->indexes[i]; }
		value_type const &operator[](size_t const i) const { return this->begin()[static_cast<ptrdiff_t>(i)]; }
		void reserve(size_t const n)
		{
			(void) n;
			this->base_type::reserve(n);
		}
		void push_back(Indexes::value_type::element_type *const index, base_type::const_reference value)
		{
			this->base_type::push_back(value);
			(*(this->base_type::end() - 1)).index(this->save_index(index));
		}
		void clear()
		{
			this->base_type::clear();
			this->indexes.clear();
			this->indices_in_use.clear();
		}
		void swap(this_type &other)
		{
			this->base_type::swap(static_cast<base_type &>(other));
			this->indexes.swap(other.indexes);
			this->indices_in_use.swap(other.indices_in_use);
		}
		friend void swap(this_type &a, this_type &b) { return a.swap(b); }
	};

	typedef std::map<std::tvstring, CacheInfo> IconCache;

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

	template<class StrCmp>
	static NameComparator<StrCmp> name_comparator(StrCmp const &cmp) { return NameComparator<StrCmp>(cmp); }

	CSearchPattern txtPattern;
	WTL::CButton btnOK, btnBrowse;
	WTL::CRichEditCtrl richEdit;
	WTL::CStatusBarCtrl statusbar;
	WTL::CAccelerator accel;
	IconCache cache;
	value_initialized<HANDLE> hRichEdit;
	value_initialized<bool> autocomplete_called;
	struct
	{
		value_initialized<int> column;
		value_initialized<unsigned char> variation;
		value_initialized<unsigned int> counter;
	} last_sort;
	Results results;
	WTL::CImageList _small_image_list;  // image list that is used as the "small" image list
	WTL::CImageList imgListSmall, imgListLarge, imgListExtraLarge;  // lists of small images
	WTL::CComboBox cmbDrive;
	value_initialized<int> indices_created;
	CThemedListViewCtrl lvFiles;
	ListViewAdapter::CachedColumnHeaderWidths cached_column_header_widths;
	WTL::CMenu menu;
	intrusive_ptr<BackgroundWorker> iconLoader;
	Handle closing_event;
	intrusive_ptr<IoCompletionPort> iocp;
	value_initialized<bool> _initialized;
	NFormat nformat_ui, nformat_io;
	value_initialized<long long> time_zone_bias;
	LCID lcid;
	value_initialized<HANDLE> hWait, hEvent;
	CoInit coinit;
	COLORREF deletedColor;
	COLORREF encryptedColor;
	COLORREF compressedColor;
	value_initialized<int> suppress_escapes;
	StringLoader LoadString;
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
	CMainDlg(HANDLE const hEvent, bool const rtl) :
		CModifiedDialogImpl<CMainDlg>(true, rtl),
		closing_event(CreateEvent(NULL, TRUE, FALSE, NULL)), iocp(new IoCompletionPort()),
		nformat_ui(std::locale("")), nformat_io(std::locale()), lcid(GetThreadLocale()), hEvent(hEvent),
		iconLoader(BackgroundWorker::create(true)),
		deletedColor(RGB(0xFF, 0, 0)), encryptedColor(RGB(0, 0xFF, 0)), compressedColor(RGB(0, 0, 0xFF))
	{
		winnt::SYSTEM_TIMEOFDAY_INFORMATION info = {};
		unsigned long nb;
		winnt::NtQuerySystemInformation(static_cast<enum winnt::_SYSTEM_INFORMATION_CLASS>(3), &info, sizeof(info), &nb);
		this->time_zone_bias = info.TimeZoneBias.QuadPart;
	}

	void SystemTimeToString(long long system_time /* UTC */, std::tvstring &buffer, bool const sortable, bool const include_time = true) const
	{
		long long local_time = system_time - this->time_zone_bias;
		winnt::TIME_FIELDS tf;
		winnt::RtlTimeToTimeFields(&reinterpret_cast<LARGE_INTEGER &>(local_time), &tf);
		if (sortable)
		{
			TCHAR buf[64], *p = buf;
			size_t cch_zero  ; basic_conv<TCHAR>::to_string(0        , p, 10); cch_zero   = std::char_traits<TCHAR>::length(p); p += static_cast<ptrdiff_t>(cch_zero  );
			size_t cch_year  ; basic_conv<TCHAR>::to_string(tf.Year  , p, 10); cch_year   = std::char_traits<TCHAR>::length(p); p += static_cast<ptrdiff_t>(cch_year  );
			size_t cch_month ; basic_conv<TCHAR>::to_string(tf.Month , p, 10); cch_month  = std::char_traits<TCHAR>::length(p); p += static_cast<ptrdiff_t>(cch_month );
			size_t cch_day   ; basic_conv<TCHAR>::to_string(tf.Day   , p, 10); cch_day    = std::char_traits<TCHAR>::length(p); p += static_cast<ptrdiff_t>(cch_day   );
			size_t cch_hour  ; basic_conv<TCHAR>::to_string(tf.Hour  , p, 10); cch_hour   = std::char_traits<TCHAR>::length(p); p += static_cast<ptrdiff_t>(cch_hour  );
			size_t cch_minute; basic_conv<TCHAR>::to_string(tf.Minute, p, 10); cch_minute = std::char_traits<TCHAR>::length(p); p += static_cast<ptrdiff_t>(cch_minute);
			size_t cch_second; basic_conv<TCHAR>::to_string(tf.Second, p, 10); cch_second = std::char_traits<TCHAR>::length(p); p += static_cast<ptrdiff_t>(cch_second);
			TCHAR zero = buf[0];
			size_t i = cch_zero;
			{ size_t const cch = cch_year  ; buffer.append(4 - cch, zero); buffer.append(&buf[i], cch); i += cch; } buffer.push_back(_T('-'));
			{ size_t const cch = cch_month ; buffer.append(2 - cch, zero); buffer.append(&buf[i], cch); i += cch; } buffer.push_back(_T('-'));
			{ size_t const cch = cch_day   ; buffer.append(2 - cch, zero); buffer.append(&buf[i], cch); i += cch; }
			if (include_time)
			{
				buffer.push_back(_T(' '));
				{ size_t const cch = cch_hour; buffer.append(2 - cch, zero); buffer.append(&buf[i], cch); i += cch; } buffer.push_back(_T(':'));
				{ size_t const cch = cch_minute; buffer.append(2 - cch, zero); buffer.append(&buf[i], cch); i += cch; } buffer.push_back(_T(':'));
				{ size_t const cch = cch_second; buffer.append(2 - cch, zero); buffer.append(&buf[i], cch); i += cch; }
			}
		}
		else
		{
			SYSTEMTIME sysTime =
			{
				static_cast<WORD>(tf.Year),
				static_cast<WORD>(tf.Month),
				static_cast<WORD>(tf.Weekday),
				static_cast<WORD>(tf.Day),
				static_cast<WORD>(tf.Hour),
				static_cast<WORD>(tf.Minute),
				static_cast<WORD>(tf.Second),
				static_cast<WORD>(tf.Milliseconds)
			};
			TCHAR buf[64];
			size_t const buffer_size = sizeof(buf) / sizeof(*buf);
			size_t cch = 0;
			size_t const cchDate = static_cast<size_t>(GetDateFormat(lcid, 0, &sysTime, NULL, &buf[0], static_cast<int>(buffer_size)));
			cch += cchDate - !!cchDate /* null terminator */;
			if (cchDate > 0 && include_time)
			{
				buf[cch++] = _T(' ');
				size_t const cchTime = static_cast<size_t>(GetTimeFormat(lcid, 0, &sysTime, NULL, &buf[cchDate], static_cast<int>(buffer_size - cchDate)));
				cch += cchTime - !!cchTime;
			}
			buffer.append(buf, cch);
		}
	}

	void OnDestroy()
	{
		UnregisterWait(this->hWait);
		this->DeleteNotifyIcon();
		this->iconLoader->clear();
		this->iocp->close();
		this->iocp.reset();
	}

	struct IconLoaderCallback
	{
		CMainDlg *this_;
		std::tvstring path;
		SIZE iconSmallSize, iconLargeSize;
		unsigned long fileAttributes;
		int iItem;

		struct MainThreadCallback
		{
			CMainDlg *this_;
			std::tvstring description, path;
			WTL::CIcon iconSmall, iconLarge;
			int iItem;
			TCHAR szTypeName[80];
			bool operator()()
			{
				WTL::CWaitCursor wait(true, IDC_APPSTARTING);
				std::reverse(path.begin(), path.end());
				IconCache::iterator const cached = this_->cache.find(path);
				std::reverse(path.begin(), path.end());
				if (cached != this_->cache.end())
				{
					_tcscpy(cached->second.szTypeName, this->szTypeName);
					cached->second.description = description;

					if (cached->second.iIconSmall < 0) { cached->second.iIconSmall = this_->imgListSmall.AddIcon(iconSmall); }
					else { this_->imgListSmall.ReplaceIcon(cached->second.iIconSmall, iconSmall); }

					if (cached->second.iIconLarge < 0) { cached->second.iIconLarge = this_->imgListLarge.AddIcon(iconLarge); }
					else { this_->imgListLarge.ReplaceIcon(cached->second.iIconLarge, iconLarge); }

					cached->second.valid = true;
				}

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
				std::tvstring normalizedPath = NormalizePath(path);
				SHFILEINFO shfi = {0};
				std::tvstring description;
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
						{ description = std::tvstring((LPCTSTR)p, uLen); }
					}
				}
#endif
				Handle fileTemp;  // To prevent icon retrieval from changing the file time
				{
					std::tvstring ntpath = _T("\\??\\") + path;
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
					std::tvstring const path_copy(path);
					int const iItem(iItem);
					MainThreadCallback callback = { this_, description, path_copy, iconSmall.Detach(), iconLarge.Detach(), iItem };
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

	int CacheIcon(std::tvstring path, int const iItem, ULONG fileAttributes, long const timestamp)
	{
		remove_path_stream_and_trailing_sep(path);
		std::reverse(path.begin(), path.end());
		IconCache::const_iterator entry = this->cache.find(path);
		if (entry == this->cache.end())
		{
			WTL::CRect rcClient;
			this->lvFiles.GetClientRect(&rcClient);
			size_t max_possible_icons = MulDiv(rcClient.Width(), rcClient.Height(), GetSystemMetrics(SM_CXSMICON) * GetSystemMetrics(SM_CYSMICON));
			size_t current_cache_size = this->cache.size(), max_cache_size = 1 << 10;
			if (rcClient.Height() > 0 && max_cache_size < max_possible_icons)
			{
				max_cache_size = max_possible_icons;
			}
			if (current_cache_size >= 2 * max_cache_size)
			{
				for (IconCache::iterator i = this->cache.begin(); i != this->cache.end(); )
				{
					if (i->second.counter + max_cache_size < current_cache_size)
					{
						this->cache.erase(i++);
					}
					else
					{
						i->second.counter -= current_cache_size - max_cache_size;
						++i;
					}
				}
				for (IconCache::iterator i = this->cache.begin(); i != this->cache.end(); ++i)
				{
					assert(i->second.counter < this->cache.size());
				}
			}
			entry = this->cache.insert(this->cache.end(), IconCache::value_type(path, CacheInfo(this->cache.size())));
		}

		std::reverse(path.begin(), path.end());

		if (!entry->second.valid)
		{
			SIZE iconSmallSize; this->imgListSmall.GetIconSize(iconSmallSize);
			SIZE iconSmallLarge; this->imgListLarge.GetIconSize(iconSmallLarge);

			IconLoaderCallback callback = { this, path, iconSmallSize, iconSmallLarge, fileAttributes, iItem };
			this->iconLoader->add(callback, timestamp);
		}
		return entry->second.iIconSmall;
	}
	
	LRESULT OnMouseWheel(UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		return this->lvFiles.SendMessage(uMsg, wParam, lParam);
	}
	
	static VOID NTAPI WaitCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
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

		this->SetWindowText(this->LoadString(IDS_APPNAME));
		this->menu.Attach(this->GetMenu());
		this->lvFiles.Attach(this->GetDlgItem(IDC_LISTFILES));
		this->btnBrowse.Attach(this->GetDlgItem(IDC_BUTTON_BROWSE));
		this->btnBrowse.SetWindowText(this->LoadString(IDS_BUTTON_BROWSE));
		this->btnOK.Attach(this->GetDlgItem(IDOK));
		this->btnOK.SetWindowText(this->LoadString(IDS_BUTTON_SEARCH));
		this->cmbDrive.Attach(this->GetDlgItem(IDC_LISTVOLUMES));
		this->accel.LoadAccelerators(IDR_ACCELERATOR1);
		this->txtPattern.SubclassWindow(this->GetDlgItem(IDC_EDITFILENAME));
		if (!this->txtPattern)
		{ this->txtPattern.Attach(this->GetDlgItem(IDC_EDITFILENAME)); }
		this->txtPattern.EnsureTrackingMouseHover();
		this->txtPattern.SetCueBannerText(this->LoadString(IDS_SEARCH_PATTERN_BANNER), true);
		WTL::CHeaderCtrl hdr = this->lvFiles.GetHeader();
		{ int const icol = COLUMN_INDEX_NAME             ; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_LEFT , 192, this->LoadString(IDS_COLUMN_NAME_HEADER         )}; this->lvFiles.InsertColumn(icol, &column); }
		{ int const icol = COLUMN_INDEX_PATH             ; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_LEFT , 330, this->LoadString(IDS_COLUMN_PATH_HEADER         )}; this->lvFiles.InsertColumn(icol, &column); }
		{ int const icol = COLUMN_INDEX_SIZE             ; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_RIGHT, 115, this->LoadString(IDS_COLUMN_SIZE_HEADER         )}; this->lvFiles.InsertColumn(icol, &column); }
		{ int const icol = COLUMN_INDEX_SIZE_ON_DISK     ; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_RIGHT, 115, this->LoadString(IDS_COLUMN_SIZE_ON_DISK_HEADER )}; this->lvFiles.InsertColumn(icol, &column); }
		{ int const icol = COLUMN_INDEX_CREATION_TIME    ; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_LEFT ,  86, this->LoadString(IDS_COLUMN_CREATION_TIME_HEADER)}; this->lvFiles.InsertColumn(icol, &column); }
		{ int const icol = COLUMN_INDEX_MODIFICATION_TIME; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_LEFT ,  86, this->LoadString(IDS_COLUMN_WRITE_TIME_HEADER   )}; this->lvFiles.InsertColumn(icol, &column); }
		{ int const icol = COLUMN_INDEX_ACCESS_TIME      ; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_LEFT ,  86, this->LoadString(IDS_COLUMN_ACCESS_TIME_HEADER  )}; this->lvFiles.InsertColumn(icol, &column); }
		{ int const icol = COLUMN_INDEX_DESCENDENTS      ; LVCOLUMN column = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT, LVCFMT_RIGHT,  74, this->LoadString(IDS_COLUMN_DESCENDENTS_HEADER  )}; this->lvFiles.InsertColumn(icol, &column); }

		this->cmbDrive.SetCueBannerText(this->LoadString(IDS_SEARCH_VOLUME_BANNER));
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
		this->lvFiles.SetExtendedListViewStyle(LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP | 0x80000000 /*LVS_EX_COLUMNOVERFLOW*/);
		{
			MENUITEMINFO mii = { sizeof(mii), MIIM_STATE };
			this->menu.GetMenuItemInfo(ID_VIEW_LARGEICONS, FALSE, &mii);
			this->small_image_list((mii.fState & MFS_CHECKED) ? this->imgListLarge : this->imgListSmall);
			this->lvFiles.SetImageList(this->imgListLarge, LVSIL_NORMAL);
			this->lvFiles.SetImageList(this->imgListExtraLarge, LVSIL_NORMAL);
		}
		this->SendMessage(WM_COMMAND, ID_VIEW_FITCOLUMNSTOWINDOW);

		this->statusbar = CreateStatusWindow(WS_CHILD | SBT_TOOLTIPS | WS_VISIBLE, NULL, *this, IDC_STATUS_BAR);
		int const rcStatusPaneWidths[] = { 360, -1 };
		this->statusbar.SetParts(sizeof(rcStatusPaneWidths) / sizeof(*rcStatusPaneWidths), const_cast<int *>(rcStatusPaneWidths));
		this->statusbar.SetText(0, this->LoadString(IDS_STATUS_DEFAULT));
		WTL::CRect rcStatusPane1; this->statusbar.GetRect(1, &rcStatusPane1);
		//this->statusbarProgress.Create(this->statusbar, rcStatusPane1, NULL, WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 0);
		//this->statusbarProgress.SetRange(0, INT_MAX);
		//this->statusbarProgress.SetPos(INT_MAX / 2);
		WTL::CRect clientRect;
		if (this->lvFiles.GetClientRect(&clientRect))
		{
			clientRect.bottom -= rcStatusPane1.Height();
			this->lvFiles.ResizeClient(clientRect.Width(), clientRect.Height(), FALSE);
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

		this->cmbDrive.SetCurSel(this->cmbDrive.AddString(this->LoadString(IDS_SEARCH_VOLUME_ALL)));
		for (size_t j = 0; j != path_names.size(); ++j)
		{
			this->cmbDrive.AddString(path_names[j].c_str());
		}
		return TRUE;
	}

	struct ResultCompareBase
	{
		~ResultCompareBase()
		{
			dlg->SetProgress(denominator, denominator);
			dlg->Flush();
		}
		struct swapper_type
		{
			ResultCompareBase *me;
			swapper_type(ResultCompareBase *const me) : me(me) { }
			void operator()(SearchResult &a, SearchResult &b)
			{
				SearchResult *const real_b = &a == &b ? NULL : &b;
				me->check_cancelled(&a, real_b);
				if (real_b)
				{
					using std::swap; swap(a, b);
				}
			}
		};
#pragma pack(push, 1)
		struct result_type
		{
			typedef unsigned short first_type;
			typedef unsigned long long second_type;
			first_type first;
			second_type second;
			result_type() : first(), second() { }
			result_type(first_type const &first, second_type const &second) : first(first), second(second) { }
			bool operator< (result_type const &other) const { return this->first < other.first || (!(other.first < this->first) && this->second < other.second); }
		};
#pragma pack(pop)
		typedef NtfsIndex Index;
		CMainDlg *const this_;
		std::vector<Index::ParentIterator::value_type> *temp;
		std::vector<unsigned long long> *temp_keys;
		unsigned char variation;
		CProgressDialog *dlg;
		unsigned long long denominator;
		unsigned long long numerator;
		std::tvstring buffer;
		void check_cancelled(SearchResult const *const a = NULL, SearchResult const *const b = NULL)
		{
			++numerator;
			if (dlg)
			{
				unsigned long const tnow = GetTickCount();
				if (dlg->ShouldUpdate(tnow))
				{
					if (dlg->HasUserCancelled(tnow))
					{
						throw CStructured_Exception(ERROR_CANCELLED, NULL);
					}
					buffer.clear();
					if (a) { Index const *const p = this_->results.ith_index(a->index())->unvolatile(); buffer += p->root_path(); p->get_path(a->key(), buffer, false); }
					if (a && b)
					{
						buffer.push_back(_T('\r'));
						buffer.push_back(_T('\n'));
					}
					if (b) { Index const *const p = this_->results.ith_index(b->index())->unvolatile(); buffer += p->root_path(); p->get_path(b->key(), buffer, false); }
					dlg->SetProgressText(buffer);
					dlg->SetProgress(numerator, numerator <= denominator ? denominator : 0);
					dlg->Flush();
				}
			}
		}
		swapper_type swapper() { return this; };
	};
	template<int SubItem>
	struct ResultCompare
	{
		ResultCompareBase *base;
		ResultCompare(ResultCompareBase *const base) : base(base) { }
		typedef ResultCompareBase::Index Index;
		typedef ResultCompareBase::result_type result_type;
		typedef unsigned char word_type;
		typedef word_type value_type;
		result_type operator()(Results::value_type const &v) const
		{
			base->check_cancelled(&v);
			result_type result = result_type();
			result.first = (base->variation & 0x2) ? static_cast<typename result_type::second_type>(~v.depth()) : typename result_type::second_type();
			NtfsIndex const *const p = base->this_->results.ith_index(v.index())->unvolatile();
			switch (SubItem)
			{
			case COLUMN_INDEX_SIZE:
			case COLUMN_INDEX_SIZE_ON_DISK:
			case COLUMN_INDEX_DESCENDENTS:
			{
				Index::size_info const &info = p->get_sizes(v.key());
				switch (SubItem)
				{
				case COLUMN_INDEX_SIZE: result.second = info.length; break;
				case COLUMN_INDEX_SIZE_ON_DISK: result.second = (base->variation & 0x1) ? info.bulkiness : info.allocated; break;
				case COLUMN_INDEX_DESCENDENTS: result.second = info.treesize; break;
				}
				break;
			}
			case COLUMN_INDEX_CREATION_TIME:
			case COLUMN_INDEX_MODIFICATION_TIME:
			case COLUMN_INDEX_ACCESS_TIME:
			{
				Index::standard_info const &info = p->get_stdinfo(v.key().frs());
				switch (SubItem)
				{
				case COLUMN_INDEX_CREATION_TIME: result.second = info.created; break;
				case COLUMN_INDEX_MODIFICATION_TIME: result.second = info.written; break;
				case COLUMN_INDEX_ACCESS_TIME: result.second = info.accessed; break;
				}
				break;
			}
			}
			return result;
		}
		int precompare(Results::value_type const &a, Results::value_type const &b) const
		{
			int r = 0;
			if (base->variation & 0x2)
			{
				size_t const
					a_depth = a.depth(),
					b_depth = b.depth();
				if (a_depth < b_depth)
				{
					r = -1;
				}
				else if (b_depth < a_depth)
				{
					r = +1;
				}
			}
			return r;
		}
		typedef result_type first_argument_type, second_argument_type;
		bool operator()(first_argument_type const &a, second_argument_type const &b) const
		{
			base->check_cancelled(NULL, NULL);
			return a < b;
		}
		bool operator()(Results::value_type const &a, Results::value_type const &b) const
		{
			base->check_cancelled(&a, &b);
			int const precomp = this->precompare(a, b);
			bool less;
			if (precomp < 0)
			{
				less = true;
			}
			else
			{
				stdext::remove_cv<Index>::type const
					*index1 = base->this_->results.ith_index(a.index())->unvolatile(),
					*index2 = base->this_->results.ith_index(b.index())->unvolatile();
				switch (SubItem)
				{
				case COLUMN_INDEX_NAME:
				case COLUMN_INDEX_PATH:
				{
					bool const name_only = SubItem == COLUMN_INDEX_NAME;
					int c; c = 0;
					if (!name_only)
					{
						Index::ParentIterator::value_type_compare comp;
						std::tvstring const &r1 = index1->root_path(), &r2 = index2->root_path();
						Index::ParentIterator::value_type
							v1 = { r1.data() },
							v2 = { r2.data() };
						v1.second = r1.size(); v1.ascii = false;
						v2.second = r2.size(); v2.ascii = false;
						if (comp(v1, v2))
						{
							c = -1;
						}
						else if (comp(v2, v1))
						{
							c = +1;
						}
					}
					if (c != 0)
					{
						less = c < 0;
					}
					else
					{
						Index::ParentIterator i1(index1, a.key()), i2(index2, b.key());
						unsigned short n1, n2;
						if (!name_only)
						{
							Index::ParentIterator j1(index1, a.key()), j2(index2, b.key());
							{
								unsigned short const a_depth = a.depth(), b_depth = b.depth();
								Index::ParentIterator *const ideeper = &(a_depth < b_depth ? j2 : j1);
								for (unsigned short depthdiff = a_depth < b_depth ? b_depth - a_depth : a_depth - b_depth; depthdiff; --depthdiff)
								{
									++*ideeper;
								}
							}
							for (;;)
							{
								if (j1 == j2)
								{
									break;
								}
								int changed = 0;
								if (!j1.empty()) { ++j1; ++changed; }
								if (!j2.empty()) { ++j2; ++changed; }
								if (!changed) { break; }
							}
							n1 = j1.icomponent();
							n2 = j2.icomponent();
						}
						else
						{
							n1 = USHRT_MAX;
							n2 = USHRT_MAX;
						}
						size_t itemp = 0;
						base->temp->resize((1 + USHRT_MAX) * 2);
						while (i1.icomponent() != n1 && i1.next() && !(name_only && i1.icomponent()))
						{
							(*base->temp)[itemp++] = *i1;
						}
						size_t const len1 = itemp;
						while (i2.icomponent() != n2 && i2.next() && !(name_only && i2.icomponent()))
						{
							(*base->temp)[itemp++] = *i2;
						}
						// Here we rely on the path structure, assuming that components are broken down on well-defined boundaries.
						// This would NOT work with arbitrary substrings.
						less = std::lexicographical_compare(
							base->temp->rend() - static_cast<ptrdiff_t>(len1), base->temp->rend(),
							base->temp->rend() - static_cast<ptrdiff_t>(itemp), base->temp->rend() - static_cast<ptrdiff_t>(len1),
							Index::ParentIterator::value_type_compare());
					}
					break;
				}
				default:
					less = this->operator()(this->operator()(a), this->operator()(b));
					break;
				}
			}
			return less;
		}
	};

	LRESULT OnFilesListColumnClick(LPNMHDR pnmh)
	{
		LPNM_LISTVIEW pLV = (LPNM_LISTVIEW)pnmh;
		WTL::CHeaderCtrl header = this->lvFiles.GetHeader();
		bool const shift_pressed = GetKeyState(VK_SHIFT) < 0;
		bool const alt_pressed = GetKeyState(VK_MENU) < 0;
		unsigned char const variation = (alt_pressed ? 1U : 0U) | ((shift_pressed ? 1U : 0U) << 1);
		bool cancelled = false;
		this->lvFiles.SetItemState(-1, 0, LVNI_SELECTED);
		int const subitem = pLV->iSubItem;
		bool const same_key_as_last = this->last_sort.column == subitem + 1 && this->last_sort.variation == variation;
		bool const reversed = same_key_as_last && this->last_sort.counter % 2;
		int resulting_sort = 0;
		if ((this->lvFiles.GetStyle() & LVS_OWNERDATA) != 0)
		{
			try
			{
				WTL::CWaitCursor const wait_cursor;
				CProgressDialog dlg(*this);
				TCHAR buf[0x100];
				safe_stprintf(buf, this->LoadString(IDS_STATUS_SORTING_RESULTS), static_cast<std::tstring>(nformat_ui(this->results.size())).c_str());
				dlg.SetProgressTitle(buf);
				if (!dlg.HasUserCancelled())
				{
					this->statusbar.SetText(0, buf);
					LockedResults locked_results(*this);
					for (size_t i = 0; i != this->results.size(); ++i) { locked_results(i); }
					std::vector<NtfsIndex::ParentIterator::value_type> temp;
					std::vector<unsigned long long> temp_keys;
					Results::iterator const begin = this->results.begin(), end = this->results.end();
					ptrdiff_t const item_count = end - begin;
					using std::ceil;
					ResultCompareBase compare = { this, &temp, &temp_keys, variation, &dlg, static_cast<unsigned long long>((ceil(log(static_cast<double>(item_count)) + 1) * item_count * 1.5)) };
					clock_t const tstart = clock();
					int proposed_sort = 0;
					bool pretend_reversed;
					switch (subitem)
					{
#define X(Column) case Column: { pretend_reversed = !reversed; proposed_sort = pretend_reversed ? +1 : -1; ResultCompare<Column> comp(&compare); if (is_sorted_ex(begin, end, comp, pretend_reversed)) { std::reverse(begin, end); } else { std::stable_sort(begin, end, comp); if (!pretend_reversed) { std::reverse(begin, end); } } } break
						X(COLUMN_INDEX_NAME);
						X(COLUMN_INDEX_PATH);
#undef  X
#define X(Column) case Column: { pretend_reversed =  reversed; proposed_sort = pretend_reversed ? +1 : -1; ResultCompare<Column> comp(&compare); if (is_sorted_ex(begin, end, comp, pretend_reversed)) { std::reverse(begin, end); } else { stable_sort_by_key(begin, end, comp, compare.swapper()); if (!pretend_reversed) { std::reverse(begin, end); } } } break
						X(COLUMN_INDEX_SIZE);
						X(COLUMN_INDEX_SIZE_ON_DISK);
						X(COLUMN_INDEX_DESCENDENTS);
						X(COLUMN_INDEX_CREATION_TIME);
						X(COLUMN_INDEX_MODIFICATION_TIME);
						X(COLUMN_INDEX_ACCESS_TIME);
#undef  X
					}
					resulting_sort = proposed_sort;
					clock_t const tend = clock();
					safe_stprintf(buf, this->LoadString(IDS_STATUS_SORTED_RESULTS), static_cast<std::tstring>(nformat_ui(this->results.size())).c_str(), (tend - tstart) * 1.0 / CLOCKS_PER_SEC);
					this->statusbar.SetText(0, buf);
				}
			}
			catch (CStructured_Exception &ex)
			{
				cancelled = true;
				if (ex.GetSENumber() != ERROR_CANCELLED)
				{
					throw;
				}
				this->statusbar.SetText(0, _T(""));
			}
			this->SetItemCount(this->lvFiles.GetItemCount());
		}
		if (!cancelled)
		{
			this->last_sort.counter = same_key_as_last ? this->last_sort.counter + 1 : 1;
			this->last_sort.column = subitem + 1;
			this->last_sort.variation = variation;
		}
		HDITEM hditem = { HDI_FORMAT };
		if (header.GetItem(subitem, &hditem))
		{
			hditem.fmt = (hditem.fmt & ~(HDF_SORTUP | HDF_SORTDOWN)) | (resulting_sort < 0 ? HDF_SORTDOWN : resulting_sort > 0 ? HDF_SORTUP : 0);
			header.SetItem(subitem, &hditem);
		}
		return TRUE;
	}

	BOOL SetItemCount(int n)
	{
		BOOL result = this->lvFiles.SetItemCount(n);
		if (result)
		{
			WTL::CHeaderCtrl header = this->lvFiles.GetHeader();
			for (int subitem = header.GetItemCount(); subitem > 0 && ((void)--subitem, true); )
			{
				HDITEM hditem = { HDI_FORMAT };
				if (header.GetItem(subitem, &hditem))
				{
					hditem.fmt = (hditem.fmt & ~(HDF_SORTUP | HDF_SORTDOWN));
					header.SetItem(subitem, &hditem);
				}
			}
			this->lvFiles.UpdateWindow();
		}
		return result;
	}

	void clear(bool const clear_cache, bool const deallocate_buffers)
	{
		WTL::CWaitCursor wait(this->lvFiles.GetItemCount() > 0, IDC_APPSTARTING);
		this->SetItemCount(0);
		this->results.clear();
		if (deallocate_buffers) { Results().swap(this->results); }
		this->last_sort.column = 0;
		this->last_sort.variation = 0;
		this->last_sort.counter = 0;
		if (clear_cache)
		{
			this->cache.clear();
			this->cached_column_header_widths.clear();
		}
	}

	void Search()
	{
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
		bool const is_path_pattern = is_regex || ~pattern.find(_T('\\')) || ~pattern.find(_T("**"));
		bool const is_stream_pattern = is_regex || ~pattern.find(_T(':'));
		bool const requires_root_path_match = is_path_pattern && !pattern.empty() && !is_regex && *pattern.begin() != _T('*') && *pattern.begin() != _T('?');
		if (!is_path_pattern && !~pattern.find(_T('*')) && !~pattern.find(_T('?'))) { pattern.insert(pattern.begin(), _T('*')); pattern.insert(pattern.begin(), _T('*')); pattern.insert(pattern.end(), _T('*')); pattern.insert(pattern.end(), _T('*')); }
		string_matcher matcher;
		try
		{
			string_matcher(is_regex ? string_matcher::pattern_regex : is_path_pattern ? string_matcher::pattern_globstar : string_matcher::pattern_glob, string_matcher::pattern_option_case_insensitive, pattern.data(), pattern.size()).swap(matcher);
		}
		catch (std::invalid_argument &ex)
		{
			RefCountedCString error = this->LoadString(IDS_INVALID_PATTERN);
			error += _T("\r\n");
			error += ex.what();
			this->MessageBox(error, this->LoadString(IDS_ERROR_TITLE), MB_ICONERROR);
			return;
		}
		bool preallocate = false;
		bool const shift_pressed = GetKeyState(VK_SHIFT) < 0;
		bool const control_pressed = GetKeyState(VK_CONTROL) < 0;
		int const selected = this->cmbDrive.GetCurSel();
		if (selected != 0)
		{
			intrusive_ptr<NtfsIndex> const p = static_cast<NtfsIndex *>(this->cmbDrive.GetItemDataPtr(selected));
			if (!p || p->failed())
			{
				this->MessageBox(this->LoadString(IDS_INVALID_NTFS_VOLUME_BODY), this->LoadString(IDS_ERROR_TITLE), MB_OK | MB_ICONERROR);
				return;
			}
		}
		this->clear(false, false);
		WTL::CWaitCursor const wait_cursor;
		CProgressDialog dlg(*this);
		dlg.SetProgressTitle(this->LoadString(IDS_SEARCHING_TITLE));
		if (dlg.HasUserCancelled()) { return; }
		typedef std::tvstring::const_iterator It;
		using std::ceil;
		clock_t const tstart = clock();
		std::vector<uintptr_t> wait_handles;
		typedef NtfsIndex const volatile *index_pointer;
		std::vector<index_pointer> nonwait_indices, wait_indices, initial_wait_indices;
		// TODO: What if they exceed maximum wait objects?
		bool any_io_pending = false;
		size_t expected_results = 0;
		size_t overall_progress_numerator = 0, overall_progress_denominator = 0;
		for (int ii = this->cmbDrive.GetCount(); ii > 0 && ((void)--ii, true); )
		{
			if (intrusive_ptr<NtfsIndex> const p = static_cast<NtfsIndex *>(this->cmbDrive.GetItemDataPtr(ii)))
			{
				bool wait = false;
				if (selected == ii || selected == 0)
				{
					std::tvstring const root_path = p->root_path();
					if (!requires_root_path_match || pattern.size() >= root_path.size() && std::equal(root_path.begin(), root_path.end(), pattern.begin()))
					{
						wait = true;
						wait_handles.push_back(p->finished_event());
						wait_indices.push_back(p.get());
						expected_results += p->expected_records();
						size_t const records_so_far = p->records_so_far();
						any_io_pending |= records_so_far < p->mft_capacity;
						overall_progress_denominator += p->mft_capacity * 2;
					}
				}
				if (!wait)
				{
					nonwait_indices.push_back(p.get());
				}
			}
		}
		initial_wait_indices = wait_indices;
		if (!any_io_pending) { overall_progress_denominator /= 2; }
		if (any_io_pending) { dlg.ForceShow(); }
		if (preallocate)
		{
			try { this->results.reserve(this->results.size() + expected_results + expected_results / 8); }
			catch (std::bad_alloc &) { }
		}
		std::vector<IoPriority> set_priorities(nonwait_indices.size() + wait_indices.size());
		for (size_t i = 0; i != nonwait_indices.size(); ++i)
		{
			IoPriority(reinterpret_cast<uintptr_t>(nonwait_indices[i]->volume()), winnt::IoPriorityLow).swap(set_priorities.at(i));
		}
		for (size_t i = 0; i != wait_indices.size(); ++i)
		{
			IoPriority(reinterpret_cast<uintptr_t>(wait_indices[i]->volume()), winnt::IoPriorityLow).swap(set_priorities.at(nonwait_indices.size() + i));
		}
		IoPriority set_priority;
		Speed::second_type initial_time = Speed::second_type();
		Speed::first_type initial_average_amount = Speed::first_type();
		std::vector<Results> results_at_depths;
		results_at_depths.reserve(std::numeric_limits<unsigned short>::max() + 1);
		while (!dlg.HasUserCancelled() && !wait_handles.empty())
		{
			if (uintptr_t const volume = reinterpret_cast<uintptr_t>(wait_indices.at(0)->volume()))
			{
				if (set_priority.volume() != volume)
				{
					IoPriority(volume, winnt::IoPriorityNormal).swap(set_priority);
				}
			}
			unsigned long const wait_result = dlg.WaitMessageLoop(wait_handles.empty() ? NULL : &*wait_handles.begin(), wait_handles.size());
			if (wait_result == WAIT_TIMEOUT)
			{
				if (dlg.ShouldUpdate())
				{
					basic_fast_ostringstream<TCHAR> ss;
					ss << this->LoadString(IDS_TEXT_READING_FILE_TABLES) << this->LoadString(IDS_TEXT_SPACE);
					bool any = false;
					unsigned long long temp_overall_progress_numerator = overall_progress_numerator;
					for (size_t i = 0; i != wait_indices.size(); ++i)
					{
						index_pointer const j = wait_indices[i];
						size_t const records_so_far = j->records_so_far();
						temp_overall_progress_numerator += records_so_far;
						if (records_so_far != j->mft_capacity)
						{
							if (any) { ss << this->LoadString(IDS_TEXT_COMMA) << this->LoadString(IDS_TEXT_SPACE); }
							else { ss << this->LoadString(IDS_TEXT_SPACE); }
							ss << j->root_path() << this->LoadString(IDS_TEXT_SPACE) << this->LoadString(IDS_TEXT_PAREN_OPEN) << nformat_ui(j->records_so_far());
							// TODO: 'of' _really_ isn't a good thing to localize in isolation..
							ss << this->LoadString(IDS_TEXT_SPACE) << this->LoadString(IDS_TEXT_OF) << this->LoadString(IDS_TEXT_SPACE);
							// These MUST be separate statements since nformat_ui is used twice
							ss << nformat_ui(static_cast<unsigned int const &>(j->mft_capacity)) << this->LoadString(IDS_TEXT_PAREN_CLOSE);
							any = true;
						}
					}
					bool const initial_speed = !initial_average_amount;
					Speed recent_speed, average_speed;
					for (size_t i = 0; i != initial_wait_indices.size(); ++i)
					{
						index_pointer const j = initial_wait_indices[i];
						{
							Speed const speed = j->speed();
							average_speed.first += speed.first;
							average_speed.second += speed.second;
							if (initial_speed)
							{
								initial_average_amount += speed.first;
							}
						}
					}
					clock_t const tnow = clock();
					if (initial_speed)
					{
						initial_time = tnow;
					}
					if (average_speed.first > initial_average_amount)
					{
						ss << _T('\n');
						ss << this->LoadString(IDS_TEXT_AVERAGE_SPEED) << this->LoadString(IDS_TEXT_COLON) << this->LoadString(IDS_TEXT_SPACE)
							<< nformat_ui(static_cast<size_t>((average_speed.first - initial_average_amount) * static_cast<double>(CLOCKS_PER_SEC) / ((tnow != initial_time ? tnow - initial_time : 1) * (1ULL << 20))))
							<< this->LoadString(IDS_TEXT_SPACE) << this->LoadString(IDS_TEXT_MIB_S);
						ss << this->LoadString(IDS_TEXT_SPACE);
						// These MUST be separate statements since nformat_ui is used twice
						ss << this->LoadString(IDS_TEXT_PAREN_OPEN) << nformat_ui(average_speed.first / (1 << 20)) << this->LoadString(IDS_TEXT_SPACE) << this->LoadString(IDS_TEXT_MIB_READ) << this->LoadString(IDS_TEXT_PAREN_CLOSE);
					}
					std::tstring const text = ss.str();
					dlg.SetProgressText(text);
					dlg.SetProgress(static_cast<long long>(temp_overall_progress_numerator), static_cast<long long>(overall_progress_denominator));
					dlg.Flush();
				}
			}
			else
			{
				if (wait_result < wait_handles.size())
				{
					index_pointer const i = wait_indices[wait_result];
					size_t current_progress_numerator = 0;
					size_t const current_progress_denominator = i->total_names_and_streams();
					std::tvstring root_path = i->root_path();
					std::tvstring current_path = root_path;
					while (!current_path.empty() && *(current_path.end() - 1) == _T('\\')) { current_path.erase(current_path.end() - 1); }
					try
					{
						lock(i)->matches([&dlg, &results_at_depths, &root_path, shift_pressed, this, i, &wait_indices, any_io_pending,
							&current_progress_numerator, current_progress_denominator,
							overall_progress_numerator, overall_progress_denominator
							, &matcher
						](TCHAR const *const name, size_t const name_length, bool const ascii, NtfsIndex::key_type const &key, size_t const depth)
						{
							unsigned long const now = GetTickCount();
							if (dlg.ShouldUpdate(now) || current_progress_denominator - current_progress_numerator <= 1)
							{
								if (dlg.HasUserCancelled(now)) { throw CStructured_Exception(ERROR_CANCELLED, NULL); }
								// this->lvFiles.SetItemCountEx(static_cast<int>(this->results.size()), 0), this->lvFiles.UpdateWindow();
								size_t temp_overall_progress_numerator = overall_progress_numerator;
								if (any_io_pending)
								{
									for (size_t k = 0; k != wait_indices.size(); ++k)
									{
										index_pointer const j = wait_indices[k];
										size_t const records_so_far = j->records_so_far();
										temp_overall_progress_numerator += records_so_far;
									}
								}
								std::tvstring text(0x100 + root_path.size(), _T('\0'));
								text.resize(static_cast<size_t>(_sntprintf(&*text.begin(), text.size(), _T("%s%s%.*s%s%s%s%s%s%s%s%s%s\r\n"),
									this->LoadString(IDS_TEXT_SEARCHING).c_str(),
									this->LoadString(IDS_TEXT_SPACE).c_str(),
									static_cast<int>(root_path.size()), root_path.c_str(),
									this->LoadString(IDS_TEXT_SPACE).c_str(),
									this->LoadString(IDS_TEXT_PAREN_OPEN).c_str(),
									static_cast<std::tstring>(nformat_ui(current_progress_numerator)).c_str(),
									this->LoadString(IDS_TEXT_SPACE).c_str(),
									this->LoadString(IDS_TEXT_OF).c_str(),
									this->LoadString(IDS_TEXT_SPACE).c_str(),
									static_cast<std::tstring>(nformat_ui(current_progress_denominator)).c_str(),
									this->LoadString(IDS_TEXT_PAREN_CLOSE).c_str(),
									this->LoadString(IDS_TEXT_ELLIPSIS).c_str())));
								if (name_length) { append_directional(text, name, name_length, ascii ? -1 : 0); }
								dlg.SetProgressText(text);
								dlg.SetProgress(temp_overall_progress_numerator + static_cast<unsigned long long>(i->mft_capacity) * static_cast<unsigned long long>(current_progress_numerator) / static_cast<unsigned long long>(current_progress_denominator), static_cast<long long>(overall_progress_denominator));
								dlg.Flush();
							}
							++current_progress_numerator;
							if (current_progress_numerator > current_progress_denominator)
							{
								throw std::logic_error("current_progress_numerator > current_progress_denominator");
							}
							TCHAR const *const path_begin = name;
							bool const match = ascii
								? matcher.is_match(static_cast<char const *>(static_cast<void const *>(path_begin)), name_length)
								: matcher.is_match(path_begin, name_length);
							if (match)
							{
								unsigned short const depth2 = static_cast<unsigned short>(depth * 2U) /* dividing by 2 later should not mess up the actual depths; it should only affect files vs. directory sub-depths */;
								if (shift_pressed)
								{
									if (depth2 >= results_at_depths.size()) { results_at_depths.resize(depth2 + 1); }
									results_at_depths[depth2].push_back(i, Results::value_type(key, depth2));
								}
								else { this->results.push_back(i, Results::value_type(key, depth2)); }
							}
						}, current_path, is_path_pattern, is_stream_pattern, control_pressed);
					}
					catch (CStructured_Exception &ex)
					{
						if (ex.GetSENumber() != ERROR_CANCELLED) { throw; }
					}
					if (any_io_pending) { overall_progress_numerator += i->mft_capacity; }
					if (current_progress_denominator) { overall_progress_numerator += static_cast<size_t>(static_cast<unsigned long long>(i->mft_capacity) * static_cast<unsigned long long>(current_progress_numerator) / static_cast<unsigned long long>(current_progress_denominator)); }
				}
				wait_indices.erase(wait_indices.begin() + static_cast<ptrdiff_t>(wait_result));
				wait_handles.erase(wait_handles.begin() + static_cast<ptrdiff_t>(wait_result));
			}
		}
		{
			size_t size_to_reserve = 0;
			for (size_t j = 0; j != results_at_depths.size(); ++j)
			{
				size_to_reserve += results_at_depths[j].size();
			}
			this->results.reserve(this->results.size() + size_to_reserve);
			for (size_t j = results_at_depths.size(); j != 0 && ((void)--j, true); )
			{
				Results const &results_at_depth = results_at_depths[j];
				for (size_t i = results_at_depth.size(); i != 0 && ((void)--i, true); )
				{
					this->results.push_back(results_at_depth.item_index(i), results_at_depth[i]);
				}
			}
			this->SetItemCount(static_cast<int>(this->results.size()));
		}
		clock_t const tend = clock();
		TCHAR buf[0x100];
		safe_stprintf(buf, this->LoadString(IDS_STATUS_FOUND_RESULTS), static_cast<std::tstring>(nformat_ui(this->results.size())).c_str(), (tend - tstart) * 1.0 / CLOCKS_PER_SEC);
		this->statusbar.SetText(0, buf);
	}

	void OnBrowse(UINT /*uNotifyCode*/, int /*nID*/, HWND /*hWnd*/)
	{
		TCHAR path[MAX_PATH];
		BROWSEINFO info = { this->m_hWnd, NULL, path, this->LoadString(IDS_BROWSE_BODY), BIF_NONEWFOLDERBUTTON | BIF_USENEWUI | BIF_RETURNONLYFSDIRS | BIF_DONTGOBELOWDOMAIN };
		if (LPITEMIDLIST const pidl = SHBrowseForFolder(&info))
		{
			bool const success = !!SHGetPathFromIDList(pidl, path);
			ILFree(pidl);
			if (success)
			{
				this->txtPattern.SetWindowText((std::tstring(path) + getdirsep() + _T("*")).c_str());
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

	void append_selected_indices(std::vector<size_t> &result) const
	{
		__declspec(thread) static void *s_hook;
		struct Hooked
		{
			void *old_s_hook;
			HWND prev_hwnd;
			ATOM prev_atom;
			HANDLE prev_result;
			Hook_NtUserGetProp::type *NtUserGetProp_old;
			Hook_NtUserSetProp::type *NtUserSetProp_old;
			Hooked() : old_s_hook(s_hook), prev_hwnd(), prev_atom(), prev_result()
			{
				s_hook = this;
				this->NtUserGetProp_old = Hook_NtUserGetProp::thread(NtUserGetProp);
				this->NtUserSetProp_old = Hook_NtUserSetProp::thread(NtUserSetProp);
			}
			~Hooked()
			{
				Hook_NtUserSetProp::thread(this->NtUserSetProp_old);
				Hook_NtUserGetProp::thread(this->NtUserGetProp_old);
				s_hook = old_s_hook;
			}
			static HANDLE __stdcall NtUserGetProp(HWND hWnd, ATOM PropId)
			{
				Hooked *const hook = static_cast<Hooked *>(s_hook);
				if (hook->prev_hwnd != hWnd || hook->prev_atom != PropId)
				{
					hook->prev_result = Hook::base(hook_NtUserGetProp)(hWnd, PropId);
					hook->prev_hwnd = hWnd;
					hook->prev_atom = PropId;
				}
				return hook->prev_result;
			}
			static BOOL __stdcall NtUserSetProp(HWND hWnd, ATOM PropId, HANDLE value)
			{
				Hooked *const hook = static_cast<Hooked *>(s_hook);
				BOOL const result = Hook::thread(hook_NtUserSetProp)(hWnd, PropId, value);
				if (result && hook->prev_hwnd == hWnd && hook->prev_atom == PropId)
				{
					hook->prev_result = value;
				}
				return result;
			}
		} NtUserProp_hook;
		result.reserve(result.size() + static_cast<size_t>(this->lvFiles.GetSelectedCount()));
		WNDPROC const lvFiles_wndproc = reinterpret_cast<WNDPROC>(::GetWindowLongPtr(this->lvFiles.m_hWnd, GWLP_WNDPROC));
		for (int i = -1;;)
		{
			i = static_cast<int>(lvFiles_wndproc(this->lvFiles.m_hWnd, LVM_GETNEXTITEM, i, MAKELPARAM(LVNI_SELECTED, 0)));
			// i = this->lvFiles.GetNextItem(i, LVNI_SELECTED);
			if (i < 0) { break; }
			result.push_back(static_cast<size_t>(i));
		}
	}

	LRESULT OnContextMenu(UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		WTL::CWaitCursor wait;
		(void)uMsg;
		LRESULT result = 0;
		POINT point = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
		if ((HWND)wParam == this->lvFiles)
		{
			std::vector<size_t> indices;
			int index;
			if (point.x == -1 && point.y == -1)
			{
				index = this->lvFiles.GetSelectedIndex();
				if (index >= 0)
				{
					RECT bounds = {};
					this->lvFiles.GetItemRect(index, &bounds, LVIR_SELECTBOUNDS);
					point.x = bounds.left;
					point.y = bounds.top;
					this->lvFiles.MapWindowPoints(NULL, &point, 1);
					indices.push_back(static_cast<size_t>(index));
				}
			}
			else
			{
				POINT clientPoint = point;
				::MapWindowPoints(NULL, this->lvFiles, &clientPoint, 1);
				index = this->lvFiles.HitTest(clientPoint, 0);
				if (index >= 0)
				{
					this->append_selected_indices(indices);
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

	class LockedResults
	{
		CMainDlg *me;
		std::vector<lock_guard<mutex> > indices_locks;  // this is to permit us to call unvolatile() below
	public:
		explicit LockedResults(CMainDlg &me) : me(&me) { }
		void operator()(size_t const index)
		{
			mutex *const m = &me->results.item_index(index)->get_mutex();
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
	};

	void RightClick(std::vector<size_t> const &indices, POINT const &point, int const focused)
	{
		LockedResults locked_results(*this);
		std::for_each(indices.begin(), indices.end(), locked_results);
		HRESULT volatile hr = S_OK;
		UINT const minID = 1000;
		WTL::CMenu menu;
		menu.CreatePopupMenu();
		ATL::CComPtr<IContextMenu> contextMenu;
		std::auto_ptr<std::pair<std::pair<CShellItemIDList, ATL::CComPtr<IShellFolder> >, std::vector<CShellItemIDList> > > p(
			new std::pair<std::pair<CShellItemIDList, ATL::CComPtr<IShellFolder> >, std::vector<CShellItemIDList> >());
		p->second.reserve(indices.size());  // REQUIRED, to avoid copying CShellItemIDList objects (they're not copyable!)
		if (indices.size() <= (1 << 10))  // if not too many files... otherwise the shell context menu this will take a long time
		{
			SFGAOF sfgao = 0;
			std::tvstring common_ancestor_path;
			std::tvstring path;
			for (size_t i = 0; i < indices.size(); ++i)
			{
				size_t const iresult = indices[i];
				NtfsIndex const *const index = this->results.item_index(iresult)->unvolatile() /* we are allowed to do this because the indices are locked */;
				path = index->root_path();
				if (index->get_path(this->results[iresult].key(), path, false))
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
		}
		unsigned int ninserted = 0;
		UINT const
			openContainingFolderId = minID - 1,
			fileIdId = minID - 2,
			copyId = minID - 3,
			copyPathId = minID - 4,
			copyTableId = minID - 5,
			dumpId = minID - 6;

		if (indices.size() == 1)
		{
			MENUITEMINFO mii2 = { sizeof(mii2), MIIM_ID | MIIM_STRING | MIIM_STATE, MFT_STRING, MFS_ENABLED, openContainingFolderId, NULL, NULL, NULL, NULL, this->LoadString(IDS_MENU_OPEN_CONTAINING_FOLDER) };
			menu.InsertMenuItem(ninserted++, TRUE, &mii2);

			if (false) { menu.SetMenuDefaultItem(openContainingFolderId, FALSE); }
		}
		if (0 <= focused && static_cast<size_t>(focused) < this->results.size())
		{
			{
				RefCountedCString text = this->LoadString(IDS_MENU_FILE_NUMBER);
				text += static_cast<std::tstring>(nformat_ui(this->results[static_cast<size_t>(focused)].key().frs())).c_str();
				MENUITEMINFO mii = { sizeof(mii), MIIM_ID | MIIM_STRING | MIIM_STATE, MFT_STRING, MFS_DISABLED, fileIdId, NULL, NULL, NULL, NULL, text };
				menu.InsertMenuItem(ninserted++, TRUE, &mii);
			}
			{
				MENUITEMINFO mii = { sizeof(mii), MIIM_ID | MIIM_STRING | MIIM_STATE, MFT_STRING, 0, copyId, NULL, NULL, NULL, NULL, this->LoadString(IDS_MENU_COPY) };
				menu.InsertMenuItem(ninserted++, TRUE, &mii);
			}
			{
				MENUITEMINFO mii = { sizeof(mii), MIIM_ID | MIIM_STRING | MIIM_STATE, MFT_STRING, 0, copyPathId, NULL, NULL, NULL, NULL, this->LoadString(IDS_MENU_COPY_PATHS) };
				menu.InsertMenuItem(ninserted++, TRUE, &mii);
			}
			{
				MENUITEMINFO mii = { sizeof(mii), MIIM_ID | MIIM_STRING | MIIM_STATE, MFT_STRING, 0, copyTableId, NULL, NULL, NULL, NULL, this->LoadString(IDS_MENU_COPY_TABLE) };
				menu.InsertMenuItem(ninserted++, TRUE, &mii);
			}
			{
				MENUITEMINFO mii = { sizeof(mii), MIIM_ID | MIIM_STRING | MIIM_STATE, MFT_STRING, 0, dumpId, NULL, NULL, NULL, NULL, this->LoadString(IDS_MENU_DUMP_TO_TABLE) };
				menu.InsertMenuItem(ninserted++, TRUE, &mii);
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
		else if (id == dumpId || id == copyId || id == copyPathId || id == copyTableId)
		{
			this->dump_or_save(indices, id == dumpId ? 0 : id == copyId ? 2 : 1, id == copyPathId ? COLUMN_INDEX_PATH : -1);
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
				this->MessageBox(GetAnyErrorText(hr), this->LoadString(IDS_ERROR_TITLE), MB_OK | MB_ICONERROR);
			}
		}
	}

	void dump_or_save(std::vector<size_t> const &locked_indices, int const mode /* 0 if dump to file, 1 if copy to clipboard, 2 if copy to clipboard as shell file list */, int const single_column)
	{
		std::tstring file_dialog_save_options;
		if (mode <= 0)
		{
			std::tstring const null_char(1, _T('\0'));  // Do NOT convert this to TCHAR because 'wchar_t' might get interpreted as 'unsigned short' depending on compiler flags
			file_dialog_save_options += this->LoadString(IDS_SAVE_OPTION_UTF8_CSV);
			file_dialog_save_options += null_char;
			file_dialog_save_options += _T("*.csv");
			file_dialog_save_options += null_char;

			file_dialog_save_options += this->LoadString(IDS_SAVE_OPTION_UTF8_TSV);
			file_dialog_save_options += null_char;
			file_dialog_save_options += _T("*.tsv");
			file_dialog_save_options += null_char;

			file_dialog_save_options += null_char;
		}
		WTL::CFileDialog fdlg(FALSE, _T("csv"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, file_dialog_save_options.c_str(), *this);
		fdlg.m_ofn.lpfnHook = NULL;
		fdlg.m_ofn.Flags &= ~OFN_ENABLEHOOK;
		fdlg.m_ofn.lpstrTitle = this->LoadString(IDS_SAVE_TABLE_TITLE);
		if (mode <= 0 ? GetSaveFileName(&fdlg.m_ofn) : (locked_indices.size() <= 1 << 16 || this->MessageBox(this->LoadString(IDS_COPY_MAY_USE_TOO_MUCH_MEMORY_BODY), this->LoadString(IDS_WARNING_TITLE), MB_OKCANCEL | MB_ICONWARNING) == IDOK))
		{
			bool const tabsep = mode > 0 || fdlg.m_ofn.nFilterIndex > 1;
			WTL::CWaitCursor wait;
			int const ncolumns = this->lvFiles.GetHeader().GetItemCount();
			File const output = { mode <= 0 ? _topen(fdlg.m_ofn.lpstrFile, _O_BINARY | _O_TRUNC | _O_CREAT | _O_RDWR | _O_SEQUENTIAL, _S_IREAD | _S_IWRITE) : NULL };
			if (mode > 0 || output != NULL)
			{
				bool const shell_file_list = mode == 2 && single_column == COLUMN_INDEX_PATH;
				struct Clipboard
				{
					bool success;
					~Clipboard() { if (success) { ::CloseClipboard(); } }
					explicit Clipboard(HWND owner) : success(owner ? !!::OpenClipboard(owner) : false) { }
					operator bool() const { return this->success; }
				};
				Clipboard clipboard(output ? NULL : this->m_hWnd);
				if (clipboard)
				{
					EmptyClipboard();
				}
				CProgressDialog dlg(*this);
				dlg.SetProgressTitle(this->LoadString(output ? IDS_DUMPING_TITLE : IDS_COPYING_TITLE));
				if (locked_indices.size() > 1 && dlg.HasUserCancelled()) { return; }
				std::string line_buffer_utf8;
				SingleMovableGlobalAllocator global_alloc;
				std::tvstring line_buffer(static_cast<std::tvstring::allocator_type>(output ? NULL : &global_alloc));
				size_t const buffer_size = 1 << 22;
				line_buffer.reserve(buffer_size);  // this is necessary since MSVC STL reallocates poorly, degenerating into O(n^2)
				if (shell_file_list)
				{
					WTL::CPoint pt;
					GetCursorPos(&pt);
					DROPFILES df = { sizeof(df), pt, FALSE, sizeof(*line_buffer.data()) > sizeof(char) };
					line_buffer.append(reinterpret_cast<TCHAR const *>(&df), sizeof(df) / sizeof(TCHAR));
				}
				if (!output && (single_column == COLUMN_INDEX_PATH || single_column < 0))
				{
					line_buffer.reserve(locked_indices.size() * MAX_PATH * (single_column >= 0 ? 2 : 3) / 4);
				}
				unsigned long long nwritten_since_update = 0;
				unsigned long prev_update_time = GetTickCount();
				try
				{
					for (size_t i = 0; i < locked_indices.size(); ++i)
					{
						bool should_flush = i + 1 >= locked_indices.size();
						bool any = false;
						for (int j = single_column >= 0 ? single_column : 0; j < (single_column >= 0 ? single_column + 1 : ncolumns); ++j)
						{
							if (j == COLUMN_INDEX_NAME) { continue; }
							if (any) { line_buffer.push_back(tabsep ? _T('\t') : _T(',')); }
							size_t const begin_offset = line_buffer.size();
							this->GetSubItemText(locked_indices[i], j, false, line_buffer, false);
							if (j == COLUMN_INDEX_PATH)
							{
								unsigned long const update_time = GetTickCount();
								if (dlg.ShouldUpdate(update_time) || i + 1 == locked_indices.size())
								{
									if (dlg.HasUserCancelled(update_time)) { throw CStructured_Exception(ERROR_CANCELLED, NULL); }
									should_flush = true;
									basic_fast_ostringstream<TCHAR> ss;
									ss << this->LoadString(output ? IDS_TEXT_DUMPING_SELECTION : IDS_TEXT_COPYING_SELECTION) << this->LoadString(IDS_TEXT_SPACE);
									ss << nformat_ui(i + 1);
									ss << this->LoadString(IDS_TEXT_SPACE) << this->LoadString(IDS_TEXT_OF) << this->LoadString(IDS_TEXT_SPACE);
									ss << nformat_ui(locked_indices.size());
									if (update_time != prev_update_time)
									{
										ss << this->LoadString(IDS_TEXT_SPACE);
										ss << this->LoadString(IDS_TEXT_PAREN_OPEN);
										ss << nformat_ui(nwritten_since_update * 1000U / ((update_time - prev_update_time) * 1ULL << 20));
										ss << this->LoadString(IDS_TEXT_SPACE) << this->LoadString(IDS_TEXT_MIB_S);
										ss << this->LoadString(IDS_TEXT_PAREN_CLOSE);
									}
									ss << this->LoadString(IDS_TEXT_COLON);
									ss << _T('\n');
									ss.append(line_buffer.data() + static_cast<ptrdiff_t>(begin_offset), line_buffer.size() - begin_offset);
									std::tstring const &text = ss.str();
									dlg.SetProgressText(text);
									dlg.SetProgress(static_cast<long long>(i), static_cast<long long>(locked_indices.size()));
									dlg.Flush();
								}
							}
							// NOTE: We assume there are no double-quotes here, so we don't handle escaping for that! This is a valid assumption for this program.
							if (tabsep)
							{
								bool may_contain_tabs = false;
								if (may_contain_tabs && line_buffer.find(_T('\t'), begin_offset) != std::tstring::npos)
								{
									line_buffer.insert(line_buffer.begin() + static_cast<ptrdiff_t>(begin_offset), _T('\"'));
									line_buffer.push_back(_T('\"'));
								}
							}
							else
							{
								if (line_buffer.find(_T(','), begin_offset) != std::tstring::npos ||
									line_buffer.find(_T('\''), begin_offset) != std::tstring::npos)
								{
									line_buffer.insert(line_buffer.begin() + static_cast<ptrdiff_t>(begin_offset), _T('\"'));
									line_buffer.push_back(_T('\"'));
								}
							}
							any = true;
						}
						if (shell_file_list)
						{
							line_buffer.push_back(_T('\0'));
						}
						else if (i < locked_indices.size() - 1)
						{
							line_buffer.push_back(_T('\r'));
							line_buffer.push_back(_T('\n'));
						}
						should_flush |= line_buffer.size() >= buffer_size;
						if (should_flush)
						{
							if (output)
							{
#if defined(_UNICODE) &&_UNICODE
								using std::max;
								line_buffer_utf8.resize(max(line_buffer_utf8.size(), (line_buffer.size() + 1) * 6), _T('\0'));
								int const cch = WideCharToMultiByte(CP_UTF8, 0, line_buffer.empty() ? NULL : &line_buffer[0], static_cast<int>(line_buffer.size()), &line_buffer_utf8[0], static_cast<int>(line_buffer_utf8.size()), NULL, NULL);
								if (cch > 0)
								{
									nwritten_since_update += _write(output, line_buffer_utf8.data(), sizeof(*line_buffer_utf8.data()) * static_cast<size_t>(cch));
								}
#else
								nwritten_since_update += _write(output, line_buffer.data(), sizeof(*line_buffer.data()) * line_buffer.size());
#endif
								line_buffer.clear();
							}
							else
							{
								nwritten_since_update = line_buffer.size() * sizeof(*line_buffer.begin());
							}
						}
					}
					if (clipboard)
					{
						unsigned int const format = shell_file_list ? CF_HDROP : sizeof(*line_buffer.data()) > sizeof(char) ? CF_UNICODETEXT : CF_TEXT;
						if (HGLOBAL const resized = GlobalReAlloc(GlobalHandle(line_buffer.c_str()), (line_buffer.size() + 1) * sizeof(*line_buffer.data()), 0))
						{
							SetClipboardData(format, resized);
							// Clear the string, because we put it in an invalid state -- the underlying buffer is too small now!
							std::tvstring(line_buffer.get_allocator()).swap(line_buffer);
						}
					}
				}
				catch (CStructured_Exception &ex)
				{
					if (ex.GetSENumber() != ERROR_CANCELLED) { throw; }
				}
			}
		}
	}

	void DoubleClick(int index)
	{
		NtfsIndex const volatile *const i = this->results.item_index(static_cast<size_t>(index));
		std::tvstring path;
		path = i->root_path(), lock(i)->get_path(this->results[static_cast<size_t>(index)].key(), path, false);
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
		if (GetKeyState(VK_CONTROL) < 0 && GetKeyState(VK_MENU) >= 0)
		{
			if (p->wVKey == 'A')
			{
				LVITEM item = { LVIF_STATE, -1, -1, LVIS_SELECTED, LVIS_SELECTED };
				this->lvFiles.SetItemState(-1, &item);
			}
			if (p->wVKey == 'C')
			{
				WTL::CWaitCursor wait;
				std::vector<size_t> indices;
				this->append_selected_indices(indices);
				LockedResults locked_results(*this);
				std::for_each(indices.begin(), indices.end(), locked_results);
				this->dump_or_save(indices, GetKeyState(VK_SHIFT) < 0 ? 1 : 2, COLUMN_INDEX_PATH);
			}
		}
		if (p->wVKey == VK_UP && this->lvFiles.GetNextItem(-1, LVNI_FOCUSED) == 0)
		{
			this->txtPattern.SetFocus();
		}
		return 0;
	}

	void GetSubItemText(size_t const j, int const subitem, bool const for_ui, std::tvstring &text, bool const lock_index = true) const
	{
		typedef std::tvstring::iterator TextIt;
		lock_ptr<NtfsIndex const> i(this->results.item_index(j), lock_index);
		if (i->records_so_far() < this->results[j].key().frs())
		{
			__debugbreak();
		}
		NFormat const &nformat = for_ui ? nformat_ui : nformat_io;
		long long svalue;
		unsigned long long uvalue;
		NtfsIndex::key_type const key = this->results[j].key();
		NtfsIndex::key_type::frs_type const frs = key.frs();
		switch (subitem)
		{
		case COLUMN_INDEX_NAME             : i->get_path(key, text, true); deldirsep(text); break;
		case COLUMN_INDEX_PATH             : text += i->root_path(); i->get_path(key, text, false); break;
		case COLUMN_INDEX_SIZE             : uvalue = static_cast<unsigned long long>(i->get_sizes(key).length   ); text += nformat(uvalue); break;
		case COLUMN_INDEX_SIZE_ON_DISK     : uvalue = static_cast<unsigned long long>(i->get_sizes(key).allocated); text += nformat(uvalue); break;
		case COLUMN_INDEX_CREATION_TIME    : svalue = i->get_stdinfo(frs).created ; SystemTimeToString(svalue, text, !for_ui); break;
		case COLUMN_INDEX_MODIFICATION_TIME: svalue = i->get_stdinfo(frs).written ; SystemTimeToString(svalue, text, !for_ui); break;
		case COLUMN_INDEX_ACCESS_TIME      : svalue = i->get_stdinfo(frs).accessed; SystemTimeToString(svalue, text, !for_ui); break;
		case COLUMN_INDEX_DESCENDENTS      : uvalue = static_cast<unsigned long long>(i->get_sizes(key).treesize); if (uvalue) { text += nformat(uvalue - 1); } break;
		default: break;
		}
	}

	LRESULT OnFilesIncrementalSearch(LPNMHDR pnmh)
	{
		NMLVFINDITEM *const pLV = (NMLVFINDITEM *) pnmh;
		if (pLV->lvfi.flags & (LVFI_STRING | LVFI_PARTIAL))
		{
			int const n = this->lvFiles.GetItemCount();
			pLV->lvfi.lParam = this->lvFiles.GetNextItem(-1, LVNI_FOCUSED);
			TCHAR const *needle = pLV->lvfi.psz;
			size_t needle_length = std::char_traits<TCHAR>::length(needle);
			while (needle_length > 1 && *(needle + 1) == *needle)
			{
				++needle;
				--needle_length;
			}
			string_matcher matcher(string_matcher::pattern_verbatim, string_matcher::pattern_option_case_insensitive, needle, needle_length);
			LockedResults locked_results(*this);
			std::tvstring text;
			for (int i = 0; i < n; ++i)
			{
				int const iItem = (pLV->lvfi.lParam + (needle_length > 1 ? 0 : 1) + i) % n;
				if (!(pLV->lvfi.flags & LVFI_WRAP) && iItem == 0 && i != 0)
				{
					break;
				}
				locked_results(static_cast<size_t>(iItem));
				text.clear();
				this->GetSubItemText(static_cast<size_t>(iItem), COLUMN_INDEX_NAME, true, text, false);
				bool const match = (pLV->lvfi.flags & (LVFI_PARTIAL | (0x0004 /*LVFI_SUBSTRING*/)))
					? text.size() >= needle_length && matcher.is_match(text.data(), needle_length)
					: text.size() == needle_length && matcher.is_match(text.data(), needle_length);
				if (match)
				{
					pLV->lvfi.lParam = iItem;
					break;
				}
			}
		}

		return 0;
	}

	void get_subitem_text(size_t const item, int const subitem, std::tvstring &text)
	{
		text.clear();
		this->GetSubItemText(item, subitem, true, text);
	}

	LRESULT OnFilesGetDispInfo(LPNMHDR pnmh)
	{
		NMLVDISPINFO *const pLV = (NMLVDISPINFO *) pnmh;

		if ((this->lvFiles.GetStyle() & LVS_OWNERDATA) != 0 && (pLV->item.mask & LVIF_TEXT) != 0)
		{
			size_t const j = static_cast<size_t>(pLV->item.iItem);
			std::tvstring text;
			this->get_subitem_text(j, pLV->item.iSubItem, text);
			if (!text.empty()) { _tcsncpy(pLV->item.pszText, text.c_str(), pLV->item.cchTextMax); }
			if (pLV->item.iSubItem == 0)
			{
				WTL::CRect rc;
				this->lvFiles.GetClientRect(&rc);
				WTL::CRect rcitem;
				if (this->lvFiles.GetItemRect(pLV->item.iItem, &rcitem, LVIR_ICON) && rcitem.IntersectRect(&rcitem, &rc))
				{
					std::tvstring path;
					this->GetSubItemText(j, COLUMN_INDEX_PATH, true, path);
					int iImage = this->CacheIcon(path, static_cast<int>(pLV->item.iItem), lock(this->results.item_index(j))->get_stdinfo(this->results[j].key().frs()).attributes(), GetMessageTime());
					if (iImage >= 0) { pLV->item.iImage = iImage; }
				}
			}
		}
		return 0;
	}

	void OnCancel(UINT /*uNotifyCode*/, int /*nID*/, HWND /*hWnd*/)
	{
		if (this->suppress_escapes <= 0 && this->CheckAndCreateIcon(false))
		{
			this->ShowWindow(SW_HIDE);
		}
		this->suppress_escapes = 0;
	}

	BOOL PreTranslateMessage(MSG* pMsg)
	{
		BOOL result = FALSE;
		if (this->m_hWnd)
		{
			if (this->accel)
			{
				if (this->accel.TranslateAccelerator(this->m_hWnd, pMsg))
				{
					result = TRUE;
				}
			}
			if (!result)
			{
				result = this->CWindow::IsDialogMessage(pMsg);
			}
		}
		return result;
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
			size_t const iresult = static_cast<size_t>(pLV->nmcd.dwItemSpec);
			unsigned long const attrs = lock(this->results.item_index(iresult))->get_stdinfo(this->results[iresult].key().frs()).attributes();
			switch (pLV->nmcd.dwDrawStage)
			{
			case CDDS_PREPAINT:
				result = CDRF_NOTIFYITEMDRAW;
				break;
			case CDDS_ITEMPREPAINT:
				result = CDRF_NOTIFYSUBITEMDRAW;
				break;
			case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
				if (false && pLV->nmcd.dwItemSpec % 2) { unsigned char const v = 0xF8; pLV->clrTextBk = RGB(v, v, v); }
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
					std::tvstring itemText;
					this->GetSubItemText(static_cast<size_t>(pLV->nmcd.dwItemSpec), pLV->iSubItem, true, itemText);
					WTL::CDCHandle dc(pLV->nmcd.hdc);
					RECT rcTwips = pLV->nmcd.rc;
					rcTwips.left = (int) ((rcTwips.left + 6) * 1440 / dc.GetDeviceCaps(LOGPIXELSX));
					rcTwips.right = (int) (rcTwips.right * 1440 / dc.GetDeviceCaps(LOGPIXELSX));
					rcTwips.top = (int) (rcTwips.top * 1440 / dc.GetDeviceCaps(LOGPIXELSY));
					rcTwips.bottom = (int) (rcTwips.bottom * 1440 / dc.GetDeviceCaps(LOGPIXELSY));
					int const savedDC = dc.SaveDC();
					{
						std::replace(itemText.begin(), itemText.end(), _T(' '), _T('\u00A0'));
						{
							size_t const prev_size = itemText.size();
							for (size_t j = 0; j != prev_size; ++j)
							{
								itemText.push_back(itemText[j]);
								if (itemText[j] == _T('\\'))
								{
									itemText.push_back(_T('\u200B'));
								}
							}
							itemText.erase(itemText.begin(), itemText.begin() + static_cast<ptrdiff_t>(prev_size));
						}
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

	void OnSize(UINT nType, WTL::CSize size)
	{
		if (GetKeyState(VK_CONTROL) < 0)
		{
			this->PostMessage(WM_COMMAND, ID_VIEW_FITCOLUMNSTOWINDOW, 0);
		}
		else if (GetKeyState(VK_SHIFT) < 0)
		{
			this->PostMessage(WM_COMMAND, ID_VIEW_AUTOSIZECOLUMNS, 0);
		}
		this->SetMsgHandled(FALSE);
	}

	void OnWindowPosChanged(LPWINDOWPOS lpWndPos)
	{
		if (lpWndPos->flags & SWP_SHOWWINDOW)
		{
			SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
			this->DeleteNotifyIcon();
			this->UpdateWindow();
			if (!this->_initialized)
			{
				this->_initialized = true;
				this->Refresh(true);
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
		NOTIFYICONDATA nid = { sizeof(nid), *this, 0, NIF_MESSAGE | NIF_ICON | NIF_TIP, WM_NOTIFYICON, this->GetIcon(FALSE) };
		_tcsncpy(nid.szTip, this->LoadString(IDS_APPNAME), sizeof(nid.szTip) / sizeof(*nid.szTip));
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

	void OnHelp(UINT /*uNotifyCode*/, int nID, CWindow /*wndCtl*/)
	{
		RefCountedCString body, title;
		unsigned int type = MB_OK | MB_ICONINFORMATION;
		switch (nID)
		{
		case ID_HELP_DONATE: body.Format(this->LoadString(IDS_HELP_DONATE_BODY), this->get_project_url(IDS_PROJECT_USER_FRIENDLY_URL)); title = this->LoadString(IDS_HELP_DONATE_TITLE); type = (type & ~static_cast<unsigned int>(MB_OK) | MB_OKCANCEL); break;
		case ID_HELP_COPYING: body = this->LoadString(IDS_HELP_COPYING_BODY); title = this->LoadString(IDS_HELP_COPYING_TITLE); break;
		case ID_HELP_NTFSMETADATA: body = this->LoadString(IDS_HELP_NTFS_METADATA_BODY); title = this->LoadString(IDS_HELP_NTFS_METADATA_TITLE); break;
		case ID_HELP_SEARCHINGBYDEPTH: body = this->LoadString(IDS_HELP_SEARCHING_BY_DEPTH_BODY); title = this->LoadString(IDS_HELP_SEARCHING_BY_DEPTH_TITLE); break;
		case ID_HELP_SORTINGBYBULKINESS: body = this->LoadString(IDS_HELP_SORTING_BY_BULKINESS_BODY); title = this->LoadString(IDS_HELP_SORTING_BY_BULKINESS_TITLE); break;
		case ID_HELP_SORTINGBYDEPTH: body = this->LoadString(IDS_HELP_SORTING_BY_DEPTH_BODY); title = this->LoadString(IDS_HELP_SORTING_BY_DEPTH_TITLE); break;
		case ID_HELP_USINGREGULAREXPRESSIONS: body = this->LoadString(IDS_HELP_REGEX_BODY); title = this->LoadString(IDS_HELP_REGEX_TITLE); break;
		}
		if (!body.IsEmpty() || !title.IsEmpty())
		{
			int const r = this->MessageBox(static_cast<LPCTSTR>(body), static_cast<LPCTSTR>(title), type);
			switch (nID)
			{
			case ID_HELP_DONATE: if (r == IDOK) { this->open_project_page(); } break;
			default: break;
			}
		}
	}

	void OnHelpBugs(UINT /*uNotifyCode*/, int /*nID*/, CWindow /*wndCtl*/)
	{
		long long const ticks = get_version(&__ImageBase);
		std::tvstring buf_localized, buf_invariant;
		RefCountedCString body;
		SystemTimeToString(ticks, buf_localized, false, false);
		SystemTimeToString(ticks, buf_invariant, true, false);
		body.Format(this->LoadString(IDS_TEXT_REPORT_ISSUES), this->get_project_url(IDS_PROJECT_USER_FRIENDLY_URL));
		body += _T("\x2022");
		body += this->LoadString(IDS_TEXT_SPACE);
		body += this->LoadString(IDS_TEXT_BUILD_DATE);
		body += this->LoadString(IDS_TEXT_SPACE);
		body += buf_localized.c_str();
		body += this->LoadString(IDS_TEXT_SPACE);
		body += this->LoadString(IDS_TEXT_PAREN_OPEN);
		body += buf_invariant.c_str();
		body += this->LoadString(IDS_TEXT_PAREN_CLOSE);
		if (this->MessageBox(body, this->LoadString(IDS_HELP_BUGS_TITLE), MB_OKCANCEL | MB_ICONINFORMATION) == IDOK)
		{
			this->open_project_page();
		}
	}

	RefCountedCString get_project_url(unsigned short const id)
	{
		RefCountedCString result;
		result.Format(this->LoadString(id), this->LoadString(IDS_PROJECT_NAME));
		return result;
	}

	void open_project_page()
	{
		ShellExecute(NULL, _T("open"), this->get_project_url(IDS_PROJECT_ROBUST_URL), NULL, NULL, SW_SHOWNORMAL);
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

	void OnViewFitColumns(UINT /*uNotifyCode*/, int nID, CWindow /*wndCtl*/)
	{
		WTL::CListViewCtrl &wndListView = this->lvFiles;
		CSetRedraw no_redraw(wndListView, false);
		if (nID == ID_VIEW_FITCOLUMNSTOWINDOW)
		{
			RECT rect;
			wndListView.GetClientRect(&rect);
			int const client_width = (std::max)(1, (int) (rect.right - rect.left) - GetSystemMetrics(SM_CXVSCROLL) - 2);

			WTL::CHeaderCtrl wndListViewHeader = wndListView.GetHeader();
			int oldTotalColumnsWidth;
			oldTotalColumnsWidth = 0;
			int columnCount;
			columnCount = wndListViewHeader.GetItemCount();
			for (int i = 0; i < columnCount; i++)
			{
				oldTotalColumnsWidth += wndListView.GetColumnWidth(i);
			}
			for (int i = 0; i < columnCount; i++)
			{
				int colWidth = wndListView.GetColumnWidth(i);
				int newWidth = MulDiv(colWidth, client_width, oldTotalColumnsWidth);
				newWidth = (std::max)(newWidth, 1);
				wndListView.SetColumnWidth(i, newWidth);
			}
		}
		else if (nID == ID_VIEW_AUTOSIZECOLUMNS)
		{
			struct TextGetter : WTL::CListViewCtrl
			{
				CMainDlg *me;
				TextGetter(CMainDlg &me) : me(&me), WTL::CListViewCtrl(me.lvFiles) { }
				static ptrdiff_t invoke(void *const me, int const item, int const subitem, ListViewAdapter::String &result)
				{
					TextGetter *const this_ = static_cast<TextGetter *>(static_cast<WTL::CListViewCtrl *>(me));
					this_->me->get_subitem_text(item, subitem, result);
					return static_cast<ptrdiff_t>(result.size());
				}
			} instance(*this);
			autosize_columns(ListViewAdapter(instance, this->cached_column_header_widths, &TextGetter::invoke));
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
		this->clear(true, true);
		int const selected = this->cmbDrive.GetCurSel();
		for (int ii = 0; ii < this->cmbDrive.GetCount(); ++ii)
		{
			if (selected == 0 || ii == selected)
			{
				intrusive_ptr<NtfsIndex> q = static_cast<NtfsIndex *>(this->cmbDrive.GetItemDataPtr(ii));
				if (q || initial && ii != 0)
				{
					std::tvstring path_name;
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
					intrusive_ptr<T> p(new T(this->iocp, q, this->m_hWnd, this->closing_event));
					this->iocp->post(0, static_cast<uintptr_t>(ii), p);
					if (this->cmbDrive.SetItemDataPtr(ii, q.get()) != CB_ERR)
					{
						q.detach();
						++this->indices_created;
					}
				}
			}
		}
	}

#pragma warning(suppress: 4555)
	BEGIN_MSG_MAP_EX(CMainDlg)
		MSG_WM_SIZE(OnSize)  // must come BEFORE chained message maps
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
		COMMAND_ID_HANDLER_EX(ID_HELP_BUGS, OnHelpBugs)
		COMMAND_ID_HANDLER_EX(ID_HELP_DONATE, OnHelp)
		COMMAND_ID_HANDLER_EX(ID_HELP_COPYING, OnHelp)
		COMMAND_ID_HANDLER_EX(ID_HELP_NTFSMETADATA, OnHelp)
		COMMAND_ID_HANDLER_EX(ID_HELP_SEARCHINGBYDEPTH, OnHelp)
		COMMAND_ID_HANDLER_EX(ID_HELP_SORTINGBYBULKINESS, OnHelp)
		COMMAND_ID_HANDLER_EX(ID_HELP_SORTINGBYDEPTH, OnHelp)
		COMMAND_ID_HANDLER_EX(ID_HELP_USINGREGULAREXPRESSIONS, OnHelp)
		COMMAND_ID_HANDLER_EX(ID_VIEW_GRIDLINES, OnViewGridlines)
		COMMAND_ID_HANDLER_EX(ID_VIEW_LARGEICONS, OnViewLargeIcons)
		COMMAND_ID_HANDLER_EX(ID_VIEW_FITCOLUMNSTOWINDOW, OnViewFitColumns)
		COMMAND_ID_HANDLER_EX(ID_VIEW_AUTOSIZECOLUMNS, OnViewFitColumns)
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

int LCIDToLocaleName_XPCompatible(LCID lcid, LPTSTR name, int name_length)
{
	HMODULE hKernel32;
	if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCTSTR>(&GetSystemInfo), &hKernel32))
	{
		hKernel32 = NULL;
	}
	typedef int WINAPI LCIDToLocaleName_t(LCID Locale, LPTSTR lpName, int cchName, DWORD dwFlags);
	if (LCIDToLocaleName_t *const LCIDToLocaleName = reinterpret_cast<LCIDToLocaleName_t *>(GetProcAddress(hKernel32, _CRT_STRINGIZE(LCIDToLocaleName))))
	{
		name_length = (*LCIDToLocaleName)(lcid, name, name_length, 0);
	}
	else
	{
		ATL::CRegKey key;
		if (key.Open(HKEY_CLASSES_ROOT, TEXT("MIME\\Database\\Rfc1766"), KEY_QUERY_VALUE) == 0)
		{
			TCHAR value_data[64 + MAX_PATH];
			TCHAR value_name[16];
			value_name[0] = _T('\0');
			safe_stprintf(value_name, _T("%04lX"), lcid);
			unsigned long value_data_length = sizeof(value_data) / sizeof(*value_data);
			LRESULT const result = key.QueryValue(value_data, value_name, &value_data_length);
			if (result == 0)
			{
				unsigned long i;
				for (i = 0; i != value_data_length; ++i)
				{
					if (value_data[i] == _T(';'))
					{
						break;
					}
					if (name_length >= 0 && i < static_cast<unsigned long>(name_length))
					{
						TCHAR ch = value_data[static_cast<ptrdiff_t>(i)];
						name[static_cast<ptrdiff_t>(i)] = ch;
					}
				}
				name_length = static_cast<int>(i);
			}
			else { name_length = 0; }
		}
		else { name_length = 0; }
	}
	return name_length;
}
WTL::CString LCIDToLocaleName_XPCompatible(LCID lcid)
{
	WTL::CString result;
	LPTSTR const buf = result.GetBufferSetLength(64);
	int const n = LCIDToLocaleName_XPCompatible(lcid, buf, result.GetLength());
	result.Delete(n, result.GetLength() - n);
	return result;
}

HMODULE mui_module = NULL;
WTL::CAppModule _Module;

template<class _BidIt,
	class _Diff,
	class _Ty,
	class _Pr> inline
	void My_Stable_sort_unchecked1(_BidIt _First, _BidIt _Last, _Diff _Count,
		std::_Temp_iterator<_Ty>& _Tempbuf, _Pr& _Pred)
{	// sort preserving order of equivalents, using _Pred
	{	// sort halves and merge
		_Diff _Count2 = (_Count + 1) / 2;
		_BidIt _Mid = _First;
		_STD advance(_Mid, _Count2);

		if (_Count2 <= _Tempbuf._Maxlen())
		{	// temp buffer big enough, sort each half using buffer
			std::_Buffered_merge_sort_unchecked(_First, _Mid, _Count2, _Tempbuf, _Pred);
			std::_Buffered_merge_sort_unchecked(_Mid, _Last, _Count - _Count2,
				_Tempbuf, _Pred);
		}
		else
		{	// temp buffer not big enough, divide and conquer
			My_Stable_sort_unchecked1(_First, _Mid, _Count2, _Tempbuf, _Pred);
			My_Stable_sort_unchecked1(_Mid, _Last, _Count - _Count2, _Tempbuf, _Pred);
		}

		std::_Buffered_merge_unchecked(_First, _Mid, _Last,
			_Count2, _Count - _Count2, _Tempbuf, _Pred);	// merge halves
	}
}

int _tmain(int argc, TCHAR* argv[])
{
	HINSTANCE const hInstance = GetModuleHandle(NULL);
	RefCountedCString guid_str;
	guid_str.Insert(guid_str.GetLength(), _T("{CB77990E-A78F-44dc-B382-089B01207F02}"));
	std::tstring module_path;
	if (argc > 0)
	{
		module_path = argv[0];
	}
	else
	{
		module_path.resize(USHRT_MAX, _T('\0'));
		module_path.resize(GetModuleFileName(hInstance, module_path.empty() ? NULL : &*module_path.begin(), static_cast<unsigned int>(module_path.size())));
	}
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
				std::tstring tempDir(32 * 1024, _T('\0'));
				tempDir.resize(GetTempPath(static_cast<DWORD>(tempDir.size()), &tempDir[0]));
				if (!tempDir.empty())
				{
					std::tstring const module_file_name(basename(module_path.begin(), module_path.end()), module_path.end());
					std::tstring fileName(module_file_name.begin(), fileext(module_file_name.begin(), module_file_name.end()));
					fileName.insert(fileName.begin(), tempDir.begin(), tempDir.end());
					TCHAR tempbuf[10]; fileName.append(_itot(64, tempbuf, 10));
					fileName.append(_T("_"));
					fileName.append(guid_str);
					fileName.append(fileext(module_file_name.begin(), module_file_name.end()), module_file_name.end());
					struct Deleter
					{
						std::tstring file;
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
	(void) argc;
	(void) argv;
	int result = 0;
	bool right_to_left = false;
	unsigned long reading_layout;
	if (GetLocaleInfo(LOCALE_USER_DEFAULT, 0x00000070 /*LOCALE_IREADINGLAYOUT*/ | LOCALE_RETURN_NUMBER, reinterpret_cast<LPTSTR>(&reading_layout), sizeof(reading_layout) / sizeof(TCHAR)) >= sizeof(reading_layout) / sizeof(TCHAR))
	{
		right_to_left = reading_layout == 1;
	}
	else
	{
		right_to_left = !!(GetWindowLongPtr(FindWindow(_T("Shell_TrayWnd"), NULL), GWL_EXSTYLE) & WS_EX_LAYOUTRTL);
	}
	if (right_to_left)
	{
		SetProcessDefaultLayout(LAYOUT_RTL);
	}
	__if_exists(_Module) { _Module.Init(NULL, hInstance); }
	{
		RefCountedCString appname;
		appname.LoadString(IDS_APPNAME);
		HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, _T("Local\\") + appname + _T(".") + guid_str);
		if (hEvent != NULL && GetLastError() != ERROR_ALREADY_EXISTS)
		{
			WTL::CMessageLoop msgLoop;
			_Module.AddMessageLoop(&msgLoop);
			if (!module_path.empty())
			{
				// https://blogs.msdn.microsoft.com/jsocha/2011/12/14/allowing-localizing-after-the-fact-using-mui/
				std::tstring module_name = module_path;
				module_name.erase(module_name.begin(), basename(module_name.begin(), module_name.end()));
				std::tstring module_directory = module_path;
				module_directory.erase(dirname(module_directory.begin(), module_directory.end()), module_directory.end());
				if (!module_directory.empty())
				{
					module_directory += getdirsep();
				}
				std::tstring const period = TEXT(".");
				std::tstring const mui_ext = TEXT("mui");
				std::tstring const locale_name = static_cast<LPCTSTR>(LCIDToLocaleName_XPCompatible(MAKELCID(GetUserDefaultUILanguage(), SORT_DEFAULT)));
				std::tstring const mui_paths [] =
				{
					module_directory + getdirsep() + module_name + period + locale_name + period + mui_ext,
					module_directory + locale_name + getdirsep() + module_name + period + mui_ext
				};
				for (size_t i = 0; i != sizeof(mui_paths) / sizeof(*mui_paths) && !mui_module; ++i)
				{
					unsigned int const mui_load_flags = LOAD_LIBRARY_AS_DATAFILE;
					for (int pass = 0; pass < 2 && !mui_module; ++pass)
					{
						mui_module = LoadLibraryEx(mui_paths[i].c_str(), NULL, mui_load_flags | (!pass ? 0x00000020 /*LOAD_LIBRARY_AS_IMAGE_RESOURCE only works on Vista and later*/ : 0));
					}
				}
			}
			CMainDlg wnd(hEvent, right_to_left);
			wnd.Create(reinterpret_cast<HWND>(NULL), NULL);
			wnd.ShowWindow(SW_SHOWDEFAULT);
			msgLoop.Run();
			_Module.RemoveMessageLoop();
		}
		else
		{
			AllowSetForegroundWindow(ASFW_ANY);
			PulseEvent(hEvent);  // PulseThread() is normally unreliable, but we don't really care here...
			result = GetLastError();
		}
	}
	__if_exists(_Module) { _Module.Term(); }
	return result;
}

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#if defined(_MSC_VER) && _MSC_VER >= 1900 && !defined(_CPPLIB_VER)
extern "C" __declspec(noreturn) void __cdecl __std_terminate() { terminate(); }
#endif

int __stdcall _tWinMain(HINSTANCE const hInstance, HINSTANCE /*hPrevInstance*/, LPTSTR /*lpCmdLine*/, int nShowCmd)
{
	(void) hInstance;
	(void) nShowCmd;
	return _tmain(__argc, __targv);
}
