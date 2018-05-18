#pragma once

// https://sourceforge.net/p/predef/wiki/Libraries/ for _CPPLIB_VER

#ifdef __cplusplus
#ifdef __cplusplus_cli
#pragma managed(push, off)
#endif

#pragma warning(disable: 4005)  // 'WCHAR_{MIN,MAX}': macro redefinition

#pragma warning(push)
#pragma warning(disable: 4619)  // there is no warning number ''
#pragma warning(disable: 4774)  // format string is not a string literal

#ifdef  _CSTDLIB_
#error include <cstdlib> already happened
#endif
#include <cstdlib>  // needed for _CPPLIB_VER
#ifdef  _CSTDDEF_
#error include <cstddef> already happened
#endif
#include <cstddef>

#if defined(_MSC_VER) && !defined(_CPPLIB_VER) || _CPPLIB_VER < 403

#define _STRALIGN_USE_SECURE_CRT 0
#define _FORWARD_LIST_  // prevent inclusion of this
#define _TUPLE_  // prevent inclusion of this
#define _TYPE_TRAITS_  // prevent inclusion of this

#ifndef _XSTD
#define _X_STD_BEGIN _STD_BEGIN
#define _X_STD_END _STD_END
#define _XSTD _STD
#endif

#ifndef _NO_RETURN
#if defined(_MSC_VER) && _MSC_VER < 1900
#define _NO_RETURN(F) __declspec(noreturn) void F
#else
#define _NO_RETURN(F) [[noreturn]] void F
#endif
#endif

#if _HAS_EXCEPTIONS
#define _NOEXCEPT	noexcept
#define _NOEXCEPT_OP(x)	noexcept(x)
#else
#define _NOEXCEPT	throw ()
#define _NOEXCEPT_OP(x)
#endif

#ifndef _CRTIMP2
#define _CRTIMP2
#endif
#ifndef _CRTIMP2_PURE
#define _CRTIMP2_PURE _CRTIMP2
#endif

#ifndef __CLRCALL_PURE_OR_CDECL
#ifdef _M_CEE_PURE
#define __CLRCALL_PURE_OR_CDECL __clrcall
#else
#define __CLRCALL_PURE_OR_CDECL __cdecl
#endif
#endif

#ifndef _In_z_
#define _In_z_
#endif
#ifndef _In_reads_
#define _In_reads_(_)
#endif

extern "C" long __cdecl _InterlockedIncrement(long volatile *lpAddend);
#ifndef _MT_INCR
#define _MT_INCR(x) _InterlockedIncrement(reinterpret_cast<long volatile *>(&x))
#endif
extern "C" long __cdecl _InterlockedDecrement(long volatile *lpAddend);
#ifndef _MT_DECR
#define _MT_DECR(x) _InterlockedDecrement(reinterpret_cast<long volatile *>(&x))
#endif

#if __cplusplus >= 201103L || defined(__GXX_EXPERIMENTAL_CXX0X__) || defined(_MSC_VER) && _MSC_VER >= 1600
#define X_HAS_MOVE_SEMANTICS
#elif defined(__clang)
#if __has_feature(cxx_rvalue_references)
#define X_HAS_MOVE_SEMANTICS
#endif
#endif
#ifdef  X_HAS_MOVE_SEMANTICS

extern "C"
{
#ifdef _WIN64
	__declspec(dllimport) __int64 (__stdcall *__stdcall GetProcAddress(struct HINSTANCE__* hModule, char const *lpProcName))();
#else
	__declspec(dllimport) int (__stdcall *__stdcall GetProcAddress(struct HINSTANCE__* hModule, char const *lpProcName))();
#endif
	__declspec(dllimport) int __stdcall GetModuleHandleExA(unsigned long dwFlags, char const *lpModuleName, struct HINSTANCE__** phModule);
	__declspec(dllimport) int __stdcall GetModuleHandleExW(unsigned long dwFlags, wchar_t const *lpModuleName, struct HINSTANCE__** phModule);
#if defined(_MSC_VER) && _MSC_VER >= 1400
#ifdef _M_X64
	void *__cdecl _InterlockedCompareExchangePointer(void *volatile *Destination, void *ExChange, void *Comparand);
#	pragma intrinsic(_InterlockedCompareExchangePointer)
#else
#if _MSC_VER < 1800
	long __cdecl _InterlockedCompareExchange(long volatile *, long, long);
#	pragma intrinsic(_InterlockedCompareExchange)
	static void *__cdecl _InterlockedCompareExchangePointer(void *volatile *Destination, void *ExChange, void *Comparand)
	{
		return (void *)_InterlockedCompareExchange((long volatile *)Destination, (long)ExChange, (long)Comparand);
	}
#else
	void *__cdecl _InterlockedCompareExchangePointer(void *volatile *Destination, void *ExChange, void *Comparand);
#pragma intrinsic(_InterlockedCompareExchangePointer)
#endif
#endif
#endif
}
#ifndef _C_STD_BEGIN
#	define _C_STD_BEGIN namespace std {
#endif
#ifndef _C_STD_END
#	define _C_STD_END }
#endif
#ifndef _CSTD
#	define _CSTD ::std::
#endif

namespace std
{
	template<class T, T v>
	struct integral_constant
	{
		static T const value = v;
		typedef T value_type;
		typedef integral_constant type;
		operator value_type() const _NOEXCEPT { return value; }
		value_type operator()() const _NOEXCEPT { return value; }
	};
	typedef integral_constant<bool, true > true_type;
	typedef integral_constant<bool, false> false_type;
	template<class> struct is_unsigned;
	template<> struct is_unsigned<unsigned char     > : true_type { };
	template<> struct is_unsigned<unsigned short    > : true_type { };
	template<> struct is_unsigned<unsigned int      > : true_type { };
	template<> struct is_unsigned<unsigned long     > : true_type { };
	template<> struct is_unsigned<unsigned long long> : true_type { };
	template<> struct is_unsigned<         char     > : integral_constant<bool, (~char() >= 0)> { };
#if defined(_NATIVE_WCHAR_T_DEFINED) && _NATIVE_WCHAR_T_DEFINED
	template<> struct is_unsigned<        wchar_t   > : integral_constant<bool, (~wchar_t() >= 0)> { };
#endif
	template<> struct is_unsigned<  signed char     > : false_type { };
	template<> struct is_unsigned<  signed short    > : false_type { };
	template<> struct is_unsigned<  signed int      > : false_type { };
	template<> struct is_unsigned<  signed long     > : false_type { };
	template<> struct is_unsigned<  signed long long> : false_type { };
	template<class> struct make_unsigned;
	template<> struct make_unsigned<unsigned char     > { typedef unsigned char      type; };
	template<> struct make_unsigned<unsigned short    > { typedef unsigned short     type; };
	template<> struct make_unsigned<unsigned int      > { typedef unsigned int       type; };
	template<> struct make_unsigned<unsigned long     > { typedef unsigned long      type; };
	template<> struct make_unsigned<unsigned long long> { typedef unsigned long long type; };
	template<> struct make_unsigned<       char     > : make_unsigned<unsigned char     > { };
	template<> struct make_unsigned<signed char     > : make_unsigned<unsigned char     > { };
	template<> struct make_unsigned<signed short    > : make_unsigned<unsigned short    > { };
	template<> struct make_unsigned<signed int      > : make_unsigned<unsigned int      > { };
	template<> struct make_unsigned<signed long     > : make_unsigned<unsigned long     > { };
	template<> struct make_unsigned<signed long long> : make_unsigned<unsigned long long> { };
	template<class T> struct add_rvalue_reference { typedef T type; };
	template<> struct add_rvalue_reference<void> { typedef void type; };
	template<> struct add_rvalue_reference<void const> { typedef void const type; };
	template<> struct add_rvalue_reference<void volatile> { typedef void volatile type; };
	template<> struct add_rvalue_reference<void const volatile> { typedef void const volatile type; };
	template<class T> struct remove_reference       { typedef T type; };
	template<class T> struct remove_reference<T &>  { typedef T type; };
	template<class T> struct remove_reference<T &&> { typedef T type; };
	template<class T>
	typename remove_reference<T>::type &&move(T &&value) _NOEXCEPT { return static_cast<typename remove_reference<T>::type &&>(value); } 
	template<class T> /* TODO: WARN: technically this is a wrong implementation... if is_function<T>::value || is_void<T>::value, it should not add an r-value reference at all */
	typename T &&declval() _NOEXCEPT;
}

namespace std { template<class C, class T, class D = ptrdiff_t, class P = T *, class R = void> struct iterator; }
#define iterator iterator_bad
#define inserter inserter_bad
#define insert_iterator insert_iterator_bad
#define back_inserter back_inserter_bad
#define back_insert_iterator back_insert_iterator_bad
#define iterator_traits iterator_traits_bad
#define reverse_iterator reverse_iterator_bad
#ifdef  _UTILITY_
#error include <utility> already happened
#endif
#include <utility>  // iterator_traits
template<class T>
struct std::iterator_traits_bad<T *>
{
	typedef std::random_access_iterator_tag iterator_category;
	typedef T value_type;
	typedef ptrdiff_t difference_type;
	typedef ptrdiff_t distance_type;
	typedef T *pointer;
	typedef T &reference;
};
#undef reverse_iterator
namespace std { template<class RanIt, class T = typename iterator_traits<RanIt>::value_type, class R = T &, class P = T *, class D = ptrdiff_t> class reverse_iterator; }
#ifdef  _ITERATOR_
#error include <iterator> already happened
#endif
#include <iterator>
#undef iterator_traits
#undef back_insert_iterator
#undef back_inserter
#undef insert_iterator
#undef inserter
#undef iterator

typedef __int64 _Longlong;
typedef unsigned __int64 _ULonglong;

#ifdef  _INC_MATH_
#error include <math.h> already happened
#endif
#include <math.h>  // ::ceil
#ifdef  _LIMITS_
#error include <limits> already happened
#endif
#include <limits>

namespace std
{
	using ::intptr_t;
	using ::uintptr_t;
	using ::memcpy;
	using ::memset;
	using ::abort;
	using ::strerror;
	using ::ceil;
	using ::va_list;

	template<class T> T *operator &(T &p) { return reinterpret_cast<T *>(&reinterpret_cast<unsigned char &>(p)); }
	template<class T> T const *operator &(T const &p) { return reinterpret_cast<T const *>(&reinterpret_cast<unsigned char const &>(p)); }
	template<class T> T volatile *operator &(T volatile &p) { return reinterpret_cast<T volatile *>(&reinterpret_cast<unsigned char volatile &>(p)); }
	template<class T> T const volatile *operator &(T const volatile &p) { return reinterpret_cast<T const volatile *>(&reinterpret_cast<unsigned char const volatile &>(p)); }

	template<bool B, class T = void> struct enable_if {};
	template<class T> struct enable_if<true, T> { typedef T type; };

	template<> class numeric_limits<__int64>;
	template<> class numeric_limits<unsigned __int64>;

	template<class T>
	struct ref_or_void { typedef T &type; };

	template<>
	struct ref_or_void<void> { typedef void type; };

	template<class C, class T, class D, class P, class R>
	struct iterator : public iterator_bad<C, T, D>
	{
		typedef D difference_type;
		typedef P pointer;
		typedef R reference;
	};

	template<class C>
	class insert_iterator : public iterator<output_iterator_tag, void, void>
	{
	public:
		typedef C container_type;
		typedef typename C::value_type value_type;
		insert_iterator(C& _X, typename C::iterator _I) : container(&_X), iter(_I) {}
		insert_iterator<C>& operator=(const value_type& _V) { iter = container->insert(iter, _V); ++iter; return (*this); }
		insert_iterator<C>& operator*() { return (*this); }
		insert_iterator<C>& operator++() { return (*this); }
		insert_iterator<C>& operator++(int) { return (*this); }
	protected:
		C *container;
		typename C::iterator iter;
	};

	template<class C, class _XI>
	inline insert_iterator<C> inserter(C& _X, _XI _I)
	{ return (insert_iterator<C>(_X, C::iterator(_I))); }

	template<typename T, typename Sign>
	struct has_push_back
	{
		typedef char yes[1];
		typedef char no [2];
		template <typename U, U> struct type_check;
		template <typename _1> static yes &chk(type_check<Sign, &_1::push_back> *);
		template <typename   > static no  &chk(...);
		enum { value = sizeof(chk<T>(0)) == sizeof(yes) };
	};

	template<class C, class T> static typename enable_if< has_push_back<C, void(C::*)(T const &)>::value>::type push_back(C &c, T const &v) { c.push_back(v); }
	template<class C, class T> static typename enable_if<!has_push_back<C, void(C::*)(T const &)>::value>::type push_back(C &c, T const &v) { c.insert(c.end(), v); }

	template<class C>
	class back_insert_iterator : public iterator<output_iterator_tag, void, void>
	{
	public:
		typedef C container_type;
		typedef typename C::value_type value_type;
		explicit back_insert_iterator(C& _X) : container(&_X) {}
		back_insert_iterator<C>& operator=(const value_type& _V) { push_back(*container, _V); return (*this); }
		back_insert_iterator<C>& operator*() { return (*this); }
		back_insert_iterator<C>& operator++() { return (*this); }
		back_insert_iterator<C>& operator++(int) { return (*this); }
	protected:
		C *container;
	};

	template<class C>
	inline back_insert_iterator<C> back_inserter(C& _X)
	{ return (back_insert_iterator<C>(_X)); }

	template<class It>
	struct iterator_traits //: public iterator_traits_bad<It>
	{
		typedef typename It::iterator_category iterator_category;
		typedef typename It::value_type value_type;
		typedef ptrdiff_t difference_type;
		typedef difference_type distance_type;
		typedef value_type *pointer;
		typedef value_type &reference;
	};

	template<class T>
	struct iterator_traits<T *>
	{
		typedef random_access_iterator_tag iterator_category;
		typedef T value_type;
		typedef ptrdiff_t difference_type;
		typedef ptrdiff_t distance_type;
		typedef T *pointer;
		typedef T &reference;
	};

	template<class T>
	struct iterator_traits<T const *>
	{
		typedef random_access_iterator_tag iterator_category;
		typedef T value_type;
		typedef ptrdiff_t difference_type;
		typedef ptrdiff_t distance_type;
		typedef T const *pointer;
		typedef T const &reference;
	};

	template<class C>
	struct iterator_traits<insert_iterator<C> >
	{
		typedef output_iterator_tag iterator_category;
		typedef typename C::value_type value_type;
		typedef void difference_type;
		typedef void distance_type;
		typedef void pointer;
		typedef void reference;
	};

	template<class It> inline typename iterator_traits<It>::iterator_category __cdecl _Iter_cat(It const &) { return iterator_traits<It>::iterator_category(); }
#if defined(_MSC_VER) && _MSC_VER >= 1800
	template<class It> using _Iter_value_t = typename iterator_traits<It>::value_type;
	template<class It> using _Iter_diff_t = typename iterator_traits<It>::difference_type;
	template<class It> using _Iter_cat_t = typename iterator_traits<It>::iterator_category;
#endif
}

namespace boost
{
	namespace iterators
	{
		namespace detail
		{
			template<class C, class T, class D, class P, class R>
			struct iterator : public std::iterator<C, T, D, P, R> { };
		}
	}

	namespace re_detail_106700
	{
		template<class It, class OutIt>
		OutIt plain_copy(It begin, It end, OutIt out) { while (begin != end) { *out = *begin; ++begin; } return out; }
		struct re_syntax_base;
		template <class Results>
		struct recursion_info;
		template<class T>
		inline recursion_info<T> *copy(recursion_info<T> *begin, recursion_info<T> *end, recursion_info<T> *out) { return plain_copy<recursion_info<T> *, recursion_info<T> *>(begin, end, out); }
		inline std::pair<bool, re_syntax_base *> *copy(std::pair<bool, re_syntax_base *> *begin, std::pair<bool, re_syntax_base *> *end, std::pair<bool, re_syntax_base *> *out) { return plain_copy<std::pair<bool, re_syntax_base *> *, std::pair<bool, re_syntax_base *> *>(begin, end, out); }
	}
}

#ifdef  _EXCEPTION_
#error include <exception> already happened
#endif
#include <exception>  // must be included before <xstring> to avoid renaming clash

// std::allocator::rebind doesn't exist!!
#define allocator allocator_bad
#ifdef  _MEMORY_
#error include <memory> already happened
#endif
#include <memory>
#undef allocator
namespace std
{
	template<class T>
	class allocator : public allocator_bad<T>
	{
		typedef allocator_bad<T> Base;
	public:
		template<class U> struct rebind { typedef allocator<U> other; };
		allocator() { }
		allocator(Base const &v) : Base(v) { }
		template<class Other>
		allocator(allocator_bad<Other> const &) : Base() { }
		typename Base::pointer allocate(typename Base::size_type n, void const *hint = NULL)
		{ return this->Base::allocate(n, hint); }
#ifdef X_HAS_MOVE_SEMANTICS
		// using Base::construct;
		// void construct(typename Base::pointer const p, T &&value) { new(p) T(static_cast<T &&>(value)); }
#endif
	};

	template<class T>
	class allocator<T const> : public allocator<T>
	{
	};

	template<class Ax>
	struct allocator_traits
	{
		typedef typename Ax::size_type size_type;
	};
}

// The above re-implementation of std::allocator messes up some warnings...
#pragma warning(push)
#pragma warning(disable: 4251)  // class 'type' needs to have dll-interface to be used by clients of class 'type2'
#pragma warning(disable: 4512)  // assignment operator could not be generated
	namespace std
	{
		template<class RanIt, class T, class R, class P, class D>
		class reverse_iterator : public iterator<typename iterator_traits<RanIt>::iterator_category, T, D, P, R>
		{
		public:
			typedef reverse_iterator<RanIt> This;
			typedef typename iterator_traits<RanIt>::difference_type difference_type;
			typedef typename iterator_traits<RanIt>::pointer pointer;
			typedef typename iterator_traits<RanIt>::reference reference;
			typedef RanIt iterator_type;
			reverse_iterator() { }
			explicit reverse_iterator(RanIt right) : current(right) { }
			template<class Other>
			reverse_iterator(const reverse_iterator<Other>& right) : current(right.base()) { }
			RanIt base() const { return (current); }
			reference operator*() const { RanIt tmp = current; return (*--tmp); }
			pointer operator->() const { return (&**this); }
			This& operator++() { --current; return (*this); }
			This operator++(int) { This tmp = *this; --current; return (tmp); }
			This& operator--() { ++current; return (*this); }
			This operator--(int) { This tmp = *this; ++current; return (tmp); }
			bool operator ==(const reverse_iterator& right) const
			{ return (current == right.base()); }
			bool operator !=(const reverse_iterator& right) const
			{ return (current != right.base()); }
			This& operator+=(difference_type offset) { current -= offset; return (*this); }
			This operator+(difference_type offset) const { return (This(current - offset)); }
			This& operator-=(difference_type offset) { current += offset; return (*this); }
			This operator-(difference_type offset) const { return (This(current + offset)); }
			reference operator[](difference_type offset) const { return (*(*this + offset)); }
			bool operator <(const reverse_iterator& right) const { return (right.base() < current); }
			bool operator >(const reverse_iterator& right) const { return (right.base() > current); }
			bool operator <=(const reverse_iterator& right) const { return (right.base() <= current); }
			bool operator >=(const reverse_iterator& right) const { return (right.base() >= current); }
			difference_type operator -(const reverse_iterator& right) const { return (right.base() - current); }
		protected:
			RanIt current;
		};
		template<class RanIt, class Diff> inline reverse_iterator<RanIt> operator+(Diff offset, const reverse_iterator<RanIt>& right) { return (right + offset); }
		//template<class RanIt1, class RanIt2> inline typename reverse_iterator<RanIt1>::difference_type operator-(const reverse_iterator<RanIt1>& left, const reverse_iterator<RanIt2>& right) { return (left - right); }
		//template<class RanIt1, class RanIt2> inline bool operator==(const reverse_iterator<RanIt1>& left, const reverse_iterator<RanIt2>& right) { return (left == right); }
		//template<class RanIt1, class RanIt2> inline bool operator!=(const reverse_iterator<RanIt1>& left, const reverse_iterator<RanIt2>& right) { return (!(left.operator ==(right))); }
		//template<class RanIt1, class RanIt2> inline bool operator<(const reverse_iterator<RanIt1>& left, const reverse_iterator<RanIt2>& right) { return (left < right); }
		//template<class RanIt1, class RanIt2> inline bool operator>(const reverse_iterator<RanIt1>& left, const reverse_iterator<RanIt2>& right) { return (right < left); }
		//template<class RanIt1, class RanIt2> inline bool operator<=(const reverse_iterator<RanIt1>& left, const reverse_iterator<RanIt2>& right) { return (!(right < left)); }
		//template<class RanIt1, class RanIt2> inline bool operator>=(const reverse_iterator<RanIt1>& left, const reverse_iterator<RanIt2>& right) { return (!(left < right)); }
	}

#define wstring wstring_bad
#define string string_bad
#ifdef _XSTRING_
#error #include <xstring> already happened
#endif
#include <xstring>
#ifdef _STDEXCEPT_
#error #include <stdexcept> already happened
#endif
#include <stdexcept>  // implicitly #include <xstring>, because we want to get the references to string/wstring out of the way
#ifdef _STRING_
#error #include <string> already happened
#endif
#ifdef _XLOCALE_
#error include <xlocale> already happened
#endif
#define xdigit  blank = space, xdigit  // this is for when #include <xlocale> occurs
#include <string>
#undef  xdigit
	namespace std
	{
		using ::strchr;
		template<class T, class Ax = allocator<T> >
		class vector;
		template<class Char, class Traits = char_traits<Char> >
		struct basic_string_view;
		template<class Char, class Traits = char_traits<Char>, class Ax = allocator<Char> >
		class basic_string_good : public basic_string<Char, Traits, Ax>
		{
			typedef basic_string_good this_type;
			typedef basic_string<Char, Traits, Ax> base_type;
		public:
			basic_string_good() : base_type() { }
			basic_string_good(typename base_type::size_type const count, typename base_type::value_type const value, Ax const &ax = Ax()) : base_type(count, value, ax) { }
			basic_string_good(typename base_type::const_pointer const begin, typename base_type::const_pointer const end, Ax const &ax = Ax()) : base_type(begin, end, ax) { }
			basic_string_good(typename base_type::const_pointer const s, typename base_type::size_type const count, Ax const &ax = Ax()) : base_type(s, count, ax) { }
			basic_string_good(typename base_type::const_pointer const s, Ax const &ax = Ax()) : base_type(s, ax) { }
			basic_string_good(base_type const &right, size_type const off, size_type const count = base_type::npos, Ax const &ax = Ax()) : base_type(right, off, count, ax) { }
			basic_string_good(base_type base) : base_type() { base.swap(static_cast<base_type &>(*this)); }
			basic_string_good(vector<Char, Ax> const &base) : base_type() { this->insert(this->end(), base.begin(), base.end()); }
			basic_string_good(basic_string_view<Char, Traits> const &other, Ax const &ax = Ax()) : base_type(other.begin(), other.end(), ax) { }
			using base_type::append;
			this_type &append(basic_string_view<Char, Traits> const &other) { return static_cast<this_type &>(this->base_type::append(other.begin(), other.end())); }
			typename base_type::reference back() { return --*this->base_type::end(); }
			typename base_type::const_reference back() const { return --*this->base_type::end(); }
			typename base_type::reference front() { return *this->base_type::front(); }
			typename base_type::const_reference front() const { return *this->base_type::front(); }
			using base_type::data;
			pointer data() { return this->empty() ? NULL : &*this->begin(); }
			void pop_back() { this->base_type::erase(this->base_type::end() - 1); }
			void push_back(typename base_type::value_type const &value) { this->base_type::append(static_cast<typename base_type::size_type>(1), value); }
			void clear() { this->base_type::erase(this->base_type::begin(), this->base_type::end()); }
			this_type operator +(typename base_type::value_type const &c) const { this_type s(*this); s.insert(s.end(), c); return s; }
			this_type operator +(typename base_type::const_pointer const &other) const { this_type s(other); s.insert(s.begin(), this->base_type::begin(), this->base_type::end()); return s; }
			this_type operator +(base_type const &other) const { this_type s(other); s.insert(s.begin(), this->base_type::begin(), this->base_type::end()); return s; }
			void swap(this_type &other) { this->base_type::swap(static_cast<base_type &>(other)); }
			friend void swap(this_type &a, this_type &b) { swap(static_cast<base_type &>(a), static_cast<base_type &>(b)); }
			template<class Other> bool operator==(Other const &other) const { return static_cast<basic_string_view<Char, Traits> >(*this) == static_cast<basic_string_view<Char, Traits> >(other); }
			template<class Other> bool operator!=(Other const &other) const { return static_cast<basic_string_view<Char, Traits> >(*this) != static_cast<basic_string_view<Char, Traits> >(other); }
			template<class Other> bool operator<=(Other const &other) const { return static_cast<basic_string_view<Char, Traits> >(*this) <= static_cast<basic_string_view<Char, Traits> >(other); }
			template<class Other> bool operator>=(Other const &other) const { return static_cast<basic_string_view<Char, Traits> >(*this) >= static_cast<basic_string_view<Char, Traits> >(other); }
			template<class Other> bool operator< (Other const &other) const { return static_cast<basic_string_view<Char, Traits> >(*this) <  static_cast<basic_string_view<Char, Traits> >(other); }
			template<class Other> bool operator> (Other const &other) const { return static_cast<basic_string_view<Char, Traits> >(*this) >  static_cast<basic_string_view<Char, Traits> >(other); }
			friend bool operator==(const_pointer const left, this_type const &right) { return static_cast<basic_string_view<Char, Traits> >(left) == static_cast<basic_string_view<Char, Traits> >(right); }
			friend bool operator!=(const_pointer const left, this_type const &right) { return static_cast<basic_string_view<Char, Traits> >(left) != static_cast<basic_string_view<Char, Traits> >(right); }
			friend bool operator<=(const_pointer const left, this_type const &right) { return static_cast<basic_string_view<Char, Traits> >(left) <= static_cast<basic_string_view<Char, Traits> >(right); }
			friend bool operator>=(const_pointer const left, this_type const &right) { return static_cast<basic_string_view<Char, Traits> >(left) >= static_cast<basic_string_view<Char, Traits> >(right); }
			friend bool operator< (const_pointer const left, this_type const &right) { return static_cast<basic_string_view<Char, Traits> >(left) <  static_cast<basic_string_view<Char, Traits> >(right); }
			friend bool operator> (const_pointer const left, this_type const &right) { return static_cast<basic_string_view<Char, Traits> >(left) >  static_cast<basic_string_view<Char, Traits> >(right); }
		};
		template<class Char, class Traits>
		struct basic_string_view
		{
			typedef basic_string_view this_type;
			typedef Char value_type;
			typedef value_type *pointer;
			typedef value_type const *const_pointer;
			typedef value_type &reference;
			typedef value_type const &const_reference;
			typedef pointer iterator;
			typedef const_pointer const_iterator;
			typedef std::reverse_iterator<pointer> reverse_iterator;
			typedef std::reverse_iterator<const_pointer> const_reverse_iterator;
			typedef ptrdiff_t difference_type;
			typedef size_t size_type;
			static size_type const npos = static_cast<size_type>(~size_type());
			// reference back() { return *--this->end(); }
			const_reference back() const { return *--this->end(); }
			// iterator begin() { return this->_begin; }
			const_iterator begin() const { return this->_begin; }
			// pointer data() { return this->_begin; }
			const_pointer data() const { return this->_begin; }
			bool empty() const { return this->begin() == this->end(); }
			// iterator end() { return this->_end; }
			const_iterator end() const { return this->_end; }
			size_type find(const_pointer const s) const { size_type result = static_cast<size_type>(std::search(this->begin(), this->end(), s, s + static_cast<ptrdiff_t>(char_traits<Char>::length(s))) - this->begin()); if (result >= this->size()) { result = npos; } return result; }
			size_type find(value_type const &v) const { size_type result = static_cast<size_type>(std::find(this->begin(), this->end(), v) - this->begin()); if (result >= this->size()) { result = npos; } return result; }
			size_type find_first_of(value_type const &v) const { return this->find(v); }
			// reference front() { return *this->begin(); }
			const_reference front() const { return *this->begin(); }
			size_type length() const { return this->size(); }
			// reference operator[](size_type const i) { return this->begin()[static_cast<difference_type>(i)]; }
			const_reference operator[](size_type const i) const { return this->begin()[static_cast<difference_type>(i)]; }
			void remove_prefix(size_type const n) { this->_begin += static_cast<ptrdiff_t>(n); }
			void remove_suffix(size_type const n) { this->_end -= static_cast<ptrdiff_t>(n); }
			size_type size() const { return static_cast<size_type>(this->_end - this->_begin); }
			this_type substr(size_type const pos = 0, size_type const count = npos) const { return this_type(this->begin() + static_cast<difference_type>(pos), count == npos ? this->end() : this->begin() + static_cast<difference_type>(pos + count)); }
			basic_string_view() : _begin(), _end() { }
			template<class Ax>
			basic_string_view(vector<Char, Ax> const &str) : _begin(str.empty() ? NULL : &*str.begin()), _end((str.empty() ? NULL : &*str.begin()) + static_cast<ptrdiff_t>(str.size())) { }
			template<class Ax>
			basic_string_view(basic_string<Char, Traits, Ax> const &str) : _begin(str.empty() ? NULL : &*str.begin()), _end((str.empty() ? NULL : &*str.begin()) + static_cast<ptrdiff_t>(str.size())) { }
			basic_string_view(const_pointer const &s, size_type const n = npos) : _begin(s), _end(s + static_cast<ptrdiff_t>(n == npos ? char_traits<Char>::length(s) : n)) { }
			explicit basic_string_view(const_pointer const begin, const_pointer const end) : _begin(begin), _end(end) { }
			bool operator==(this_type const &other) const { return this->size() == other.size() && equal(this->begin(), this->end(), other.begin()); }
			bool operator!=(this_type const &other) const { return !(*this == other); }
			bool operator< (this_type const &other) const { return lexicographical_compare(this->begin(), this->end(), other.begin(), other.end(), less<value_type>()); }
			bool operator> (this_type const &other) const { return lexicographical_compare(this->begin(), this->end(), other.begin(), other.end(), greater<value_type>()); }
			bool operator<=(this_type const &other) const { return lexicographical_compare(this->begin(), this->end(), other.begin(), other.end(), less_equal<value_type>()); }
			bool operator>=(this_type const &other) const { return lexicographical_compare(this->begin(), this->end(), other.begin(), other.end(), greater_equal<value_type>()); }
			bool operator==(const_pointer const &other) const { return *this == static_cast<this_type>(other); }
			bool operator!=(const_pointer const &other) const { return *this != static_cast<this_type>(other); }
			bool operator< (const_pointer const &other) const { return *this <  static_cast<this_type>(other); }
			bool operator> (const_pointer const &other) const { return *this >  static_cast<this_type>(other); }
			bool operator<=(const_pointer const &other) const { return *this <= static_cast<this_type>(other); }
			bool operator>=(const_pointer const &other) const { return *this >= static_cast<this_type>(other); }
			friend bool operator==(const_pointer const &left, this_type const &right) { return right == left; }
			friend bool operator!=(const_pointer const &left, this_type const &right) { return right != left; }
			friend bool operator< (const_pointer const &left, this_type const &right) { return right >  left; }
			friend bool operator> (const_pointer const &left, this_type const &right) { return right <  left; }
			friend bool operator<=(const_pointer const &left, this_type const &right) { return right >= left; }
			friend bool operator>=(const_pointer const &left, this_type const &right) { return right <= left; }
		private:
			const_pointer _begin, _end;
		};
		typedef basic_string_view<char> string_view;
		typedef basic_string_view<wchar_t> wstring_view;

		template<class Traits, class Alloc> float stof(basic_string<char, Traits, Alloc> const &str) { return atof(static_cast<char const *>(str.c_str())); }
		template<class Traits, class Alloc> float stof(basic_string<wchar_t, Traits, Alloc> const &str) { return _wtof(static_cast<wchar_t const *>(str.c_str())); }
		template<class Traits, class Alloc> int stoi(basic_string<char, Traits, Alloc> const &str) { return atoi(static_cast<char const *>(str.c_str())); }
		template<class Traits, class Alloc> int stoi(basic_string<wchar_t, Traits, Alloc> const &str) { return _wtoi(static_cast<wchar_t const *>(str.c_str())); }
		template<class T> basic_string_good<char> to_string(T const &);
		template<> inline basic_string_good<char> to_string<int>(int const &value) { char buf[32]; buf[0] = '\0'; return itoa(value, buf, 10); }
		template<> inline basic_string_good<char> to_string<long>(long const &value) { char buf[32]; buf[0] = '\0'; return _ltoa(value, buf, 10); }
		template<> inline basic_string_good<char> to_string<long long>(long long const &value) { char buf[32]; buf[0] = '\0'; return _i64toa(value, buf, 10); }
	}

	// Fixes for 'vector' -- boost::ptr_vector chokes on the old implementation!
#ifdef _VECTOR_
#error #include <vector> already happened
#endif
#define vector vector_bad
#include <vector>
#undef  vector
	namespace std
	{
		template<class T, class Ax>
		class vector : public vector_bad<T, Ax>
		{
			typedef vector this_type;
			typedef vector_bad<T, Ax> base_type;
		public:
			typedef typename base_type::value_type value_type;
			typedef typename base_type::allocator_type allocator_type;
			typedef typename base_type::allocator_type::      pointer       pointer;
			typedef typename base_type::allocator_type::const_pointer const_pointer;
			typedef typename base_type::      iterator       iterator;
			typedef typename base_type::const_iterator const_iterator;
			typedef typename base_type::      reverse_iterator       reverse_iterator;
			typedef typename base_type::const_reverse_iterator const_reverse_iterator;
			vector() : base_type() { }
			explicit vector(size_type const count) : base_type(count) { }
			explicit vector(Ax const &ax) : base_type(ax) { }
			vector(size_type const count, Ax const &ax) : base_type(count, ax) { }
			vector(size_type const count, value_type const &value, Ax const &ax = Ax()) : base_type(count, value, ax) { }
			vector(const_pointer const begin, const_pointer const end, Ax const &ax = Ax()) : base_type(begin, end, ax) { }
			vector(this_type const &base) : base_type(static_cast<base_type const &>(base)) { }
			this_type &operator =(this_type const &other) { return static_cast<this_type &>(this->base_type::operator =(static_cast<base_type const &>(other))); }
#ifdef X_HAS_MOVE_SEMANTICS
			vector(this_type &&other) : base_type() { static_cast<base_type &>(other).swap(static_cast<base_type &>(*this)); other.clear(); }
			this_type &operator =(this_type &&other) { return (this_type(static_cast<this_type &&>(other)).swap(*this), *this); }
#endif
			const_iterator cbegin() const { return this->begin(); }
			const_iterator cend() const { return this->end(); }
			pointer data() { return this->empty() ? NULL : &*this->begin(); }
			const_pointer data() const { return this->empty() ? NULL : &*this->begin(); }
			void emplace_back() { this->push_back(value_type()); }
			template<class T1>
			void emplace_back(T1 const &arg1) { this->push_back(value_type(arg1)); }
			template<class T1, class T2>
			void emplace_back(T1 const &arg1, T2 const &arg2) { this->push_back(value_type(arg1, arg2)); }
			void shrink_to_fit() { vector(*this).swap(*this); }
			friend void swap(this_type &a, this_type &b) { using std::swap; swap(static_cast<base_type &>(a), static_cast<base_type &>(b)); }
		};
		struct _PVOID
		{
			void *p;
			_PVOID(void *const &p = 0) : p(p) { }
			template<class T> operator T *&() { return reinterpret_cast<T *&>(p); }
			template<class T> operator T *const &() const { return reinterpret_cast<T *const &>(p); }
		};
	}
	template<>
	class std::vector<void *, std::allocator<void *> > : public std::vector<void *, std::allocator<_PVOID> >
	{
	public:
		using std::vector<void *, std::allocator<_PVOID> >::insert;
		template<class It>
		void insert(iterator it, It begin, It end) { std::copy(begin, end, std::inserter(*this, it)); }
	};

#if 0
	template<>
	struct std::iterator_traits<std::vector<_Bool,_Bool_allocator>::_It>
	{
		typedef std::random_access_iterator_tag iterator_category;
		typedef unsigned int value_type;
		typedef ptrdiff_t difference_type;
		typedef ptrdiff_t distance_type;
		typedef unsigned int *pointer;
		typedef unsigned int &reference;
	};
#endif

#if !defined(_NATIVE_WCHAR_T_DEFINED) && (defined(DDK_CTYPE_WCHAR_FIX) && DDK_CTYPE_WCHAR_FIX)
#ifdef _DLL
	namespace std
	{
		template <class> class ctype;
		template <> class ctype<wchar_t>;
	}
#undef _DLL
#include <xlocale>
#define _DLL
	namespace std
	{
		template <>
		class ctype<wchar_t> : public ctype_base {
		public:
			typedef wchar_t _E;
			typedef _E char_type;
			bool is(mask _M, _E _C) const
				{return ((_Ctype._Table[(wchar_t)_C] & _M) != 0); }
			const _E *is(const _E *_F, const _E *_L, mask *_V) const
				{for (; _F != _L; ++_F, ++_V)
					*_V = _Ctype._Table[(wchar_t)*_F];
				return (_F); }
			const _E *scan_is(mask _M, const _E *_F,
				const _E *_L) const
				{for (; _F != _L && !is(_M, *_F); ++_F)
					;
				return (_F); }
			const _E *scan_not(mask _M, const _E *_F,
				const _E *_L) const
				{for (; _F != _L && is(_M, *_F); ++_F)
					;
				return (_F); }
			_E tolower(_E _C) const
				{return (do_tolower(_C)); }
			const _E *tolower(_E *_F, const _E *_L) const
				{return (do_tolower(_F, _L)); }
			_E toupper(_E _C) const
				{return (do_toupper(_C)); }
			const _E *toupper(_E *_F, const _E *_L) const
				{return (do_toupper(_F, _L)); }
			_E widen(wchar_t _X) const
				{return (_X); }
			const _E *widen(const wchar_t *_F, const wchar_t *_L, _E *_V) const
				{memcpy(_V, _F, _L - _F);
				return (_L); }
			_E narrow(_E _C, wchar_t _D = '\0') const
				{(_D); return (_C); }
			const _E *narrow(const _E *_F, const _E *_L, wchar_t _D,
				wchar_t *_V) const
				{(_D);memcpy(_V, _F, _L - _F);
				return (_L); }
			static locale::id id;
			explicit ctype(const mask *_Tab = 0, bool _Df = false,
				size_t _R = 0)
				: ctype_base(_R)
				{_Lockit Lk;
				_Init(_Locinfo());
				if (_Ctype._Delfl)
					free((void *)_Ctype._Table), _Ctype._Delfl = false;
				if (_Tab == 0)
					_Ctype._Table = _Cltab;
				else
					_Ctype._Table = _Tab, _Ctype._Delfl = _Df; }
			ctype(const _Locinfo& _Lobj, size_t _R = 0)
				: ctype_base(_R) {_Init(_Lobj); }
			static size_t __cdecl _Getcat()
				{return (_LC_CTYPE); }
			static const size_t table_size;
		_PROTECTED:
			virtual ~ctype()
				{if (_Ctype._Delfl)
					free((void *)_Ctype._Table); }
		protected:
			static void __cdecl _Term(void)
				{free((void *)_Cltab); }
			void _Init(const _Locinfo& _Lobj)
				{_Lockit Lk;
				_Ctype = _Lobj._Getctype();
				if (_Cltab == 0)
					{_Cltab = _Ctype._Table;
					atexit(_Term);
					_Ctype._Delfl = false; }}
			virtual _E do_tolower(_E _C) const
				{return (_E)(_Tolower((wchar_t)_C, &_Ctype)); }
			virtual const _E *do_tolower(_E *_F, const _E *_L) const
				{for (; _F != _L; ++_F)
					*_F = (_E)_Tolower(*_F, &_Ctype);
				return ((const _E *)_F); }
			virtual _E do_toupper(_E _C) const
				{return ((_E)_Toupper((wchar_t)_C, &_Ctype)); }
			virtual const _E *do_toupper(_E *_F, const _E *_L) const
				{for (; _F != _L; ++_F)
					*_F = (_E)_Toupper(*_F, &_Ctype);
				return ((const _E *)_F); }
			const mask *table() const _THROW0()
				{return (_Ctype._Table); }
			static const mask * __cdecl classic_table() _THROW0()
				{_Lockit Lk;
				if (_Cltab == 0)
					locale::classic();      // force locale::_Init() call
				return (_Cltab); }
		private:
			_Locinfo::_Ctypevec _Ctype;
			static const mask *_Cltab;
		};
		namespace
		{
			struct HINSTANCE__* get_msvcprt_handle()
			{
				static struct HINSTANCE__ *volatile g_hMSCRP60 = NULL;
				if (!g_hMSCRP60)
				{
					struct HINSTANCE__ *hMSCRP60 = NULL;
#if defined(_UNICODE) || defined(UNICODE)
					GetModuleHandleExW(0x4 | 0x2, reinterpret_cast<wchar_t const *>(&ctype<char>::id), &hMSCRP60);
#else
					GetModuleHandleExA(0x4 | 0x2, reinterpret_cast<char const *>(&ctype<char>::id), &hMSCRP60);
#endif
					_InterlockedCompareExchangePointer(&reinterpret_cast<void *volatile &>(g_hMSCRP60), hMSCRP60, NULL);
				}
				return g_hMSCRP60;
			}
		}
		template<> inline
			const ctype<wchar_t>& __cdecl use_facet<ctype<wchar_t> >(const locale& _L, const ctype<wchar_t> *,
				bool _Cfacet)
			{static const locale::facet *_Psave = 0;
			_Lockit _Lk;
			static locale::id *volatile g_ctype_wchar_t_id = NULL;
			if (!g_ctype_wchar_t_id)
			{ _InterlockedCompareExchangePointer(&reinterpret_cast<void *volatile &>(g_ctype_wchar_t_id), reinterpret_cast<locale::id *>(GetProcAddress(get_msvcprt_handle(), "?id@?$ctype@G@std@@2V0locale@2@A")), NULL); }
			size_t _Id = *g_ctype_wchar_t_id;
			const locale::facet *_Pf = _L._Getfacet(_Id, true);
			if (_Pf != 0)
				;
			else if (!_Cfacet || !_L._Iscloc())
				_THROW(bad_cast, "missing locale facet");
			else if (_Psave == 0)
				_Pf = _Psave = _Tidyfac<ctype<wchar_t>>::_Save(new ctype<wchar_t>);
			else
				_Pf = _Psave;
			return (*(const ctype<wchar_t> *)_Pf); }
	}
#endif
#endif

#pragma warning(push)
#pragma warning(disable: 4100)  // unreferenced formal parameter
#ifdef  _LOCALE_
#error include <locale> already happened
#endif
#include <locale>
	using std::codecvt;
#pragma warning(pop)

#ifdef  _SSTREAM_
#error include <sstream> already happened
#endif
#include <sstream>  // get rid of warnings
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable: 4127)  // conditional expression is constant
#ifdef  _FSTREAM_
#error include <fstream> already happened
#endif
#include <fstream>
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable: 4512)  // assignment operator could not be generated
#define set set_bad
#define multiset multiset_bad
#ifdef  _SET_
#error include <set> already happened
#endif
#include <set>
#undef  multiset
#undef  set
namespace std
{
	template<class K, class Pr = less<K>, class Ax = allocator<K> >
	class set : public set_bad<K, Pr, Ax>
	{
		typedef set this_type;
		typedef set_bad<K, Pr, Ax> base_type;
	public:
		explicit set(Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(pred, ax) { }
		set(typename base_type::const_iterator const &first, typename base_type::const_iterator const &last, Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(first, last, pred, ax)
		template<class It> set(It const &first, It const &last, Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(pred, ax) { this->insert<It>(first, last); }
		using base_type::insert;
		template<class It> void insert(It const &first, It const &last) { for (It i = first; i != last; ++i) { this->base_type::insert(*i); } }
	};
	template<class K, class Pr = less<K>, class Ax = allocator<K> >
	class multiset : public multiset_bad<K, Pr, Ax>
	{
		typedef multiset this_type;
		typedef multiset_bad<K, Pr, Ax> base_type;
	public:
		explicit multiset(Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(pred, ax) { }
		multiset(typename base_type::const_iterator const &first, typename base_type::const_iterator const &last, Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(first, last, pred, ax)
		template<class It> multiset(It const &first, It const &last, Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(pred, ax) { this->insert<It>(first, last); }
		using base_type::insert;
		template<class It> void insert(It const &first, It const &last) { for (It i = first; i != last; ++i) { this->base_type::insert(*i); } }
	};
}
#pragma warning(pop)

#pragma warning(push)
#define map map_bad
#define multimap multimap_bad
#ifdef  _MAP_
#error include <map> already happened
#endif
#include <map>
#undef  multimap
#undef  map
namespace std
{
	template<class K, class V, class Pr = less<K>, class Ax = allocator<V> >
	class map : public map_bad<K, V, Pr, Ax>
	{
		typedef map this_type;
		typedef map_bad<K, V, Pr, Ax> base_type;
	public:
		explicit map(Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(pred, ax) { }
		map(typename base_type::const_iterator const &first, typename base_type::const_iterator const &last, Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(first, last, pred, ax)
		template<class It> map(It const &first, It const &last, Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(pred, ax) { this->insert<It>(first, last); }
		using base_type::insert;
		template<class It> void insert(It const &first, It const &last) { for (It i = first; i != last; ++i) { this->base_type::insert(*i); } }
	};
	template<class K, class V, class Pr = less<K>, class Ax = allocator<V> >
	class multimap : public multimap_bad<K, V, Pr, Ax>
	{
		typedef multimap this_type;
		typedef multimap_bad<K, V, Pr, Ax> base_type;
	public:
		explicit multimap(Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(pred, ax) { }
		multimap(typename base_type::const_iterator const &first, typename base_type::const_iterator const &last, Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(first, last, pred, ax)
		template<class It> multimap(It const &first, It const &last, Pr const &pred = Pr(), Ax const &ax = Ax()) : base_type(pred, ax) { this->insert<It>(first, last); }
		using base_type::insert;
		template<class It> void insert(It const &first, It const &last) { for (It i = first; i != last; ++i) { this->base_type::insert(*i); } }
	};
}
#pragma warning(pop)

#pragma push_macro("min")
#pragma push_macro("max")
#undef min
#undef max
#ifdef  _VALARRAY_
#error include <valarray> already happened
#endif
#include <valarray>
#ifndef _CPPLIB_VER
namespace std
{
	template<class T> inline T const &min(T const &a, T const &b);
	template<class T> inline T const &max(T const &a, T const &b);
}
#endif
#pragma pop_macro("max")
#pragma pop_macro("min")


namespace std
{
	template<class T>
	class unique_ptr  // actually a reference-counted pointer here, to allow it to be copyable and thus storable in std::vector.
	{
		typedef unique_ptr this_type;
		void this_type_does_not_support_comparisons() const { }
	protected:
		typedef void (this_type::*bool_type)() const;
	public:
		T *p;
		ptrdiff_t *refcount;
	public:
		~unique_ptr()
		{
			if (T *const ptr = this->p)
			{
				--*this->refcount;
				if (!*this->refcount)
				{
					delete this->refcount;
					delete ptr;
				}
				this->refcount = NULL;
				this->p = NULL;
			}
		}
		unique_ptr() : p(), refcount() { }
		explicit unique_ptr(T *const p) : p(p), refcount() { if (this->p) { if (!this->refcount) { this->refcount = new ptrdiff_t(); } ++*this->refcount; } }
		unique_ptr(this_type const &other) : p(other.p), refcount(other.refcount) { if (this->p) { ++*this->refcount; } }
#ifdef X_HAS_MOVE_SEMANTICS
		unique_ptr(this_type &&other) : p(other.p), refcount(other.refcount) { other.p = NULL; other.refcount = NULL; }
		template<class U> unique_ptr(unique_ptr<U> &&other) : p(other.p), refcount(other.refcount) { other.p = NULL; other.refcount = NULL; }
#endif
#if defined(_MSC_VER) && _MSC_VER >= 1700
		unique_ptr(nullptr_t const &) : p(), refcount() { }
#else
		unique_ptr(void const volatile *const &) : p(), refcount() { }
#endif
		typedef T element_type;
		void swap(this_type &other) { using std::swap; swap(this->p, other.p); swap(this->refcount, other.refcount); }
		friend void swap(this_type &a, this_type &b) { return a.swap(b); }
		element_type *get() const { return this->p; }
		element_type &operator *() const { return *this->p; }
		element_type *operator->() const { return &**this; }
		void reset(element_type *const other = NULL) { this_type(other).swap(*this); }
		this_type &operator =(this_type other) { return (other.swap(*this), *this); }
		bool operator==(element_type *const other) const { return this->p == other; }
		bool operator!=(element_type *const other) const { return this->p != other; }
		bool operator<=(element_type *const other) const { return !std::less<element_type *>()(other, this->p); }
		bool operator>=(element_type *const other) const { return !std::less<element_type *>()(this->p, other); }
		bool operator< (element_type *const other) const { return std::less<element_type *>()(this->p, other); }
		bool operator> (element_type *const other) const { return std::less<element_type *>()(other, this->p); }
		bool operator==(this_type const &other) const { return *this == other.p; }
		bool operator!=(this_type const &other) const { return *this != other.p; }
		bool operator<=(this_type const &other) const { return *this <= other.p; }
		bool operator>=(this_type const &other) const { return *this >= other.p; }
		bool operator< (this_type const &other) const { return *this <  other.p; }
		bool operator> (this_type const &other) const { return *this >  other.p; }
		operator bool_type() const { return this->p ? &this_type::this_type_does_not_support_comparisons : NULL; }
	};
	template<class T>
	class unique_ptr<T[]> : public unique_ptr<T>
	{
		typedef unique_ptr this_type;
		typedef unique_ptr<T> base_type;
	public:
		~unique_ptr()
		{
			if (T *const other = this->p)
			{
				--*this->refcount;
				if (!*this->refcount)
				{
					delete this->refcount;
					delete [] other;
				}
				this->refcount = NULL;
				this->p = NULL;
			}
		}
		unique_ptr() : base_type() { }
		explicit unique_ptr(typename base_type::element_type *const other) : base_type(other) { }
		unique_ptr(this_type const &other) : base_type(static_cast<base_type const &>(other)) { }
#ifdef X_HAS_MOVE_SEMANTICS
		unique_ptr(this_type &&other) : base_type(static_cast<base_type &&>(other)) { }
		template<class U> unique_ptr(unique_ptr<U[]> &&other) : base_type(static_cast<unique_ptr<U> &&>(other)) { }
#endif
#if defined(_MSC_VER) && _MSC_VER >= 1700
		unique_ptr(nullptr_t const &other) : base_type(other) { }
#else
		unique_ptr(void const volatile *const &other) : base_type(other) { }
#endif
		this_type &operator =(this_type other) { return (other.swap(*this), *this); }
		typename base_type::element_type &operator[](size_t const i) const { return this->p[i]; }
		void reset(typename base_type::element_type *const other = NULL) { this_type(other).swap(*this); }
	};
	template<class T>
	struct unique_maker
	{
		static unique_ptr<T> make_unique() { return unique_ptr<T>(new T()); }
		template<class T1> static unique_ptr<T> make_unique(T1 const &arg1) { return unique_ptr<T>(new T(arg1)); }
		template<class T1, class T2> static unique_ptr<T> make_unique(T1 const &arg1, T2 const &arg2) { return unique_ptr<T>(new T(arg1, arg2)); }
		template<class T1, class T2, class T3> static unique_ptr<T> make_unique(T1 const &arg1, T2 const &arg2, T3 const &arg3) { return unique_ptr<T>(new T(arg1, arg2, arg3)); }
		template<class T1, class T2, class T3, class T4> static unique_ptr<T> make_unique(T1 const &arg1, T2 const &arg2, T3 const &arg3, T4 const &arg4) { return unique_ptr<T>(new T(arg1, arg2, arg3, arg4)); }
	};
	template<class T>
	struct unique_maker<T[]>
	{
		template<class T1>
		static unique_ptr<T[]> make_unique(T1 const &size) { return unique_ptr<T[]>(new T[size]()); }
	};
	template<class T> unique_ptr<T> make_unique() { return unique_maker<T>::make_unique(); }
	template<class T, class T1> unique_ptr<T> make_unique(T1 const &arg1) { return unique_maker<T>::make_unique<T1>(arg1); }
	template<class T, class T1, class T2> unique_ptr<T> make_unique(T1 const &arg1, T2 const &arg2) { return unique_maker<T>::make_unique<T1, T2>(arg1, arg2); }
	template<class T, class T1, class T2, class T3> unique_ptr<T> make_unique(T1 const &arg1, T2 const &arg2, T3 const &arg3) { return unique_maker<T>::make_unique<T1, T2, T3>(arg1, arg2, arg3); }
	template<class T, class T1, class T2, class T3, class T4> unique_ptr<T> make_unique(T1 const &arg1, T2 const &arg2, T3 const &arg3, T4 const &arg4) { return unique_maker<T>::make_unique<T1, T2, T3, T4>(arg1, arg2, arg3, arg4); }

}

namespace std
{
	template<class T> typename T::iterator begin(T &value) { return value.begin(); }
	template<class T> typename T::const_iterator begin(T const &value) { return value.begin(); }
	template<class T, size_t N> T *begin(T (&value)[N]) { return &value[0]; }
	template<class T, size_t N> T const *begin(T const (&value)[N]) { return &value[0]; }
	template<class T> typename T::iterator end(T &value) { return value.end(); }
	template<class T> typename T::const_iterator end(T const &value) { return value.end(); }
	template<class T, size_t N> T *end(T (&value)[N]) { return &value[N]; }
	template<class T, size_t N> T const *end(T const (&value)[N]) { return &value[N]; }

#ifdef X_HAS_MOVE_SEMANTICS
	template<class InputIt, class OutputIt>
	OutputIt move(InputIt first, InputIt last, OutputIt d_first) { while (first != last) { *d_first++ = move(*first++); } return d_first; }
	template<class BidirIt1, class BidirIt2>
	BidirIt2 move_backward(BidirIt1 first, BidirIt1 last, BidirIt2 d_last) { while (first != last) { *(--d_last) = move(*(--last)); } return d_last; }
#endif
	template<class InputIt, class UnaryPredicate>
	InputIt find_if_not(InputIt first, InputIt last, UnaryPredicate q) { return find_if(first, last, not1(q)); }
	template<class InputIt, class UnaryPredicate>
	bool all_of(InputIt first, InputIt last, UnaryPredicate p) { return find_if_not(first, last, p) == last; }
	template<class InputIt, class UnaryPredicate>
	bool any_of(InputIt first, InputIt last, UnaryPredicate p) { return find_if(first, last, p) != last; }
	template<class InputIt, class UnaryPredicate>
	bool none_of(InputIt first, InputIt last, UnaryPredicate p) { return find_if(first, last, p) == last; }
}

namespace std
{
	template<class From, class To> struct propagate_const_from { typedef To type; };
	template<class From, class To> struct propagate_const_from<From const, To> : propagate_const_from<From, To const> { };
	template<class From, class To> struct propagate_const_from<From &, To> : propagate_const_from<From, To> { };

	template<class, class = void, class = void> struct tuple;
	template<class T1, class T2>
	struct tuple<T1, T2> : pair<T1, T2>
	{
		typedef pair<T1, T2> base_type;
		tuple() : base_type() { }
		explicit tuple(T1 const &arg1, T2 const &arg2) : base_type(arg1, arg2) { }
	};
	template<size_t I, class Tuple> struct tuple_element;
	template<class Tuple> struct tuple_element<1 - 1, Tuple> { typedef typename propagate_const_from<Tuple, typename Tuple:: first_type>::type type; static type &get(Tuple &tup) { return tup.first ; } };
	template<class Tuple> struct tuple_element<2 - 1, Tuple> { typedef typename propagate_const_from<Tuple, typename Tuple::second_type>::type type; static type &get(Tuple &tup) { return tup.second; } };
	template<class Tuple> struct tuple_element<3 - 1, Tuple> { typedef typename propagate_const_from<Tuple, typename Tuple:: third_type>::type type; static type &get(Tuple &tup) { return tup.third ; } };
	template<size_t I, class Tuple> typename tuple_element<I, Tuple>::type &get(Tuple &tup) { return tuple_element<I, Tuple>::get(tup); }
}

namespace std
{
	inline long long abs(long long const value) { return _abs64(value); }
	template<class T, class Compare> T const &clamp(T const &v, T const &lo, T const &hi, Compare comp) { return comp(v, lo) ? lo : comp(hi, v) ? hi : v; }
	template<class T> T const &clamp(T const &v, T const &lo, T const &hi) { return clamp(v, lo, hi, less<T>()); }
}
using std::abs;

#include <list>
namespace std
{
	template<class T, class Ax = allocator<T> >
	class forward_list : public list<T, Ax>
	{
		typedef forward_list this_type;
		typedef list<T, Ax> base_type;
		struct before_begin_iterator { typename base_type::iterator i; };
	public:
		using base_type::remove_if;
		before_begin_iterator before_begin() { before_begin_iterator r = { this->base_type::begin() }; return r; }
		void splice_after(before_begin_iterator pos, this_type &other) { this->base_type::splice(pos.i, other); }
		template<class Pr>
		void remove_if(Pr pr) { typename base_type::iterator l = this->base_type::end(); for (typename base_type::iterator f = this->base_type::begin(); f != l; ) if (pr(*f)) { this->base_type::erase(f++); } else { ++f; } }
	};
}

namespace std
{
	template<class T>
	class initializer_list
	{
	public:
		typedef T value_type;
		typedef const T& reference;
		typedef const T& const_reference;
		typedef size_t size_type;
		typedef const T* iterator;
		typedef const T* const_iterator;
		initializer_list() _NOEXCEPT : _begin(), _end() { }
		initializer_list(T const *first, T const *last) _NOEXCEPT : _begin(first), _end(last) { }
		T const *begin() const _NOEXCEPT { return begin; }
		T const *end() const _NOEXCEPT { return _end; }
		size_t size() const _NOEXCEPT { return (size_t) (_end - _begin); }
	private:
		T const *_begin, *_end;
	};
}

namespace std
{
	_CRTIMP2_PURE inline void __CLRCALL_PURE_OR_CDECL _Xbad_alloc() { throw bad_alloc(); }
	template<class InIt1, class InIt2, class Pr>
	inline bool equal(InIt1 First1, InIt1 Last1, InIt2 First2, InIt2 Last2, Pr Pred)
	{
		for (; First1 != Last1 && First2 != Last2; ++First1, (void)++First2)
			if (!Pred(*First1, *First2))
				return false;
		return (First1 == Last1 && First2 == Last2);
	}
	template<class T> inline void _Swap_adl(T &a, T &b) { return swap(a, b); }
	struct _Container_base { };
	struct _Container_base0 { void _Orphan_all() { } void _Swap_all(_Container_base0 &) { } };
	struct _Iterator_base0 { void _Adopt(const void *) { } _Container_base0 const *_Getcont() const { return 0; } };
	typedef _Iterator_base0 _Iterator_base;
	template<class Category, class Ty, class Diff, class Pointer, class Reference, class Base>
	struct _Iterator012 : public Base
	{
		typedef Category iterator_category;
		typedef Ty value_type;
		typedef Diff difference_type;
		typedef Pointer pointer;
		typedef Reference reference;
	};
	typedef unsigned long _Uint32t;
	typedef _Uint32t _Uint4_t;
	typedef _Uint4_t _Atomic_integral_t;
	typedef _Atomic_integral_t _Atomic_counter_t;
	template<class It> inline It _Unchecked(It s) { return s; }
}
#ifdef _BITMASK_OPS
#undef _BITMASK_OPS
#endif
#define _BITMASK_OPS(T) \
	inline T operator |(T const a, T const b) { return static_cast<T>(static_cast<int>(a) | static_cast<int>(b)); } \
	inline T operator &(T const a, T const b) { return static_cast<T>(static_cast<int>(a) & static_cast<int>(b)); } \
	inline T operator ^(T const a, T const b) { return static_cast<T>(static_cast<int>(a) ^ static_cast<int>(b)); } \
	inline T operator ~(T const v) { return static_cast<T>(~static_cast<int>(v)); } \
	inline T &operator |=(T &a, T const b) { return a = (a | b); } \
	inline T &operator &=(T &a, T const b) { return a = (a & b); } \
	inline T &operator ^=(T &a, T const b) { return a = (a ^ b); }

#define _DEBUG_RANGE(first, last)
#define _SCL_SECURE_VALIDATE(cond)
#define _SCL_SECURE_VALIDATE_RANGE(cond)

#undef  X_HAS_MOVE_SEMANTICS
#endif

// This should be AFTER all standard headers are included

#undef wstring
#undef string
#define basic_string basic_string_good
namespace std
{
	typedef basic_string<char> string;
	typedef basic_string<wchar_t> wstring;
}


#if defined __cplusplus_cli
#define EHVEC_CALEETYPE __clrcall
#else
#define EHVEC_CALEETYPE __stdcall
#endif
#if defined __cplusplus_cli
#define EHVEC_CALLTYPE __clrcall 
#elif defined _M_IX86
#define EHVEC_CALLTYPE __thiscall
#else
#define EHVEC_CALLTYPE __stdcall
#endif

#if defined(_MSC_VER) && _MSC_VER >= 1900
void EHVEC_CALEETYPE __ArrayUnwind(
	void*       ptr,                // Pointer to array to destruct
	size_t      size,               // Size of each element (including padding)
	int         count,              // Number of elements in the array
	void(EHVEC_CALLTYPE *pDtor)(void*)    // The destructor to call
);

inline void EHVEC_CALEETYPE __ehvec_ctor(
	void*       ptr,                // Pointer to array to destruct
	size_t      size,               // Size of each element (including padding)
	//  int         count,              // Number of elements in the array
	size_t      count,              // Number of elements in the array
	void(EHVEC_CALLTYPE *pCtor)(void*),   // Constructor to call
	void(EHVEC_CALLTYPE *pDtor)(void*)    // Destructor to call should exception be thrown
) {
	size_t i = 0;      // Count of elements constructed
	int success = 0;

	__try
	{
		// Construct the elements of the array
		for (; i < count; i++)
		{
			(*pCtor)(ptr);
			ptr = (char*)ptr + size;
		}
		success = 1;
	}
	__finally
	{
		if (!success)
			__ArrayUnwind(ptr, size, (int)i, pDtor);
	}
}

inline void EHVEC_CALEETYPE __ehvec_dtor(
	void*       ptr,                // Pointer to array to destruct
	size_t      size,               // Size of each element (including padding)
	//  int         count,              // Number of elements in the array
	size_t      count,              // Number of elements in the array
	void(EHVEC_CALLTYPE *pDtor)(void*)    // The destructor to call
) {
	int success = 0;

	// Advance pointer past end of array
	ptr = (char*)ptr + size*count;

	__try
	{
		// Destruct elements
		while (count-- > 0)
		{
			ptr = (char*)ptr - size;
			(*pDtor)(ptr);
		}
		success = 1;
	}
	__finally
	{
		if (!success)
			__ArrayUnwind(ptr, size, (int)count, pDtor);
	}
}
#endif

#pragma push_macro("_set_se_translator")
extern "C" __inline _se_translator_function __cdecl __set_se_translator(_se_translator_function f)
{
	_se_translator_function (__cdecl *p_set_se_translator)(_se_translator_function f) = &_set_se_translator;
	return p_set_se_translator(f);
}
#define _set_se_translator __set_se_translator
typedef struct _EXCEPTION_POINTERS EXCEPTION_POINTERS;
typedef unsigned int UINT;
#include <ProvExce.h>
#pragma pop_macro("_set_se_translator")

#endif

#pragma warning(pop)

#ifdef __cplusplus_cli
#pragma managed(pop)
#endif
#endif
