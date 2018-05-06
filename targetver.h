#pragma once

#define _WIN32_WINNT 0x502
#include <SDKDDKVer.h>

#ifdef _MSC_VER
// ============= Put these FIRST ============
#if _MSC_VER < 1900
#pragma warning(disable: 4616)  // not a valid compiler warning
#pragma warning(disable: 4619)  // #pragma warning : there is no warning number
#endif
// ==========================================

#ifndef _DEBUG
#pragma warning(disable: 4005)  // macro redefinition  // Only in DDK compilations (which are Release-mode)...
#endif
#pragma warning(disable: 4062)  // enumerator in switch of enum is not handled
#pragma warning(disable: 4100)  // unreferenced formal parameter
#ifndef _DEBUG
#pragma warning(disable: 4163)  // not available as an intrinsic function  // Only in DDK compilations (which are Release-mode)...
#endif
#pragma warning(disable: 4191)  // 'reinterpret_cast': unsafe conversion
#pragma warning(disable: 4265)  // class has virtual functions, but destructor is not virtual
#pragma warning(disable: 4290)  // C++ exception specification ignored except to indicate a function is not __declspec(nothrow)
#pragma warning(disable: 4324)  // structure was padded due to __declspec(align())
#pragma warning(disable: 4365)  // conversion, signed/unsigned mismatch
#pragma warning(disable: 4371)  // layout of class may have changed from a previous version of the compiler due to better packing of member
#pragma warning(disable: 4435)  // Object layout under /vd2 will change due to virtual base
#pragma warning(disable: 4458)  // declaration of 'field' hides class member
#pragma warning(disable: 4459)  // declaration of 'identifier' hides global declaration
#ifndef _DEBUG
#pragma warning(disable: 4505)  // unreferenced local function has been removed
#endif
#pragma warning(disable: 4510)  // default constructor could not be generated
#pragma warning(disable: 4512)  // assignment operator could not be generated
#pragma warning(disable: 4610)  // can never be instantiated - user defined constructor required
#pragma warning(disable: 4623)  // default constructor was implicitly defined as deleted
#pragma warning(disable: 4624)  // destructor was implicitly defined as deleted because a base class destructor is inaccessible or deleted
#pragma warning(disable: 4625)  // copy constructor was implicitly defined as deleted
#pragma warning(disable: 4626)  // assignment operator was implicitly defined as deleted
#pragma warning(disable: 4668)  // 'MACRO' is not defined as a preprocessor macro, replacing with '0' for '#if/#elif'
#pragma warning(disable: 4710)  // function not inlined
#pragma warning(disable: 4711)  // function selected for automatic inline expansion
#pragma warning(disable: 4820)  // 'n' bytes padding added after data member
// #pragma warning(disable: 4838)  // conversion requires a narrowing conversion
#pragma warning(disable: 5026)  // move constructor was implicitly defined as deleted
#pragma warning(disable: 5027)  // move assignment operator was implicitly defined as deleted
#endif

#define _USE_MATH_DEFINES 1
#define _CRT_OBSOLETE_NO_WARNINGS 1
#define _CRT_SECURE_NO_WARNINGS 1
#define _SCL_SECURE_NO_WARNINGS 1
#define _CRT_NON_CONFORMING_SWPRINTFS 1
#define _STRALIGN_USE_SECURE_CRT 0
#define _ATL_NO_COM 1
#define _ATL_NO_AUTOMATIC_NAMESPACE 1
#define _ATL_DISABLE_DEPRECATED 1
#define _WTL_NO_AUTOMATIC_NAMESPACE 1
#define _WTL_USE_VSSYM32 1
#define STRICT 1
#define NOMINMAX 1
#define BUILD_WINDOWS 1
#define BOOST_ALL_NO_LIB 1
#define BOOST_DISABLE_ASSERTS 1
#define BOOST_EXCEPTION_DISABLE 1

#ifndef _DEBUG
#define _SECURE_SCL 0
#define _ITERATOR_DEBUG_LEVEL 0
#define __STDC_WANT_SECURE_LIB__ 0
#define _STRALIGN_USE_SECURE_CRT 0
#define __SIZEOF_LONG_LONG__ (ULLONG_MAX / (UCHAR_MAX + 1U) + 1)
#define __SIZEOF_WCHAR_T__ (WCHAR_MAX / (UCHAR_MAX + 1U) + 1)
#endif
