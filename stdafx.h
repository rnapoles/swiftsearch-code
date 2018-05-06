#pragma once

#include "targetver.h"


#if defined(__STDC_WANT_SECURE_LIB__) && !__STDC_WANT_SECURE_LIB__
#if !(defined(_MSC_VER) && _MSC_VER <= 1400)
#define sprintf_s(buf, size, ...) sprintf(buf, __VA_ARGS__)
#define swprintf_s(buf, size, ...) swprintf(buf, size, __VA_ARGS__)
#define wcstok_s(tok, delim, ctx) wcstok(tok, delim)
#define wcstok_s(tok, delim, ctx) wcstok(tok, delim)
#define wcscpy_s(a, b, c) wcscpy(a, c)
#define wcscat_s(a, b, c) wcscat(a, c)
#define memcpy_s(a, b, c, d) memcpy(a, c, d)
#define memmove_s(a, b, c, d) memmove(a, c, d)
#define wmemcpy_s(a, b, c, d) wmemcpy(a, c, d)
#define wmemmove_s(a, b, c, d) wmemmove(a, c, d)
#define strcpy_s(a, b, c) strcpy(a, c)
#define strncpy_s(a, b, c, d) strncpy(a, c, d)
#define wcsncpy_s(a, b, c, d) wcsncpy(a, c, d)
#define vswprintf_s(a, b, c, d) _vstprintf(a, c, d)
#define strcat_s(a, b, c) strcat(a, c)
#define ATL_CRT_ERRORCHECK(A) ((A), 0)
#endif
#endif


#pragma warning(push)
#pragma warning(disable: 4571)  // Informational: catch(...) semantics changed since Visual C++ 7.1; structured exceptions (SEH) are no longer caught
#include "WinDDKFixes.hpp"

#include <process.h>
#include <stddef.h>
#include <stdio.h>
#include <tchar.h>
#include <time.h>

#include <algorithm>
#include <cassert>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <utility>
#include <vector>
#pragma warning(pop)

namespace WTL { using std::min; using std::max; }

#ifndef _CPPLIB_VER
#define __movsb __movsb_
#define __movsd __movsd_
#define __movsw __movsw_
#define __movsq __movsq_
#endif
#include <Windows.h>
#ifndef _CPPLIB_VER
#undef __movsq
#undef __movsw
#undef __movsd
#undef __movsb
#endif

#pragma warning(push)
#pragma warning(disable: 4191)  // 'type cast': unsafe conversion
#pragma warning(disable: 4265)  // class has virtual functions, but destructor is not virtual
#pragma warning(disable: 4302)
#pragma warning(disable: 4365)
#pragma warning(disable: 4457)  // declaration of 'pstr' hides function parameter
#pragma warning(disable: 4555)  // expression has no effect; expected expression with side-effect
#pragma warning(disable: 4838)  // conversion requires a narrowing conversion
#pragma warning(disable: 4917)  // a GUID can only be associated with a class, interface or namespace
#pragma warning(disable: 4987)  // nonstandard extension used: 'throw (...)'
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
#pragma warning(pop)


#if defined(__STDC_WANT_SECURE_LIB__) && !__STDC_WANT_SECURE_LIB__
#if !(defined(_MSC_VER) && _MSC_VER <= 1400)
#undef sprintf_s
#undef swprintf_s
#undef wcstok_s
#undef wcstok_s
#undef wcscpy_s
#undef wcscat_s
#undef memcpy_s
#undef memmove_s
#undef wmemcpy_s
#undef wmemmove_s
#undef strcpy_s
#undef strncpy_s
#undef wcsncpy_s
#undef vswprintf_s
#undef strcat_s
#undef ATL_CRT_ERRORCHECK
#endif
#endif
