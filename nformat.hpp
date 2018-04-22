#pragma once

#ifndef NFORMAT_HPP
#define NFORMAT_HPP

#include <tchar.h>

#include <locale>
#include <string>
#include <sstream>

std::locale get_numpunct_locale(std::locale const &loc)
{
	std::locale result(loc);
#if defined(_MSC_VER) && defined(_ADDFAC)
	std::_ADDFAC(result, new std::numpunct<TCHAR>());
#else
	result = std::locale(locale, new std::numpunct<TCHAR>());
#endif
	return result;
}

class NumberFormatter
{
	std::basic_string<TCHAR> result;
	struct SS : public std::basic_stringstream<TCHAR>
	{
		typedef std::basic_stringstream<char_type, traits_type> base_type;
#if defined(_MSC_VER) && !defined(_WIN64) && (!defined(_CPPLIB_VER) || _CPPLIB_VER < 403)
		struct NumPunctFacet : public _Nput
		{
			typedef TCHAR _E;
			typedef std::ostreambuf_iterator<_E, std::char_traits<_E> > _OI;
			static char *__cdecl _Ifmt(char *_Fmt, const char *_Spec, ios_base::fmtflags _Fl)
			{
				char *_S = _Fmt;
				*_S++ = '%';
				if (_Fl & ios_base::showpos)
				{ *_S++ = '+'; }
				if (_Fl & ios_base::showbase)
				{ *_S++ = '#'; }
				*_S++ = _Spec[0];
				*_S++ = _Spec[1];
				*_S++ = _Spec[2];
				*_S++ = _Spec[3];
				*_S++ = _Spec[4];
				ios_base::fmtflags _Bfl = _Fl & ios_base::basefield;
				*_S++ = _Bfl == ios_base::oct ? 'o'
					: _Bfl != ios_base::hex ? _Spec[5]      // 'd' or 'u'
					: _Fl & ios_base::uppercase ? 'X' : 'x';
				*_S = '\0';
				return (_Fmt);
			}
			_OI do_put(_OI _F, ios_base& _X, _E _Fill, __int64 _V) const
			{
				char _Buf[2 * _MAX_INT_DIG], _Fmt[12];
				return (_Iput(_F, _X, _Fill, _Buf, sprintf(_Buf, _Ifmt(_Fmt, "I64lld", _X.flags()), _V)));
			}
			_OI do_put(_OI _F, ios_base& _X, _E _Fill, unsigned __int64 _V) const
			{
				char _Buf[2 * _MAX_INT_DIG], _Fmt[12];
				return (_Iput(_F, _X, _Fill, _Buf, sprintf(_Buf, _Ifmt(_Fmt, "I64llu", _X.flags()), _V)));
			}
		};
		template<class V>
		SS &custom_leftshift(V _X)
		{
			iostate _St = goodbit;
			const std::basic_ostringstream<TCHAR>::sentry _Ok(*this);
			if (_Ok)
			{
				const _Nput& _Fac = _USE(getloc(), _Nput);
				_TRY_IO_BEGIN
					if (static_cast<NumPunctFacet const &>(_Fac).do_put(std::basic_ostringstream<TCHAR>::_Iter(rdbuf()), *this, fill(), _X).failed())
					{
						_St |= badbit;
					}
				_CATCH_IO_END
			}
			setstate(_St);
			return *this;
		}
		using std::basic_ostringstream<TCHAR>::operator<<;
		SS &operator <<(long long x) { return this->custom_leftshift(x); }
		SS &operator <<(unsigned long long x) { return this->custom_leftshift(x); }
#endif
};
	SS ss;
	bool ascii;
public:
	explicit NumberFormatter(std::locale const &loc) : ascii(false)
	{
		this->ss.imbue(loc);
	}

#ifdef _M_X64
	static unsigned int base_10_digits(unsigned long long x)
	{
		// https://stackoverflow.com/a/25934909
		unsigned int digits = 0;
		unsigned long leading_zero = 0;
		switch (_BitScanReverse64(&leading_zero, x) ? leading_zero + 1 : 0)
		{
		case 0: case 1: case 2: case 3: digits = 0; break;
		case 4: case 5: case 6: digits = 1; break;
		case 7: case 8: case 9: digits = 2; break;
		case 10: case 11: case 12: case 13: digits = 3; break;
		case 14: case 15: case 16: digits = 4; break;
		case 17: case 18: case 19: digits = 5; break;
		case 20: case 21: case 22: case 23: digits = 6; break;
		case 24: case 25: case 26: digits = 7; break;
		case 27: case 28: case 29: digits = 8; break;
		case 30: case 31: case 32: case 33: digits = 9; break;
		case 34: case 35: case 36: digits = 10; break;
		case 37: case 38: case 39: digits = 11; break;
		case 40: case 41: case 42: case 43: digits = 12; break;
		case 44: case 45: case 46: digits = 13; break;
		case 47: case 48: case 49: digits = 14; break;
		case 50: case 51: case 52: case 53: digits = 15; break;
		case 54: case 55: case 56: digits = 16; break;
		case 57: case 58: case 59: digits = 17; break;
		case 60: case 61: case 62: case 63: digits = 18; break;
		case 64: digits = 19; break;
		default: break;
		}
		unsigned long long i = 0;
		switch (digits)
		{
		case  0: i = 1; break;
		case  1: i = 10; break;
		case  2: i = 100; break;
		case  3: i = 1000; break;
		case  4: i = 10000; break;
		case  5: i = 100000; break;
		case  6: i = 1000000; break;
		case  7: i = 10000000; break;
		case  8: i = 100000000; break;
		case  9: i = 1000000000; break;
		case 10: i = 10000000000; break;
		case 11: i = 100000000000; break;
		case 12: i = 1000000000000; break;
		case 13: i = 10000000000000; break;
		case 14: i = 100000000000000; break;
		case 15: i = 1000000000000000; break;
		case 16: i = 10000000000000000; break;
		case 17: i = 100000000000000000; break;
		case 18: i = 1000000000000000000; break;
		case 19: i = 10000000000000000000; break;
		default: break;
		}
		return digits + (x >= i);
	}
#endif

	template<class V>
	static void format_fast_ascii_append(std::basic_string<TCHAR> &result, V value, size_t const min_width);

	std::basic_string<TCHAR> const &operator()(unsigned long long v);
};


template<class V>
inline void NumberFormatter::format_fast_ascii_append(std::basic_string<TCHAR> &result, V value, size_t const min_width)
{
	size_t const n = result.size();
	V const radix = 10;
	for (size_t i = 0; value != 0 || i < min_width; ++i)
	{
		V rem = static_cast<V>(value % radix);
		while (rem < 0) { rem += radix; }
		result += static_cast<TCHAR>(_T('0') + rem);
		value /= radix;
	}
	std::reverse(result.begin() + static_cast<ptrdiff_t>(n), result.end());
}

#ifdef _M_X64
template<>
inline void NumberFormatter::format_fast_ascii_append<unsigned long long>(std::basic_string<TCHAR> &result, unsigned long long value, size_t const min_width)
{
	size_t digits10 = base_10_digits(static_cast<unsigned long long>(value));
	if (digits10 < min_width) { digits10 = min_width; }
	size_t const n = result.size();
	result.resize(n + digits10);
	unsigned char const radix = 10;
	for (size_t i = 0; value != 0 || i < min_width; ++i)
	{
		long long rem = static_cast<long long>(value % radix);
		while (rem < 0) { rem += radix; }
		result[n + digits10 - 1 - i] = static_cast<TCHAR>(_T('0') + rem);
		value /= radix;
	}
}
#endif

inline std::basic_string<TCHAR> const &NumberFormatter::operator()(unsigned long long v)
{
	if (this->ascii)
	{
		result.erase(result.begin(), result.end());
		this->format_fast_ascii_append(result, v, 0);
	}
	else
	{
		ss.str(std::basic_string<TCHAR>());
		ss.clear();
		ss << v;
		ss.seekg(0);
		ss >> result;
	}
	return result;
}

#endif
