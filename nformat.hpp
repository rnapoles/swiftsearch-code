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
	NumberFormatter() : ascii(true) { }
	explicit NumberFormatter(std::locale const &loc) : ascii(false) { this->ss.imbue(loc); }
	
	template<class V>
	static void format_fast_ascii_append(std::basic_string<TCHAR> &result, V value, size_t const min_width)
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

	template<class T>
	std::basic_string<TCHAR> const &operator()(T v)
	{
		if (this->ascii)
		{
			result.erase(result.begin(), result.end());
			this->format_fast_ascii_append<T>(result, v, 0);
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
};

#endif