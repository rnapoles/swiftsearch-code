#pragma once

#include <memory.h>

#include <Windows.h>

class Hook
{
	Hook(Hook const &);
	Hook &operator =(Hook const &);
	int set_hook(void *new_proc)
	{
		int r;
		unsigned char *const proc_buf = reinterpret_cast<unsigned char *const &>(*this->ptr);
#ifdef _WIN64
		if (memcmp(&proc_buf[0], "\x4C\x8B\xD1\xB8", 4) == 0 &&
			memcmp(&proc_buf[8], "\xF6\x04\x25", 3) == 0 &&
			memcmp(&proc_buf[16], "\x75\x03\x0F\x05\xC3\xCD\x2E\xC3", 8) == 0)
		{
			unsigned int const proc_buf_size = sizeof(this->old_proc);
			memcpy(this->old_proc, proc_buf, proc_buf_size);
			DWORD old_protect;
			if (VirtualProtect(this->old_proc, proc_buf_size, PAGE_EXECUTE_READWRITE, &old_protect) &&
				VirtualProtect(proc_buf, proc_buf_size, PAGE_EXECUTE_READWRITE, &old_protect))
			{
				ptrdiff_t j = 0;
				proc_buf[j++] = 0x48;
				proc_buf[j++] = 0xB8;
				j += ((void)memcpy(&proc_buf[j], &new_proc, sizeof(new_proc)), sizeof(new_proc));
				proc_buf[j++] = 0xFF;
				proc_buf[j++] = 0xE0;
				VirtualProtect(proc_buf, proc_buf_size, old_protect, &old_protect);
				*this->ptr = reinterpret_cast<func_type *>(&this->old_proc[0]);
				r = 1;
			}
			else { r = 0; }
		}
		else { r = 0; }
#else
		if (memcmp(&proc_buf[0], "\xB8", 1) == 0 &&
			memcmp(&proc_buf[5], "\xE8", 1) == 0 &&
			memcmp(&proc_buf[10], "\xC2", 1) == 0)  // raw 32-bit
		{
			r = 0;
		}
		else if (memcmp(&proc_buf[0], "\xB8", 1) == 0 &&
			memcmp(&proc_buf[5], "\xBA", 1) == 0 &&
			memcmp(&proc_buf[10], "\xFF", 1) == 0 &&
			memcmp(&proc_buf[12], "\xC2", 1) == 0)  // WOW64
		{
			r = 0;
		}
		else { r = 0; }
#endif
		return r;
	}
	int unset_hook()
	{
		return 0;
	}
	typedef void func_type();
	func_type **ptr;
	unsigned char old_proc[
#ifdef _WIN64
		24
#else
		1
#endif
	];
protected:
	~Hook() { this->term(); }
	Hook() : ptr() { }
	bool do_init(func_type *&ptr, func_type *old_func, func_type *new_func)
	{
		bool result = false;
		if (!this->ptr && old_func)
		{
			this->ptr = &ptr;
			if (this->ptr && !*this->ptr)
			{
				*this->ptr = old_func;
				result = !!this->set_hook(reinterpret_cast<void *>(new_func));
			}
		}
		return result;
	}
	template<class F>
	bool init(F &ptr, F old_func, F new_func)
	{
		(void)(&reinterpret_cast<func_type &>(*ptr)) /* just to ensure this is a function type... */;
		return this->do_init(reinterpret_cast<func_type *&>(ptr), reinterpret_cast<func_type *>(old_func), reinterpret_cast<func_type *>(new_func));
	}
	template<class F1, class F2>
	static F1 reinterpret_cast_like(F2 f2, F1 = F1()) { return reinterpret_cast<F1>(f2); }
public:
	void term()
	{
		if (this->ptr)
		{
			if (*this->ptr)
			{
				this->unset_hook();
				*this->ptr = 0;
			}
			this->ptr = 0;
		}
	}
	template<class Derived>
	static typename Derived::type *&base(Derived &derived) { return derived.template base_like<typename Derived::type *>(NULL); }
	template<class Derived>
	static typename Derived::type *&thread(Derived &derived) { return derived.template thread<typename Derived::type *>(); }
};

#define HOOK_STRINGIZE_(Name) #Name
#define HOOK_STRINGIZE(Name) HOOK_STRINGIZE_(Name)

#define HOOK_DEFINE(ReturnType, Name, Params)  \
	struct Hook_##Name : Hook  \
	{  \
		template<class F> static F &base_or_thread_like(F f) { F *p = &thread<F>(); if (!p || !*p) { p = &base_like<F>(f); } return *p; }  \
		template<class F> static F &base_like(F) { static F base = F(); return base; }  \
		template<class F> bool init(F func) { return this->Hook::init(base_like(hook), reinterpret_cast_like(func, hook), hook); }  \
		Hook_##Name() { }  \
		static char const *name() { return HOOK_STRINGIZE(Name); }  \
		typedef ReturnType type Params;  \
		using Hook::thread; \
		template<class F>  \
		static F &thread() { __declspec(thread) static F f = NULL; return f; };  \
		template<class F>  \
		static F thread(F value) { F *thd = &thread<F>(); F const old = *thd; *thd = value; return old; };  \
		static type hook;  \
	} hook_##Name;  \
	ReturnType Hook_##Name::hook Params
