#pragma once

#include <memory.h>

#include <Windows.h>

class Hook
{
	Hook(Hook const &);
	Hook &operator =(Hook const &);
	int set_hook(void *new_proc)
	{
		unsigned char proc_buf_size;
		unsigned char *const proc_buf = reinterpret_cast<unsigned char *const &>(*this->ptr);
#ifdef _WIN64
		if (memcmp(&proc_buf[0], "\x4C\x8B\xD1\xB8", 4) == 0 &&
			memcmp(&proc_buf[8], "\xF6\x04\x25", 3) == 0 &&
			memcmp(&proc_buf[16], "\x75\x03\x0F\x05\xC3\xCD\x2E\xC3", 8) == 0)
		{
			proc_buf_size = 24;
		}
#else
		if (memcmp(&proc_buf[0], "\xB8", 1) == 0 &&
			memcmp(&proc_buf[5], "\xE8", 1) == 0 &&
			memcmp(&proc_buf[10], "\xC2", 1) == 0)  // raw 32-bit
		{
			proc_buf_size = 13;
		}
		else if (memcmp(&proc_buf[0], "\xB8", 1) == 0 &&
			memcmp(&proc_buf[5], "\xBA", 1) == 0 &&
			memcmp(&proc_buf[10], "\xFF", 1) == 0 &&
			memcmp(&proc_buf[12], "\xC2", 1) == 0)  // WOW64
		{
			proc_buf_size = 15;
		}
#endif
		else { proc_buf_size = 0; }

		int r;
		DWORD old_protect;
		if (proc_buf_size && VirtualProtect(this->old_proc, proc_buf_size, PAGE_EXECUTE_READWRITE, &old_protect) &&
			VirtualProtect(proc_buf, proc_buf_size, PAGE_READWRITE /* no execute permission, to make sure nobody calls it concurrently */, &old_protect))
		{
			std::copy(&proc_buf[0], &proc_buf[proc_buf_size], this->old_proc);
			ptrdiff_t j = 0;
#ifdef _WIN64
			proc_buf[j++] = 0x48;
#endif
			proc_buf[j++] = 0xB8;
			j += std::copy(reinterpret_cast<unsigned char const *>(&new_proc), reinterpret_cast<unsigned char const *>(&new_proc + 1), &proc_buf[j]) - &proc_buf[j];
			proc_buf[j++] = 0xFF;
			proc_buf[j++] = 0xE0;
			FlushInstructionCache(GetCurrentProcess(), proc_buf, proc_buf_size);
			VirtualProtect(proc_buf, proc_buf_size, old_protect, &old_protect);
			this->old_func = *this->ptr;
			this->old_proc_size = proc_buf_size;
			*this->ptr = reinterpret_cast<func_type *>(&this->old_proc[0]);
			r = 1;
		}
		else { r = 0; }
		return r;
	}
	int unset_hook()
	{
		int r;
		size_t const proc_buf_size = this->old_proc_size;
		unsigned char *const proc_buf = reinterpret_cast<unsigned char *const &>(this->old_func);
		DWORD old_protect;
		if (proc_buf_size && VirtualProtect(proc_buf, proc_buf_size, PAGE_READWRITE /* no execute permission, to make sure nobody calls it concurrently */, &old_protect))
		{
			std::copy(&this->old_proc[0], &this->old_proc[proc_buf_size], proc_buf);
			FlushInstructionCache(GetCurrentProcess(), proc_buf, proc_buf_size);
			VirtualProtect(proc_buf, proc_buf_size, old_protect, &old_protect);
			this->old_func = NULL;
			r = 1;
		}
		else { r = 0; }
		return r;
	}
	typedef void func_type();
	func_type **ptr, *old_func;
	unsigned char old_proc[32];
	size_t old_proc_size;
protected:
	~Hook() { this->term(); }
	Hook() : ptr(), old_func(), old_proc_size() { }
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
				if (this->unset_hook())
				{
					*this->ptr = 0;
				}
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
		using Hook::thread;  \
		template<class F>  \
		static F &thread() { __declspec(thread) static F f = NULL; return f; };  \
		template<class F>  \
		static F thread(F value) { F *thd = &thread<F>(); F const old = *thd; *thd = value; return old; };  \
		static type hook;  \
	} hook_##Name;  \
	ReturnType Hook_##Name::hook Params
