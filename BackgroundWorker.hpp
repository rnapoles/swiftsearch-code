#pragma once

#ifndef BACKGROUNDWORKER_HPP
#define BACKGROUNDWORKER_HPP

#include <limits.h>
#include <process.h>
#include <deque>
#include <utility>
#include <Windows.h>
#include <Objbase.h>

class BackgroundWorker
{
	BackgroundWorker(BackgroundWorker const &);
	BackgroundWorker &operator =(BackgroundWorker const &);
protected:
	struct DECLSPEC_NOVTABLE Thunk
	{
		virtual bool operator()() { return false; }
		virtual ~Thunk() { }
	};
	class CSLock
	{
	public:
		CRITICAL_SECTION& cs;
		CSLock(CRITICAL_SECTION& criticalSection) : cs(criticalSection) { EnterCriticalSection(&this->cs); }
		~CSLock() { LeaveCriticalSection(&this->cs); }
	};
	mutable CRITICAL_SECTION criticalSection;
	mutable int refs;
	friend void intrusive_ptr_add_ref(BackgroundWorker const volatile *p) { ++p->refs; }
	friend void intrusive_ptr_release(BackgroundWorker const volatile *p) { if (!--p->refs) { delete p; } }

private:
	virtual void add(Thunk *pThunk, bool lifo) = 0;

public:
	BackgroundWorker() : refs() { InitializeCriticalSection(&this->criticalSection); }
	virtual ~BackgroundWorker() throw(std::exception) { DeleteCriticalSection(&this->criticalSection); }

	virtual void clear() = 0;

	static BackgroundWorker *create(bool coInitialize = true);

	template<typename Func>
	void add(Func const &func, bool lifo)
	{
		CSLock lock(this->criticalSection);
		struct FThunk : public Thunk
		{
			Func func;
			FThunk(Func const &func) : func(func) { }
			bool operator()() { return this->func() != 0; }
		};
		std::auto_ptr<Thunk> pThunk(new FThunk(func));
		this->add(pThunk.get(), lifo);
		pThunk.release();
	}
};

class BackgroundWorkerImpl : public BackgroundWorker
{
	static bool use_window_messages() { return false; }
	class CoInit
	{
		CoInit(CoInit const &) : hr(S_FALSE) { }
	public:
		HRESULT hr;
		CoInit(bool initialize = true) : hr(initialize ? CoInitialize(NULL) : S_FALSE) { }
		~CoInit() { if (this->hr == S_OK) { CoUninitialize(); } }
	};

	std::deque<Thunk *> todo;
	unsigned int tid;
	bool coInitialize;
	HANDLE hThread;
	HANDLE hSemaphore;
	volatile bool stop;

	static unsigned int CALLBACK entry(void *arg) { return ((BackgroundWorkerImpl *)arg)->process(); }
public:
	BackgroundWorkerImpl(bool coInitialize)
		: coInitialize(coInitialize), tid(0), hThread(), hSemaphore(NULL), stop(false)
	{
		this->hThread = (HANDLE)_beginthreadex(NULL, 0, entry, this, CREATE_SUSPENDED, &tid);
		this->hSemaphore = CreateSemaphore(NULL, 0, LONG_MAX, NULL);
		ResumeThread(this->hThread);
	}

	~BackgroundWorkerImpl() throw(std::exception)
	{
		// Clear all the tasks
		this->stop = true;
		CSLock lock(this->criticalSection);
		this->todo.clear();
		if (!use_window_messages())
		{
			LONG prev;
			if (!ReleaseSemaphore(this->hSemaphore, 1, &prev) || WaitForSingleObject(this->hThread, INFINITE) != WAIT_OBJECT_0)
			{ throw new std::runtime_error("The background thread did not terminate properly."); }
		}
		else
		{
			PostThreadMessage(this->tid, WM_QUIT, NULL, NULL);
			if (WaitForSingleObject(this->hThread, INFINITE) != WAIT_OBJECT_0)
			{
				throw new std::runtime_error("The background thread did not terminate properly.");
			}
		}
		CloseHandle(this->hSemaphore);
		CloseHandle(this->hThread);
	}

	void clear()
	{
		CSLock lock(this->criticalSection);
		this->todo.clear();
	}

	bool empty() const
	{
		CSLock lock(this->criticalSection);
		return this->todo.empty();
	}

	unsigned int process()
	{
		// SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
		// SetThreadPriority(GetCurrentThread(), 0x00010000 /*THREAD_MODE_BACKGROUND_BEGIN*/);
		DWORD result = 0;
		CoInit const com(this->coInitialize);
		if (!use_window_messages())
		{
			while ((result = WaitForSingleObject(this->hSemaphore, INFINITE)) == WAIT_OBJECT_0)
			{
				if (this->stop)
				{
					result = ERROR_CANCELLED;
					break;
				}
				Thunk *pThunk = NULL;
				{
					CSLock lock(this->criticalSection);
					if (!this->todo.empty())
					{
						std::auto_ptr<Thunk> next(this->todo.front());
						this->todo.pop_front();
						pThunk = next.release();
					}
				}
				if (pThunk)
				{
					std::auto_ptr<Thunk> thunk(pThunk);
					pThunk = NULL;
					if (!(*thunk)())
					{
						result = ERROR_REQUEST_ABORTED;
						break;
					}
				}
			}
		}
		else
		{
			for (;;)
			{
				MSG msg = { NULL, WM_NULL, 0, 0 };
				BOOL anyMessage = PeekMessage(&msg, reinterpret_cast<HWND>(-1), WM_QUIT, WM_QUIT, PM_REMOVE);
				BOOL hasQuitMessage = anyMessage;
				if (!anyMessage)
				{
					anyMessage |= PeekMessage(&msg, reinterpret_cast<HWND>(-1), 0, 0, PM_REMOVE);
					hasQuitMessage |= anyMessage && msg.message == WM_QUIT;
				}
				if (hasQuitMessage)
				{
					result = ERROR_CANCELLED;
					break;
				}
				if (anyMessage)
				{
					if (msg.message == WM_NULL && reinterpret_cast<HANDLE>(msg.wParam) == this->hThread)
					{
						if (!(*std::auto_ptr<Thunk>(reinterpret_cast<Thunk *>(msg.lParam)))())
						{
							result = ERROR_REQUEST_ABORTED;
							break;
						}
					}
				}
				else
				{
					if (!WaitMessage())
					{
						result = WAIT_FAILED;
						break;
					}
				}
			}
		}
		if (result == WAIT_FAILED) { result = GetLastError(); }
		return result;
	}

	void add(Thunk *pThunk, bool lifo)
	{
		DWORD exitCode;
		if (GetExitCodeThread(this->hThread, &exitCode) && exitCode == STILL_ACTIVE)
		{
			if (!use_window_messages())
			{
				if (lifo) { this->todo.push_front(pThunk); }
				else { this->todo.push_back(pThunk); }
			}
			LONG prev;
			if (use_window_messages()
				? PostThreadMessage(this->tid, WM_NULL, reinterpret_cast<WPARAM>(this->hThread), reinterpret_cast<LPARAM>(pThunk))
				: ReleaseSemaphore(this->hSemaphore, 1, &prev))
			{
			}
			else
			{
				throw std::runtime_error("Unexpected error when releasing semaphore.");
			}
		}
		else
		{
			throw std::runtime_error("The background thread has terminated, probably because the callback told it to stop.");
		}
	}
};
BackgroundWorker *BackgroundWorker::create(bool coInitialize)
{
	return new BackgroundWorkerImpl(coInitialize);
}

#endif