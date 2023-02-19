#pragma once

#include <thread>
#include <functional>

//typedef DWORD(*DoMessageProxy)(DEBUG_EVENT &);

class DebuggerThread
{
	// Static Member
public:
	static void start(uint64_t pid, std::function<DWORD(DEBUG_EVENT &)>);
	static void stop(uint64_t pid);

private:
	static std::thread *_thread;
	static DebuggerThread *_instance;

	// Debugger
private:
	DebuggerThread();
	~DebuggerThread();

private:
	void run(uint64_t pid);
	void terminate(uint64_t pid);

public:
	void setMessageProxy(std::function<DWORD(DEBUG_EVENT &)>);

private:
	uint64_t _pid;

	volatile bool _stopDebug;
	std::function<DWORD(DEBUG_EVENT &)> _doMessageProxy;

};

