#include "pch.h"
#include "DebuggerThread.h"

std::thread *DebuggerThread::_thread = nullptr;
DebuggerThread *DebuggerThread::_instance = nullptr;

void DebuggerThread::start(uint64_t pid, std::function<DWORD(DEBUG_EVENT &)> doMessageProxy)
{
	if (_instance == nullptr)
	{
		_instance = new DebuggerThread;
		_instance->setMessageProxy(doMessageProxy);
	}

	if (_thread == nullptr)
	{
		_thread = new std::thread(
			[&]() {
				// runº¯Êý»á×èÈû
				_instance->run(pid);

				delete _instance;
				_instance = nullptr;
			}
		);

		_thread->detach();
	}
}

void DebuggerThread::stop(uint64_t pid)
{
	if (_instance)
		_instance->terminate(pid);

	_thread = nullptr;
}

DebuggerThread::DebuggerThread()
	: _stopDebug{ false }
	, _pid{ 0 }
{
}

DebuggerThread::~DebuggerThread()
{

}

void DebuggerThread::run(uint64_t pid)
{
	this->_pid = pid;

	BOOL isDebug = DebugActiveProcess(pid);

	DEBUG_EVENT dbgEvt = { 0 };
	DWORD dwState = DBG_CONTINUE;

	while (WaitForDebugEvent(&dbgEvt, INFINITE))
	{
		dwState = _doMessageProxy(dbgEvt);

		if (_stopDebug) break;

		ContinueDebugEvent(dbgEvt.dwProcessId, dbgEvt.dwThreadId, dwState);
	}
	
}

void DebuggerThread::terminate(uint64_t pid)
{
	_stopDebug = true;
	DebugActiveProcessStop(pid);
}

void DebuggerThread::setMessageProxy(std::function<DWORD(DEBUG_EVENT &)> proxy)
{
	this->_doMessageProxy = proxy;
}
