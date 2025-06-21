#ifndef ZT_TIMED_MUTEX_HPP
#define ZT_TIMED_MUTEX_HPP

#include "Constants.hpp"
#include <chrono>

#ifdef __UNIX_LIKE__

#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>

namespace ZeroTier {

// Enhanced mutex with timeout and deadlock detection capabilities
class TimedMutex
{
public:
	TimedMutex()
	{
		pthread_mutex_init(&_mh, nullptr);
	}

	~TimedMutex()
	{
		pthread_mutex_destroy(&_mh);
	}

	// Standard blocking lock
	inline void lock() const
	{
		pthread_mutex_lock(&((const_cast<TimedMutex*>(this))->_mh));
	}

	// Try to acquire lock without blocking
	inline bool try_lock() const
	{
		return pthread_mutex_trylock(&((const_cast<TimedMutex*>(this))->_mh)) == 0;
	}

	// Try to acquire lock with timeout (milliseconds)
	inline bool try_lock_for(uint64_t timeout_ms) const
	{
		struct timespec abs_timeout;
		clock_gettime(CLOCK_REALTIME, &abs_timeout);
		
		// Add timeout to current time
		abs_timeout.tv_sec += timeout_ms / 1000;
		abs_timeout.tv_nsec += (timeout_ms % 1000) * 1000000;
		
		// Handle nanosecond overflow
		if (abs_timeout.tv_nsec >= 1000000000) {
			abs_timeout.tv_sec++;
			abs_timeout.tv_nsec -= 1000000000;
		}
		
		int result = pthread_mutex_timedlock(&((const_cast<TimedMutex*>(this))->_mh), &abs_timeout);
		return result == 0;
	}

	inline void unlock() const
	{
		pthread_mutex_unlock(&((const_cast<TimedMutex*>(this))->_mh));
	}

	// RAII lock with timeout support
	class TimedLock
	{
	public:
		TimedLock(TimedMutex &m, uint64_t timeout_ms = 0) :
			_m(&m), _locked(false)
		{
			if (timeout_ms == 0) {
				m.lock();
				_locked = true;
			} else {
				_locked = m.try_lock_for(timeout_ms);
				if (!_locked) {
					// Log timeout for debugging
					fprintf(stderr, "MUTEX_TIMEOUT: Failed to acquire lock within %llu ms\n", 
						(unsigned long long)timeout_ms);
				}
			}
		}

		~TimedLock()
		{
			if (_locked) {
				_m->unlock();
			}
		}

		bool acquired() const { return _locked; }

	private:
		TimedMutex *const _m;
		bool _locked;
	};

	// Standard lock for compatibility
	class Lock
	{
	public:
		Lock(TimedMutex &m) : _m(&m)
		{
			m.lock();
		}

		Lock(const TimedMutex &m) : _m(const_cast<TimedMutex*>(&m))
		{
			_m->lock();
		}

		~Lock()
		{
			_m->unlock();
		}

	private:
		TimedMutex *const _m;
	};

private:
	TimedMutex(const TimedMutex &) {}
	const TimedMutex &operator=(const TimedMutex &) { return *this; }

	pthread_mutex_t _mh;
};

} // namespace ZeroTier

#endif // __UNIX_LIKE__

#ifdef __WINDOWS__

#include <stdlib.h>
#include <windows.h>

namespace ZeroTier {

// Windows implementation with timeout support
class TimedMutex
{
public:
	TimedMutex()
	{
		InitializeCriticalSection(&_cs);
	}

	~TimedMutex()
	{
		DeleteCriticalSection(&_cs);
	}

	inline void lock()
	{
		EnterCriticalSection(&_cs);
	}

	inline bool try_lock()
	{
		return TryEnterCriticalSection(&_cs) != 0;
	}

	inline bool try_lock_for(uint64_t timeout_ms)
	{
		// Windows doesn't have native timed critical sections
		// Implement with polling (not ideal but workable)
		const uint64_t sleep_interval = 1; // 1ms
		uint64_t elapsed = 0;
		
		while (elapsed < timeout_ms) {
			if (try_lock()) {
				return true;
			}
			Sleep(sleep_interval);
			elapsed += sleep_interval;
		}
		
		fprintf(stderr, "MUTEX_TIMEOUT: Failed to acquire lock within %llu ms\n", 
			(unsigned long long)timeout_ms);
		return false;
	}

	inline void unlock()
	{
		LeaveCriticalSection(&_cs);
	}

	// Same lock classes as Unix version...
	class TimedLock
	{
	public:
		TimedLock(TimedMutex &m, uint64_t timeout_ms = 0) :
			_m(&m), _locked(false)
		{
			if (timeout_ms == 0) {
				m.lock();
				_locked = true;
			} else {
				_locked = m.try_lock_for(timeout_ms);
			}
		}

		~TimedLock()
		{
			if (_locked) {
				_m->unlock();
			}
		}

		bool acquired() const { return _locked; }

	private:
		TimedMutex *const _m;
		bool _locked;
	};

	class Lock
	{
	public:
		Lock(TimedMutex &m) : _m(&m)
		{
			m.lock();
		}

		~Lock()
		{
			_m->unlock();
		}

	private:
		TimedMutex *const _m;
	};

private:
	TimedMutex(const TimedMutex &) {}
	const TimedMutex &operator=(const TimedMutex &) { return *this; }

	CRITICAL_SECTION _cs;
};

} // namespace ZeroTier

#endif // __WINDOWS__

#endif // ZT_TIMED_MUTEX_HPP 