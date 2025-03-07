// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <deque>
#include <map>
#include <mutex>

#include "compiler_check.hpp"
#include "guid.hpp"
#include "provider.hpp"
#include "trace_context.hpp"
#include "etw.hpp"


namespace krabs { namespace details {
	template <typename T> class trace_manager;
} /* namespace details */ } /* namespace krabs */

namespace krabs { namespace testing {
	template <typename T> class trace_proxy;
} /* namespace testing */ } /* namespace krabs */


namespace krabs {

	template <typename T>
	class provider;

	/**
	 * <summary>
	 * Selected statistics about an ETW trace
	 * </summary>
	 */
	class trace_stats {
	public:
		const uint32_t buffers_count;
		const uint32_t buffers_free;
		const uint32_t buffers_written;
		const uint32_t buffers_lost;
		const uint64_t events_total;
		const uint64_t events_handled;
		const uint32_t events_lost;
		const uint32_t buffer_size;
		const uint32_t minimum_buffers;
		const uint32_t maximum_buffers;
		const uint32_t maximum_file_size;
		const uint32_t log_file_mode;
		const uint32_t flush_timer;
		const uint32_t enable_flags;
		const std::wstring log_file_name;
		const std::wstring logger_name;
		const uint32_t flush_threshold;

		trace_stats(uint64_t eventsHandled, const details::trace_info& props)
			: buffers_count(props.properties.NumberOfBuffers)
			, buffers_free(props.properties.FreeBuffers)
			, buffers_written(props.properties.BuffersWritten)
			, buffers_lost(props.properties.RealTimeBuffersLost)
			, events_total(eventsHandled + props.properties.EventsLost)
			, events_handled(eventsHandled)
			, events_lost(props.properties.EventsLost)
			, buffer_size(props.properties.BufferSize)
			, minimum_buffers(props.properties.MinimumBuffers)
			, maximum_buffers(props.properties.MaximumBuffers)
			, maximum_file_size(props.properties.MaximumFileSize)
			, log_file_mode(props.properties.LogFileMode)
			, flush_timer(props.properties.FlushTimer)
			, enable_flags(props.properties.EnableFlags)
			, flush_threshold(props.properties.FlushThreshold)
			, logger_name(props.traceName)
			, log_file_name(props.logfileName)
		{ }
	};

	/**
	 * <summary>
	 *    Represents a single trace session that can have multiple
	 *    enabled providers. Ideally, there should only need to be a
	 *    single trace instance for all ETW user traces.
	 * </summary>
	 */
	template <typename T>
	class trace {
	public:

		typedef T trace_type;

		/**
		 * <summary>
		 *   Constructs a trace with an optional trace name, which can be
		 *   any arbitrary, unique name.
		 * </summary>
		 *
		 * <example>
		 *   trace trace;
		 *   trace namedTrace(L"Some special name");
		 * </example>
		 */
		trace(const std::wstring &name);
		trace(const wchar_t *name = L"");

		/**
		 * <summary>
		 *   Destructs the trace session and unregisters the session, if
		 *   applicable.
		 * </summary>
		 *
		 * <example>
		 *   trace trace;
		 *   // ~trace implicitly called
		 * </example>
		 */
		~trace();

		/**
		 * <summary>
		 * Sets the trace properties for a session.
		 * Must be called before open()/start().
		 * See https://docs.microsoft.com/en-us/windows/win32/etw/event-trace-properties
		 * for important details and restrictions.
		 * Configurable properties are ->
		 *  - BufferSize.  In KB. The maximum buffer size is 1024 KB.
		 *  - MinimumBuffers. Minimum number of buffers is two per processor*.
		 *  - MaximumBuffers.
		 *  - FlushTimer. How often, in seconds, the trace buffers are forcibly flushed.
		 *  - LogFileMode. EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING simulates a *single* sequential processor.
		 * </summary>
		 * <example>
		 *    krabs::trace trace;
		 *    EVENT_TRACE_PROPERTIES properties = { 0 };
		 *    properties.BufferSize = 256;
		 *    properties.MinimumBuffers = 12;
		 *    properties.MaximumBuffers = 48;
		 *    properties.FlushTimer = 1;
		 *    properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		 *    trace.set_trace_properties(&properties);
		 *    krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
		 *    provider<> powershell(id);
		 *    trace.enable(powershell);
		 *    trace.start();
		 * </example>
		 */
		void set_trace_properties(const PEVENT_TRACE_PROPERTIES properties);

		/**
		 * <summary>
		 * Configures trace session settings.
		 * Must be called after open().
		 * See https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-tracesetinformation
		 * for more information.
		 * </summary>
		 * <example>
		 *    krabs::trace trace;
		 *    // Adjust SE_SYSTEM_PROFILE_NAME token privilege through AdjustTokenPrivileges(...)
		 *    // to enable stack tracing (not done in this example). Then:
		 *    STACK_TRACING_EVENT_ID event_id = {0};
		 *    event_id.EventGuid = krabs::guids::perf_info;
		 *    event_id.Type = 46; // SampleProfile
		 *    trace.open();
		 *    trace.set_trace_information(TraceStackTracingInfo, &event_id, sizeof(STACK_TRACING_EVENT_ID));
		 *    krabs::kernel_provider stack_walk_provider(EVENT_TRACE_FLAG_PROFILE, krabs::guids::stack_walk);
		 *    trace.enable(stack_walk_provider);
		 *    trace.process();
		 * </example>
		 */
		void set_trace_information(
			TRACE_INFO_CLASS information_class,
			PVOID trace_information,
			ULONG information_length);

		/**
		 * <summary>
		 * Configures trace to read from a file instead of realtime
		 * Must be called before open().
		 * See https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-tracesetinformation
		 * for more information.
		 * </summary>
		 * <example>
		 *    krabs::trace trace;
		 *    trace.set_trace_filename(L"C:\merged.etl");
		 *    trace.process();
		 * </example>
		 */
		void set_trace_filename(const std::wstring& filename);

		/**
		 * <summary>
		 * Update the session configuration so that the session receives
		 * the requested events from the provider.
		 * </summary>
		 * <example>
		 *    krabs::trace trace;
		 *    krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
		 *    provider<> powershell(id);
		 *    trace.enable(powershell);
		 * </example>
		 */
		void update();

		/**
		 * <summary>
		 * Update the session configuration so that the session receives
		 * the requested events from the provider. 
		 * </summary>
		 * <example>
		 *    krabs::trace trace;
		 *    krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
		 *    provider<> powershell(id);
		 *    trace.enable(powershell);
		 * </example>
		 */
		void enable(const typename T::provider_type &p);

		/**
		 * <summary>
		 * Update the session configuration so that the session does not
		 * receive events from the provider.
		 * </summary>
		 * <example>
		 *    krabs::trace trace;
		 *    krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
		 *    provider<> powershell(id);
		 *    trace.disable(powershell);
		 * </example>
		 */
		void disable(const typename T::provider_type& p);

		/**
		 * <summary>
		 * Starts a trace session.
		 * </summary>
		 * <example>
		 *    krabs::trace trace;
		 *    krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
		 *    provider<> powershell(id);
		 *    trace.enable(powershell);
		 *    trace.start();
		 * </example>
		 */
		void start();

		/**
		 * <summary>
		 * Closes a trace session.
		 * </summary>
		 * <example>
		 *    krabs::trace trace;
		 *    krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
		 *    provider<> powershell(id);
		 *    trace.enable(powershell);
		 *    trace.start();
		 *    trace.stop();
		 * </example>
		 */
		void stop(bool force = false);

		/**
		 * <summary>
		 * Closes a trace session.
		 * </summary>
		 * <example>
		 *    krabs::trace trace;
		 *    krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
		 *    provider<> powershell(id);
		 *    trace.enable(powershell);
		 *    trace.start();
		 *    trace.stop();
		 * </example>
		 */
		void close();

		/**
		* <summary>
		* Opens a trace session.
		* This is an optional call before start() if you need the trace
		* registered with the ETW subsystem before you start processing events.
		* </summary>
		* <example>
		*    krabs::trace trace;
		*    krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
		*    provider<> powershell(id);
		*    trace.enable(powershell);
		*    auto logfile = trace.open();
		* </example>
		*/
		EVENT_TRACE_LOGFILE open();

		/**
		 * <summary>
		 * Transition the ETW trace from real-time to file or vice versa.
		 * </summary>
		 */
		void transition_to_realtime();

		/**
		* <summary>
		* Start processing events for an already opened session.
		* </summary>
		* <example>
		*    krabs::trace trace;
		*    krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
		*    provider<> powershell(id);
		*    trace.enable(powershell);
		*    trace.open();
		*    trace.process();
		* </example>
		*/
		void process(LPFILETIME start_time = nullptr, LPFILETIME end_time = nullptr);

		/**
		* <summary>
		* Start processing events for an already opened session.
		* </summary>
		* <example>
		*    krabs::trace trace;
		*    krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
		*    provider<> powershell(id);
		*    trace.enable(powershell);
		*    trace.open();
		*    trace.process();
		* </example>
		*/
		void flush();

		/**
		 * <summary>
		 * Queries the trace session to get stats about
		 * events lost and buffers handled.
		 * </summary>
		 */
		trace_stats query_stats();

		/**
		 * <summary>
		 * Returns the number of buffers that were processed.
		 * </summary>
		 * <example>
		 *    krabs::trace trace;
		 *    krabs::guid id(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}");
		 *    provider<> powershell(id);
		 *    trace.enable(powershell);
		 *    trace.start();
		 *    trace.stop();
		 *    std::wcout << trace.buffers_processed() << std::endl;
		 * </example>
		 */
		size_t buffers_processed() const;

		/**
		 * <summary>
		 * Adds a function to call when an event is fired which has no corresponding provider.
		 * </summary>
		 *
		 * <param name="callback">the function to call into</param>
		 * <example>
		 *    void my_fun(const EVENT_RECORD &record) { ... }
		 *    // ...
		 *    krabs::trace trace;
		 *    trace.set_default_event_callback(my_fun);
		 * </example>
		 *
		 * <example>
		 *    auto fun = [&](const EVENT_RECORD &record) {...}
		 *    krabs::trace trace;
		 *    trace.set_default_event_callback(fun);
		 * </example>
		 */
		void set_default_event_callback(c_provider_callback callback);

	private:

		/**
		 * <summary>
		 *   Invoked when an event occurs in the underlying ETW session.
		 * </summary>
		 */
		void on_event(const EVENT_RECORD &);

		/////**
		//// * <summary>
		//// * Updates a trace session.
		//// * </summary>
		//// * <example>
		//// *    todo
		//// * </example>
		//// */
		//void update_provider(const typename T::provider_type& p);

	private:
		std::wstring name_;
		std::wstring logFilename_;
		bool non_stoppable_;
		std::deque<std::reference_wrapper<const typename T::provider_type>> enabled_providers_;
		// This essentially takes the union of all the provider flags
		// for a given provider. This comes about when multiple providers
		// for the same XX are provided and request different provider flags.
		// TODO: Only forward the calls that are requested to each provider.
		typename T::provider_enable_info provider_enable_info_;
		std::mutex providers_mutex_;
		LPFILETIME start_time_;
		LPFILETIME end_time_;


		TRACEHANDLE registrationHandle_;
		TRACEHANDLE sessionHandle_;

		size_t buffersRead_;
		uint64_t eventsHandled_;

		EVENT_TRACE_PROPERTIES properties_;

		const trace_context context_;

		provider_callback default_callback_ = nullptr;

	private:
		template <typename T>
		friend class details::trace_manager;

		template <typename T>
		friend class testing::trace_proxy;

		friend typename T;
	};

	// Implementation
	// ------------------------------------------------------------------------

	template <typename T>
	trace<T>::trace(const std::wstring &name)
		: registrationHandle_(INVALID_PROCESSTRACE_HANDLE)
		, sessionHandle_(INVALID_PROCESSTRACE_HANDLE)
		, eventsHandled_(0)
		, buffersRead_(0)
		, context_()
		, non_stoppable_(false)
		, start_time_(nullptr)
		, end_time_(nullptr)
	{
		name_ = T::enforce_name_policy(name);
		ZeroMemory(&properties_, sizeof(EVENT_TRACE_PROPERTIES));
	}

	template <typename T>
	trace<T>::trace(const wchar_t *name)
		: registrationHandle_(INVALID_PROCESSTRACE_HANDLE)
		, sessionHandle_(INVALID_PROCESSTRACE_HANDLE)
		, eventsHandled_(0)
		, buffersRead_(0)
		, context_()
		, non_stoppable_(false)
		, start_time_(nullptr)
		, end_time_(nullptr)
	{
		name_ = T::enforce_name_policy(name);
		ZeroMemory(&properties_, sizeof(EVENT_TRACE_PROPERTIES));
	}

	template <typename T>
	trace<T>::~trace()
	{
		if (!non_stoppable_) {
			stop();
		}
		else {
			close();
		}
	}

	template <typename T>
	void trace<T>::set_trace_properties(const PEVENT_TRACE_PROPERTIES properties)
	{
		properties_ = {};
		properties_.BufferSize = properties->BufferSize;
		properties_.MinimumBuffers = properties->MinimumBuffers;
		properties_.MaximumBuffers = properties->MaximumBuffers;
		properties_.FlushTimer = properties->FlushTimer;
		properties_.LogFileMode = properties->LogFileMode;
	}

	template <typename T>
	void trace<T>::set_trace_information(
		TRACE_INFO_CLASS information_class,
		PVOID trace_information,
		ULONG information_length)
	{
		details::trace_manager<trace> manager(*this);
		manager.set_trace_information(information_class, trace_information, information_length);
	}

	template <typename T>
	void trace<T>::set_trace_filename(const std::wstring& filename)
	{
		logFilename_ = filename;
	}

	template <typename T>
	void trace<T>::on_event(const EVENT_RECORD &record)
	{
		++eventsHandled_;
		//std::lock_guard<std::mutex> lock(providers_mutex_);
		T::forward_events(record, *this);
	}

	template <typename T>
	void trace<T>::enable(const typename T::provider_type& p)
	{                    
		auto insert_unique = [&](const auto& _p) {
			auto it = std::find_if(enabled_providers_.begin(), enabled_providers_.end(), [&_p](const auto& x) {
				return x.get().guid() == _p.guid();
				});
			if (it == enabled_providers_.end()) {
				enabled_providers_.push_back(std::ref(_p));
			}
			else {
				*it = std::ref(_p);
			}
		};

		if (registrationHandle_ == INVALID_PROCESSTRACE_HANDLE && sessionHandle_ == INVALID_PROCESSTRACE_HANDLE) {
			insert_unique(p);
		}
		else {        
			std::lock_guard<std::mutex> lock(providers_mutex_);
			details::trace_manager<trace> manager(*this);
			manager.enable(p);
			insert_unique(p);
		}                                                                         
	}

	template <typename T>
	void trace<T>::disable(const typename T::provider_type& p)
	{   
		if (registrationHandle_ == INVALID_PROCESSTRACE_HANDLE) {
			auto it = std::find_if(enabled_providers_.begin(), enabled_providers_.end(), [&p](const auto& x) {
				return x.get().guid() == p.guid();
				});

			if (it != enabled_providers_.end()) {
				std::lock_guard<std::mutex> lock(providers_mutex_);
				details::trace_manager<trace> manager(*this);
				manager.disable(p);
				enabled_providers_.erase(it);
			}
		}
	}

	template <typename T>
	void trace<T>::start()
	{
		eventsHandled_ = 0;
		details::trace_manager<trace> manager(*this);
		manager.start();
	}

	template <typename T>
	void trace<T>::stop(bool force)
	{
		if (!non_stoppable_ || force) {
			details::trace_manager<trace> manager(*this);
			manager.stop();
		}        
	}

	template <typename T>
	void trace<T>::close()
	{
		details::trace_manager<trace> manager(*this);
		manager.close();
	}

	template <typename T>
	EVENT_TRACE_LOGFILE trace<T>::open()
	{
		eventsHandled_ = 0;
		non_stoppable_ = true;
		details::trace_manager<trace> manager(*this);
		return manager.open();
	}

	template <typename T>
	void trace<T>::transition_to_realtime()
	{
		//EVENT_TRACE_CONTROL_CONVERT_TO_REALTIME
		details::trace_manager<trace> manager(*this);
		manager.transition_to_realtime();
	}

	template <typename T>
	void trace<T>::process(LPFILETIME start_time, LPFILETIME end_time)
	{
		eventsHandled_ = 0;

		if (start_time != nullptr) {
			start_time_ = start_time;
		}

		if (end_time != nullptr) {
			end_time_ = end_time;
		}

		details::trace_manager<trace> manager(*this);
		manager.process();
	}

	template <typename T>
	void trace<T>::flush() 
	{
		details::trace_manager<trace> manager(*this);
		manager.flush();
	}

	template <typename T>
	void trace<T>::update()
	{
		details::trace_manager<trace> manager(*this);
		manager.update();
	}

	template <typename T>
	trace_stats trace<T>::query_stats()
	{
		details::trace_manager<trace> manager(*this);
		return { eventsHandled_, manager.query() };
	}

	template <typename T>
	size_t trace<T>::buffers_processed() const
	{
		return buffersRead_;
	}

	template <typename T>
	void trace<T>::set_default_event_callback(c_provider_callback callback)
	{
		default_callback_ = callback;
	}

}
