// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

#include <krabs.hpp>

#include "ITrace.hpp"
#include "NativePtr.hpp"
#include "Provider.hpp"
#include "RawProvider.hpp"
#include "Errors.hpp"
#include "TraceStats.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

	/// <summary>
	/// Represents an owned user trace.
	/// </summary>
	public ref class UserTrace : public IUserTrace, public IDisposable {
	public:

		/// <summary>
		/// Constructs a user trace session with a generated name.
		/// </summary>
		/// <example>
		///     var UserTrace trace = new UserTrace();
		/// </example>
		UserTrace();

		/// <summary>
		/// Stops the user trace when disposed.
		/// </summary>
		~UserTrace();

		/// <summary>
		/// Constructs a named user trace session, where the name can be
		/// any arbitrary, unique string.
		/// </summary>
		/// <param name="name">the name to assign to the UserTrace object</param>
		/// <example>
		///     var trace = new UserTrace("Purdy kitty");
		/// </example>
		UserTrace(String^ name);

		/// <summary>
		/// Enables a provider for the given user trace.
		/// </summary>
		/// <param name="provider">the <see cref="O365::Security::ETW::Provider"/> to enable on the trace</param>
		/// <example>
		///     UserTrace trace = new UserTrace();
		///     System.Guid powershell = System.Guid.Parse("{...}")
		///     Provider provider = new Provider(powershell);
		///     trace.Enable(provider);
		/// </example>
		virtual void Enable(O365::Security::ETW::Provider ^provider);

		/// <summary>
		/// Enables a raw provider for the given user trace.
		/// </summary>
		/// <param name="provider">the <see cref="O365::Security::ETW::RawProvider"/> to enable on the trace</param>
		/// <example>
		///     UserTrace trace = new UserTrace();
		///     System.Guid powershell = System.Guid.Parse("{...}")
		///     Provider provider = new RawProvider(powershell);
		///     trace.Enable(provider);
		/// </example>
		virtual void Enable(O365::Security::ETW::RawProvider ^provider);

		/// <summary>
		/// Enables a provider for the given user trace.
		/// </summary>
		/// <param name="provider">the <see cref="O365::Security::ETW::Provider"/> to enable on the trace</param>
		/// <example>
		///     UserTrace trace = new UserTrace();
		///     System.Guid powershell = System.Guid.Parse("{...}")
		///     Provider provider = new Provider(powershell);
		///     trace.Enable(provider);
		/// </example>
		virtual void Disable(O365::Security::ETW::Provider^ provider);

		/// <summary>
		/// Enables a raw provider for the given user trace.
		/// </summary>
		/// <param name="provider">the <see cref="O365::Security::ETW::RawProvider"/> to enable on the trace</param>
		/// <example>
		///     UserTrace trace = new UserTrace();
		///     System.Guid powershell = System.Guid.Parse("{...}")
		///     Provider provider = new RawProvider(powershell);
		///     trace.Enable(provider);
		/// </example>
		virtual void Disable(O365::Security::ETW::RawProvider^ provider);

		/// <summary>
		/// Sets the trace properties for a session.
		/// Must be called before Open()/Start().
		/// See https://docs.microsoft.com/en-us/windows/win32/etw/event-trace-properties
		/// for important details and restrictions.
		///
		/// Configurable properties are ->
		///  - BufferSize. In KB. The maximum buffer size is 1024 KB.
		///  - MinimumBuffers. Minimum number of buffers is two per processor* .
		///  - MaximumBuffers.
		///  - FlushTimer. How often, in seconds, the trace buffers are forcibly flushed.
		///  - LogFileMode. EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING simulates a *single* sequential processor.
		/// </summary>
		/// <param name="properties">the <see cref="O365::Security::ETW::EventTraceProperties"/> to set on the trace</param>
		/// <example>
		///     var trace = new UserTrace();
		///     var properties = new EventTraceProperties
		///     {
		///         BufferSize = 256,
		///         LogFileMode = (uint)LogFileModeFlags.FLAG_EVENT_TRACE_REAL_TIME_MODE
		///     };
		///     trace.SetTraceProperties(properties);
		///     // ...
		///     trace.Start();
		/// </example>
		virtual void SetTraceProperties(EventTraceProperties ^properties);

		/// <summary>
		/// 
		/// </summary>
		/// <param name="filename"></param>
		virtual void SetTraceFilename(String^ filename);

		/// <summary>
		/// Opens a trace session.
		/// </summary>
		/// <example>
		///     var trace = new UserTrace();
		///     // ...
		///     trace.Open();
		///     // ...
		///     trace.Start();
		/// </example>
		/// <remarks>
		/// This is an optional call before Start() if you need the trace
		/// registered with the ETW subsystem before you start processing events.
		/// </remarks>
		virtual void Open();

		/// <summary>
		/// Opens a trace session.
		/// </summary>
		/// <example>
		///     var trace = new UserTrace();
		///     // ...
		///     trace.Open();
		///     // ...
		///     trace.Process();
		/// </example>
		/// <remarks>
		/// This is an optional call before Start() if you need the trace
		/// registered with the ETW subsystem before you start processing events.
		/// </remarks>
		virtual void Process();


		/// <summary>
		/// Opens a trace session.
		/// </summary>
		/// <example>
		///     var trace = new UserTrace();
		///     // ...
		///     trace.Open();
		///     // ...
		///     trace.Process();
		/// </example>
		/// <remarks>
		/// This is an optional call before Start() if you need the trace
		/// registered with the ETW subsystem before you start processing events.
		/// </remarks>
		virtual void Process(DateTime^ time, bool isStartTime);

		
		/// <summary>
		/// Opens a trace session.
		/// </summary>
		/// <example>
		///     var trace = new UserTrace();
		///     // ...
		///     trace.Open();
		///     // ...
		///     trace.Process();
		/// </example>
		/// <remarks>
		/// This is an optional call before Start() if you need the trace
		/// registered with the ETW subsystem before you start processing events.
		/// </remarks>
		virtual void Process(DateTime^ startTime, DateTime^ endTime);


		/// <summary>
		/// Starts listening for events from the enabled providers.
		/// </summary>
		/// <example>
		///     UserTrace trace = new UserTrace();
		///     // ...
		///     trace.Start();
		/// </example>
		/// <remarks>
		/// This function is a blocking call. Whichever thread calls Start() is effectively
		/// donating itself to the ETW subsystem as the processing thread for events.
		///
		/// A side effect of this is that it is expected that Stop() will be called on
		/// a different thread.
		/// </remarks>
		virtual void Start();

		/// <summary>
		/// Stops listening for events.
		/// </summary>
		/// <example>
		///     UserTrace trace = new UserTrace();
		///     // ...
		///     trace.Start();
		///     trace.Stop();
		/// </example>
		virtual void Stop();

		/// <summary>
		/// Stops listening for events.
		/// </summary>
		/// <example>
		///     UserTrace trace = new UserTrace();
		///     // ...
		///     trace.Start();
		///     trace.Stop();
		/// </example>
		virtual void Close();

		/// <summary>
		/// Stops listening for events.
		/// </summary>
		/// <example>
		///     UserTrace trace = new UserTrace();
		///     // ...
		///     trace.Start();
		///     trace.Stop();
		/// </example>
		virtual void Update();

		/// <summary>
		/// 
		/// </summary>
		virtual void TransitionToRealtime();

		/// <summary>
		/// Get stats about events handled by this trace
		/// </summary>
		/// <returns>the <see cref="O365::Security::ETW::TraceStats"/> for the current trace object</returns>
		virtual TraceStats QueryStats();

	internal:
		bool disposed_ = false;
		O365::Security::ETW::NativePtr<krabs::user_trace> trace_;
	};

	// Implementation
	// ------------------------------------------------------------------------

	inline UserTrace::UserTrace()
		: trace_(new krabs::user_trace())
	{
	}

	inline UserTrace::~UserTrace()
	{
		if (disposed_) {
			return;
		}

		Stop();
		disposed_ = true;
	}

	inline UserTrace::UserTrace(String ^name)
		: trace_()
	{
		std::wstring nativeName = msclr::interop::marshal_as<std::wstring>(name);
		O365::Security::ETW::NativePtr<krabs::user_trace> temp(nativeName);
		trace_.Swap(temp);
	}

	inline void UserTrace::Enable(O365::Security::ETW::Provider ^provider)
	{
		return trace_->enable(*provider->provider_);
	}

	inline void UserTrace::Enable(O365::Security::ETW::RawProvider ^provider)
	{
		return trace_->enable(*provider->provider_);
	}

	inline void UserTrace::Disable(O365::Security::ETW::Provider^ provider)
	{
		return trace_->disable(*provider->provider_);
	}

	inline void UserTrace::Disable(O365::Security::ETW::RawProvider^ provider)
	{
		return trace_->disable(*provider->provider_);
	}

	inline void UserTrace::SetTraceProperties(EventTraceProperties ^properties)
	{
		EVENT_TRACE_PROPERTIES _properties;
		_properties.BufferSize = properties->BufferSize;
		_properties.MinimumBuffers = properties->MinimumBuffers;
		_properties.MaximumBuffers = properties->MaximumBuffers;
		_properties.LogFileMode = properties->LogFileMode;
		_properties.FlushTimer = properties->FlushTimer;
		ExecuteAndConvertExceptions(return trace_->set_trace_properties(&_properties));
	}

	inline void UserTrace::SetTraceFilename(String^ filename)
	{
		std::wstring nativeName = msclr::interop::marshal_as<std::wstring>(filename);
		ExecuteAndConvertExceptions(return trace_->set_trace_filename(nativeName));     
	}

	inline void UserTrace::Open()
	{
		ExecuteAndConvertExceptions((void)trace_->open());
	}

	inline void UserTrace::Process(DateTime^ time, bool isStartTime)
	{
		::FILETIME _time;
		{
			LARGE_INTEGER temp;
			temp.QuadPart = time->ToFileTimeUtc();
			_time.dwLowDateTime = temp.LowPart;
			_time.dwHighDateTime = temp.HighPart;
		}
		
		if (isStartTime) {
			ExecuteAndConvertExceptions((void)trace_->process(&_time));
		}
		else {
			ExecuteAndConvertExceptions((void)trace_->process(nullptr, &_time));
		}     
	}

	inline void UserTrace::Process()
	{
		ExecuteAndConvertExceptions((void)trace_->process());
	}

	inline void UserTrace::Process(DateTime^ startTime, DateTime^ endTime)
	{

		::FILETIME _start_time;
		{
			LARGE_INTEGER temp;
			temp.QuadPart = startTime->ToFileTimeUtc();
			_start_time.dwLowDateTime = temp.LowPart;
			_start_time.dwHighDateTime = temp.HighPart;
		}
		
		::FILETIME _end_time; 
		{
			LARGE_INTEGER temp;
			temp.QuadPart = endTime->ToFileTimeUtc();
			_end_time.dwLowDateTime = temp.LowPart;
			_end_time.dwHighDateTime = temp.HighPart;
		}

		ExecuteAndConvertExceptions((void)trace_->process(&_start_time, &_end_time));
	}


	inline void UserTrace::Start()
	{
		ExecuteAndConvertExceptions(return trace_->start());
	}

	inline void UserTrace::Stop()
	{
		ExecuteAndConvertExceptions(return trace_->stop());
	}

	inline void UserTrace::Close()
	{
		ExecuteAndConvertExceptions(return trace_->close());
	}

	inline void UserTrace::Update()
	{
		ExecuteAndConvertExceptions(return trace_->update());
	}

	inline void UserTrace::TransitionToRealtime()
	{
		ExecuteAndConvertExceptions(return trace_->transition_to_realtime());
	}

	inline TraceStats UserTrace::QueryStats()
	{
		ExecuteAndConvertExceptions(return TraceStats(trace_->query_stats()));
	}

} } } }