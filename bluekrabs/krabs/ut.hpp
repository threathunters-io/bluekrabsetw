// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <set>
#include <chrono>
#include <iostream>

#include "compiler_check.hpp"
#include "trace.hpp"
#include "provider.hpp"

#include "property.hpp"

namespace krabs { namespace details {

    /**
     * <summary>
     *   Used as a template argument to a trace instance. This class implements
     *   code paths for user traces. Should never be used or seen by client
     *   code.
     * </summary>
     */
    struct ut {       
        //ENABLE_TRACE_PARAMETERS
        struct enable_trace_info {
            GUID guid;
            ENABLE_TRACE_PARAMETERS parameters;         
            bool rundown_enabled = false;
            UCHAR level;
            ULONGLONG any;
            ULONGLONG all;
            ULONG enable_property;
            EVENT_FILTER_DESCRIPTOR filter_desc[15] = { 0 };
        };

        typedef krabs::provider<> provider_type;
        typedef std::map<krabs::guid, enable_trace_info> provider_enable_info;
        /**
         * <summary>
         *   Used to assign a name to the trace instance that is being
         *   instantiated.
         * </summary>
         * <remarks>
         *   There really isn't a name policy to enforce with user traces, but
         *   kernel traces do have specific naming requirements.
         * </remarks>
         */
        static const std::wstring enforce_name_policy(
            const std::wstring &name);

        /**
         * <summary>
         *   Generates a value that fills the EnableFlags field in an
         *   EVENT_TRACE_PROPERTIES structure. This controls the providers that
         *   get enabled for a kernel trace. For a user trace, it doesn't do
         *   much of anything.
         * </summary>
         */
        static const unsigned long construct_enable_flags(
            const krabs::trace<krabs::details::ut> &trace);

        /**
         * <summary>
         *   Enables the providers that are attached to the given trace.
         * </summary>
         */
        static void enable_providers(
            krabs::trace<krabs::details::ut> &trace);
       
        ///**
        // * <summary>
        // *   Enables the providers that are attached to the given trace.
        // * </summary>
        // */
        static void enable_provider(
            krabs::trace<krabs::details::ut>& trace,
            const krabs::details::ut::provider_type& p);

        /**
         * <summary>
         *   Enables the providers that are attached to the given trace.
         * </summary>
         */
        static void disable_provider(
            krabs::trace<krabs::details::ut>& trace,
            const krabs::details::ut::provider_type& p);

        /**
         * <summary>
         *   Enables the configured rundown events for each provider.
         *   Should be called immediately prior to ProcessTrace.
         * </summary>
         */
        static void enable_rundown(
            krabs::trace<krabs::details::ut>& trace);
        
        /**
         * <summary>
         *   Decides to forward an event to any of the providers in the trace.
         * </summary>
         */
        static void forward_events(
            const EVENT_RECORD &record,
            krabs::trace<krabs::details::ut> &trace);

        /**
         * <summary>
         *   Sets the ETW trace log file mode.
         * </summary>
         */
        static unsigned long augment_file_mode();

        /**
         * <summary>
         *   Returns the GUID of the trace session.
         * </summary>
         */
        static krabs::guid get_trace_guid();
    };


    // Implementation
    // ------------------------------------------------------------------------

    inline const std::wstring ut::enforce_name_policy(
        const std::wstring &name_hint)
    {
        if (name_hint.empty()) {
            return std::to_wstring(krabs::guid::random_guid());
        }

        return name_hint;
    }

    inline const unsigned long ut::construct_enable_flags(
        const krabs::trace<krabs::details::ut> &)
    {
        return 0;
    }
    
    inline void ut::enable_providers(
        krabs::trace<krabs::details::ut>& trace)
    {
        if (trace.registrationHandle_ == INVALID_PROCESSTRACE_HANDLE) {
            return;
        }
                    
        for (auto& provider : trace.enabled_providers_) {
            auto& _provider = provider.get();
            enable_provider(trace, _provider);       
        }
    }

    inline void ut::enable_provider(
        krabs::trace<krabs::details::ut>& trace,
        const krabs::details::ut::provider_type& provider)
    {
        if (trace.registrationHandle_ == INVALID_PROCESSTRACE_HANDLE) {
            return;
        }

        // This essentially takes the union of all the provider flags
        // for a given provider GUID. This comes about when multiple providers
        // for the same GUID are provided and request different provider flags.        
        auto& provider_enable_info = trace.provider_enable_info_[provider.guid_];
        provider_enable_info.parameters.ControlFlags = 0;
        provider_enable_info.parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        provider_enable_info.guid = provider.guid_;
        // TODO: Only forward the calls that are requested to each provider.
        provider_enable_info.level |= provider.level_;
        provider_enable_info.any |= provider.any_;
        provider_enable_info.all |= provider.all_;
        provider_enable_info.rundown_enabled |= provider.rundown_enabled_;
        provider_enable_info.parameters.EnableProperty |= provider.enable_property_;

        // There can only be one descriptor for each filter 
        // type as specified by the Type member of the 
        // EVENT_FILTER_DESCRIPTOR structure.
        if (provider.pre_filter_.count == 0)
        {
            provider_enable_info.parameters.FilterDescCount = 0;
            provider_enable_info.parameters.EnableFilterDesc = &provider_enable_info.filter_desc[0];
        }
        else
        {
            provider_enable_info.parameters.FilterDescCount = provider.pre_filter_.count;
            provider_enable_info.parameters.EnableFilterDesc = const_cast<EVENT_FILTER_DESCRIPTOR*>(&provider.pre_filter_.descriptor[0]);
        }

        ULONG status = EnableTraceEx2(trace.registrationHandle_,
            &provider.guid_,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            provider_enable_info.level,
            provider_enable_info.any,
            provider_enable_info.all,
            0,
            &provider_enable_info.parameters);

        error_check_common_conditions(status);
    }

    inline void ut::disable_provider(
        krabs::trace<krabs::details::ut>& trace,
        const krabs::details::ut::provider_type& provider)
    {
        if (trace.registrationHandle_ == INVALID_PROCESSTRACE_HANDLE) {
            return;
        }

        auto it = trace.provider_enable_info_.find(provider.guid_);
        if (it != trace.provider_enable_info_.end()) {
            ULONG status = EnableTraceEx2(trace.registrationHandle_,
                &provider.guid_,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                0,
                0,
                0,
                0,
                NULL);

            error_check_common_conditions(status);
            if (status == ERROR_SUCCESS) {                              
                trace.provider_enable_info_.erase(it);
            }
        }
    }

    

    inline void ut::enable_rundown(
        krabs::trace<krabs::details::ut>& trace)
    {
        if (trace.registrationHandle_ == INVALID_PROCESSTRACE_HANDLE)
            return;

        for (auto& provider : trace.enabled_providers_) {
            if (!provider.get().rundown_enabled_)
                continue;

            ULONG status = EnableTraceEx2(trace.registrationHandle_,
                &provider.get().guid_,
                EVENT_CONTROL_CODE_CAPTURE_STATE,
                0,
                0,
                0,
                0,
                NULL);
            error_check_common_conditions(status);
        }
    }

    inline void ut::forward_events(
        const EVENT_RECORD &record,
        krabs::trace<krabs::details::ut> &trace)
    {
        // for manifest providers, EventHeader.ProviderId is the Provider GUID
        for (auto& provider : trace.enabled_providers_) {
            if (record.EventHeader.ProviderId == provider.get().guid_) {
                provider.get().on_event(record, trace.context_);
                return;
            }
        }

        // for MOF providers, EventHeader.Provider is the *Message* GUID
        // we need to ask TDH for event information in order to determine the
        // correct provider to pass this event to
        if ((record.EventHeader.EventProperty & EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG) == 1) {
            auto schema = get_event_schema_from_tdh(record);
            auto eventInfo = reinterpret_cast<PTRACE_EVENT_INFO>(schema.get());
            for (auto& provider : trace.enabled_providers_) {
                if (eventInfo->ProviderGuid == provider.get().guid_) {
                    provider.get().on_event(record, trace.context_);
                    return;
                }
            }
        }
        
        if (trace.default_callback_ != nullptr)
            trace.default_callback_(record, trace.context_);
    }

    inline unsigned long ut::augment_file_mode()
    {
        return 0;
    }

    inline krabs::guid ut::get_trace_guid()
    {
        return krabs::guid::random_guid();
    }

} /* namespace details */ } /* namespace krabs */
