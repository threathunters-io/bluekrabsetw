// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <set>

#include "compiler_check.hpp"
#include "trace.hpp"
#include "provider.hpp"

#include "property.hpp"
////#include <windows.h>
//#include <tdh.h>
////#include <evntrace.h>
//
//#pragma comment(lib, "tdh.lib")

namespace krabs { namespace details {

    /**
     * <summary>
     *   Used as a template argument to a trace instance. This class implements
     *   code paths for user traces. Should never be used or seen by client
     *   code.
     * </summary>
     */
    struct ut {

        typedef krabs::provider<> provider_type;
        
        struct filter_flags {
            ULONG filter_type_;
            std::set<unsigned short> event_ids_;
            std::set<std::string> event_names_;
            ULONGLONG custom_value_;
            ULONG custom_size_;
            std::wstring field_name_;
            unsigned short compare_op_;
            std::wstring value_;
        };

        struct event_filter_buffers {
            std::vector<BYTE> event_id_buffer;
            std::vector<BYTE> event_name_buffer;
        };
        //ENABLE_TRACE_PARAMETERS
        struct provider_enable_info {
            ENABLE_TRACE_PARAMETERS parameters;
            event_filter_buffers event_buffer;
            std::vector<filter_flags> filter_flags_;
            bool rundown_enabled_ = false;
            UCHAR level_;
            ULONGLONG any_;
            ULONGLONG all_;
            ULONG enable_property_;
        };

        typedef std::map<krabs::guid, provider_enable_info> provider_enable_info_container;

        

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
         *   todo.
         * </summary>
         */
        void populate_filter_1();

        /**
         * <summary>
         *   todo.
         * </summary>
         */
        void populate_filter_2();

        /**
         * <summary>
         *   todo.
         * </summary>
         */
        static void populate_provider_enable_info(const ut::provider_type& provider, ut::provider_enable_info& info);

        /**
         * <summary>
         *   Enables the providers that are attached to the given trace.
         * </summary>
         */
        static void enable_providers(
            const krabs::trace<krabs::details::ut> &trace);

        /**
         * <summary>
         *   Enables the configured rundown events for each provider.
         *   Should be called immediately prior to ProcessTrace.
         * </summary>
         */
        static void enable_rundown(
            const krabs::trace<krabs::details::ut>& trace);

        /**
         * <summary>
         *   Decides to forward an event to any of the providers in the trace.
         * </summary>
         */
        static void forward_events(
            const EVENT_RECORD &record,
            const krabs::trace<krabs::details::ut> &trace);

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

    inline void ut::populate_filter_1()
    {
         



    }

    inline void ut::populate_filter_2()
    {




    }

    inline void ut::populate_provider_enable_info(const ut::provider_type& provider, ut::provider_enable_info& info)
    {
        //enable_trace_parameters info = {};
        EVENT_FILTER_DESCRIPTOR filterDesc[15] = { 0 };
        info.parameters.ControlFlags = 0;
        info.parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        info.parameters.SourceId = provider.guid_;

        info.level_ |= provider.level_;
        info.any_ |= provider.any_;
        info.all_ |= provider.all_;
        info.enable_property_ |= provider.enable_property_;
        info.rundown_enabled_ |= provider.rundown_enabled_;

        info.parameters.FilterDescCount = 0;
        info.parameters.EnableFilterDesc = &filterDesc[0];
        
        for (const auto& direct_filters : provider.direct_filters_) {
            for (const auto& direct_filter : direct_filters.list_) {
                switch (direct_filter->get_type()) {
                case EVENT_FILTER_TYPE_SYSTEM_FLAGS: {
                    auto& _filterDesc = filterDesc[info.parameters.FilterDescCount];
                    auto noneTypeFilter = reinterpret_cast<system_flags_event_filter*>(direct_filter.get());
                    _filterDesc.Ptr = reinterpret_cast<ULONGLONG>(&noneTypeFilter->get_value());
                    _filterDesc.Size = noneTypeFilter->get_size();
                    _filterDesc.Type = EVENT_FILTER_TYPE_SYSTEM_FLAGS;
                    info.parameters.FilterDescCount++;
                    break;
                }
                case EVENT_FILTER_TYPE_EVENT_ID: {
                    auto& _filterDesc = filterDesc[info.parameters.FilterDescCount];
                    auto idTypeFilter = reinterpret_cast<event_id_event_filter*>(direct_filter.get());
                    auto filterEventIdCount = idTypeFilter->get_data().size();
                    auto size = FIELD_OFFSET(EVENT_FILTER_EVENT_ID, Events[filterEventIdCount]);
                    if (filterEventIdCount > 0) {
                        _filterDesc.Type = EVENT_FILTER_TYPE_EVENT_ID;
                        info.event_buffer.event_id_buffer.resize(size, 0);
                        auto filterEventIds = reinterpret_cast<PEVENT_FILTER_EVENT_ID>(&(info.event_buffer.event_id_buffer[0]));
                        filterEventIds->FilterIn = TRUE;
                        filterEventIds->Count = static_cast<USHORT>(filterEventIdCount);
                        auto index = 0;
                        for (auto id : idTypeFilter->get_data()) {
                            filterEventIds->Events[index] = id;
                            index++;
                        }
                        _filterDesc.Ptr = reinterpret_cast<ULONGLONG>(filterEventIds);
                        _filterDesc.Size = size;
                    }
                    info.parameters.FilterDescCount++;                    
                    break;
                }
                case EVENT_FILTER_TYPE_EVENT_NAME: {
                    auto& _filterDesc = filterDesc[info.parameters.FilterDescCount];
                    auto nameTypeFilter = reinterpret_cast<event_name_event_filter*>(direct_filter.get());
                    /*typedef struct _EVENT_FILTER_EVENT_NAME {
                        ULONGLONG MatchAnyKeyword;
                        ULONGLONG MatchAllKeyword;
                        UCHAR     Level;
                        BOOLEAN   FilterIn;
                        USHORT    NameCount;
                        UCHAR     Names[ANYSIZE_ARRAY];
                    } EVENT_FILTER_EVENT_NAME, * PEVENT_FILTER_EVENT_NAME;*/
                    auto filterNamesCount = nameTypeFilter->get_data().size();
                    auto size = FIELD_OFFSET(EVENT_FILTER_EVENT_ID, Events[filterNamesCount]);
                    if (filterNamesCount > 0) {
                        _filterDesc.Type = EVENT_FILTER_TYPE_EVENT_NAME;
                        info.event_buffer.event_name_buffer.resize(size, 0);
                        auto filterEventNames = reinterpret_cast<PEVENT_FILTER_EVENT_NAME>(&(info.event_buffer.event_name_buffer[0]));
                        filterEventNames->FilterIn = TRUE;
                        filterEventNames->Level = info.level_;
                        filterEventNames->MatchAnyKeyword = info.any_;
                        filterEventNames->MatchAllKeyword = info.all_;
                        auto index = 0;
                        for (auto name : nameTypeFilter->get_data()) {
                            // The Names field should be a series of NameCount nul - terminated utf - 8
                            // event names.
                            name.push_back('\0');
                            for (auto& s : name) {
                                filterEventNames->Names[index] = s;
                                index++;
                            }

                            filterEventNames->NameCount = static_cast<USHORT>(filterNamesCount);
                        }
                        _filterDesc.Ptr = reinterpret_cast<ULONGLONG>(filterEventNames);
                        _filterDesc.Size = size;
                    }
                    info.parameters.FilterDescCount++;
                    break;
                }
                case EVENT_FILTER_TYPE_PAYLOAD: {
                    break;
                }
                default: {
                    break;
                }
                }
            }
        }

        //return enable_trace_parameters{ 0 };
    }

    inline void ut::enable_providers(
        const krabs::trace<krabs::details::ut>& trace)
    {
        if (trace.registrationHandle_ == INVALID_PROCESSTRACE_HANDLE)
            return;

        provider_enable_info_container providers_enable_info;
        // This function essentially takes the union of all the provider flags
        // for a given provider GUID. This comes about when multiple providers
        // for the same GUID are provided and request different provider flags.
        // TODO: Only forward the calls that are requested to each provider.
        for (auto& provider : trace.providers_) {
            //auto& a = provider.get();
            auto& enable_info = providers_enable_info[provider.get().guid_];
            populate_provider_enable_info(provider, enable_info);
            
            ULONG status = EnableTraceEx2(trace.registrationHandle_,
                &enable_info.parameters.SourceId,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                enable_info.level_,
                enable_info.any_,
                enable_info.all_,
                0,
                &enable_info.parameters);

            error_check_common_conditions(status);           
        }
    }

    inline void ut::enable_rundown(
        const krabs::trace<krabs::details::ut>& trace)
    {
        if (trace.registrationHandle_ == INVALID_PROCESSTRACE_HANDLE)
            return;

        for (auto& provider : trace.providers_) {
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
        const krabs::trace<krabs::details::ut> &trace)
    {
        // for manifest providers, EventHeader.ProviderId is the Provider GUID
        for (auto& provider : trace.providers_) {
            if (record.EventHeader.ProviderId == provider.get().guid_) {
                provider.get().on_event(record, trace.context_);
                return;
            }
        }

        // for MOF providers, EventHeader.Provider is the *Message* GUID
        // we need to ask TDH for event information in order to determine the
        // correct provider to pass this event to
        auto schema = get_event_schema_from_tdh(record);
        auto eventInfo = reinterpret_cast<PTRACE_EVENT_INFO>(schema.get());
        for (auto& provider : trace.providers_) {
            if (eventInfo->ProviderGuid == provider.get().guid_) {
                provider.get().on_event(record, trace.context_);
                return;
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
