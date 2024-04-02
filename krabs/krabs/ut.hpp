// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <set>

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
            std::vector<BYTE> event_pid_buffer;
            std::vector<BYTE> event_exe_name_buffer;
            std::vector<BYTE> event_name_buffer;
            unsigned int pids[MAX_EVENT_FILTER_PID_COUNT] = { 0 };
            EVENT_FILTER_DESCRIPTOR filter_desc[15] = { 0 };
            PAYLOAD_FILTER_PREDICATE predicates[MAX_PAYLOAD_PREDICATES] = { 0 };
        };
        //ENABLE_TRACE_PARAMETERS
        struct provider_enable_info {
            ENABLE_TRACE_PARAMETERS parameters;         
            bool rundown_enabled = false;
            UCHAR level;
            ULONGLONG any;
            ULONGLONG all;
            ULONG enable_property;

            event_filter_buffers event_buffer;
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
        static ULONG populate_system_flags_filter_desc(ut::provider_enable_info& info, const system_flags_event_filter* system_flags);

        /**
         * <summary>
         *   todo.
         * </summary>
         */
        static ULONG populate_event_id_filter_desc(ut::provider_enable_info& info, const event_id_event_filter* system_flags);

        /**
         * <summary>
         *   todo.
         * </summary>
         */
        static ULONG populate_event_pid_filter_desc(ut::provider_enable_info& info, const event_pid_event_filter* system_flags);

        /**
         * <summary>
         *   todo.
         * </summary>
         */
        static ULONG populate_event_name_filter_desc(ut::provider_enable_info& info, const event_name_event_filter* event_names);

        /**
         * <summary>
         *   todo.
         * </summary>
         */
        static ULONG populate_event_payload_filter_desc(ut::provider_enable_info& info, const event_payload_event_filter* event_names);

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

    inline ULONG ut::populate_system_flags_filter_desc(ut::provider_enable_info& info, const system_flags_event_filter* system_flags)
    {
        auto& filter_desc = info.parameters.EnableFilterDesc[info.parameters.FilterDescCount];
        filter_desc.Ptr = reinterpret_cast<ULONGLONG>(&system_flags->get_value());
        filter_desc.Size = system_flags->get_size();
        filter_desc.Type = EVENT_FILTER_TYPE_SYSTEM_FLAGS;

        return 1;
    }

    inline ULONG ut::populate_event_id_filter_desc(ut::provider_enable_info& info, const event_id_event_filter* event_ids)
    {
        /*typedef struct _EVENT_FILTER_EVENT_ID {
            BOOLEAN FilterIn;
            UCHAR Reserved;
            USHORT Count;
            USHORT Events[ANYSIZE_ARRAY];
        } EVENT_FILTER_EVENT_ID, * PEVENT_FILTER_EVENT_ID;*/
        auto& filter_desc = info.parameters.EnableFilterDesc[info.parameters.FilterDescCount];
        auto& buffer = info.event_buffer.event_id_buffer;
        auto event_ids_count = event_ids->get_data().size();
        auto buffer_size = FIELD_OFFSET(EVENT_FILTER_EVENT_ID, Events[event_ids_count]);
        if (event_ids_count > 0) {
            filter_desc.Type = EVENT_FILTER_TYPE_EVENT_ID;
            buffer.resize(buffer_size, 0);
            auto event_ids_desc = reinterpret_cast<PEVENT_FILTER_EVENT_ID>(&buffer[0]);
            event_ids_desc->FilterIn = TRUE;
            event_ids_desc->Count = static_cast<USHORT>(event_ids_count);
            auto index = 0;
            for (auto id : event_ids->get_data()) {
                event_ids_desc->Events[index] = id;
                index++;
            }
            filter_desc.Ptr = reinterpret_cast<ULONGLONG>(event_ids_desc);
            filter_desc.Size = buffer_size;

            return 1;
        }

        return 0;
    }

    inline ULONG ut::populate_event_pid_filter_desc(ut::provider_enable_info& info, const event_pid_event_filter* event_ids)
    {
        /*typedef struct _EVENT_FILTER_EVENT_ID {
            BOOLEAN FilterIn;
            UCHAR Reserved;
            USHORT Count;
            USHORT Events[ANYSIZE_ARRAY];
        } EVENT_FILTER_EVENT_ID, * PEVENT_FILTER_EVENT_ID;*/
        auto& filter_desc = info.parameters.EnableFilterDesc[info.parameters.FilterDescCount];
        auto& buffer = info.event_buffer.pids;
        auto event_ids_count = event_ids->get_data().size();
        //auto buffer_size = FIELD_OFFSET(EVENT_FILTER_EVENT_ID, Events[event_ids_count]);
        if (event_ids_count > 0) {
            /*filter_desc.Type = EVENT_FILTER_TYPE_PID;
            buffer.resize(buffer_size, 0);
            auto event_ids_desc = reinterpret_cast<PEVENT_FILTER_EVENT_ID>(&buffer[0]);
            event_ids_desc->FilterIn = TRUE;
            event_ids_desc->Count = static_cast<USHORT>(event_ids_count);
            auto index = 0;
            for (auto id : event_ids->get_data()) {
                event_ids_desc->Events[index] = id;
                index++;
            }*/
            auto index = 0;
            for (auto id : event_ids->get_data()) {
                buffer[index] = id;
                index++;
            }

            auto size = sizeof(unsigned int) * index;
            filter_desc.Type = EVENT_FILTER_TYPE_PID;
            filter_desc.Ptr = reinterpret_cast<ULONGLONG>(buffer);
            filter_desc.Size = (ULONG)size;

            return 1;
        }

        return 0;
    }

    inline ULONG ut::populate_event_name_filter_desc(ut::provider_enable_info& info, const event_name_event_filter* event_names) 
    {
        /*typedef struct _EVENT_FILTER_EVENT_NAME {
            ULONGLONG MatchAnyKeyword;
            ULONGLONG MatchAllKeyword;
            UCHAR     Level;
            BOOLEAN   FilterIn;
            USHORT    NameCount;
            UCHAR     Names[ANYSIZE_ARRAY];
        } EVENT_FILTER_EVENT_NAME, * PEVENT_FILTER_EVENT_NAME;*/
        auto& filter_desc = info.parameters.EnableFilterDesc[info.parameters.FilterDescCount]; //todo check if slot set
        auto& buffer = info.event_buffer.event_id_buffer;
        auto names_count = event_names->get_data().size();
        auto buffer_size = FIELD_OFFSET(EVENT_FILTER_EVENT_ID, Events[names_count]);
        if (names_count > 0) {
            filter_desc.Type = EVENT_FILTER_TYPE_EVENT_NAME;
            buffer.resize(buffer_size, 0);
            auto event_name_desc = reinterpret_cast<PEVENT_FILTER_EVENT_NAME>(&buffer[0]);
            event_name_desc->FilterIn = TRUE;
            event_name_desc->Level = info.level;
            event_name_desc->MatchAnyKeyword = info.any;
            event_name_desc->MatchAllKeyword = info.all;
            
            // The Names field should be a series of
            // NameCount null terminated utf-8
            // event names.
            auto index = 0;
            for (auto name : event_names->get_data()) {              
                name.push_back('\0');
                for (auto& s : name) {
                    event_name_desc->Names[index] = s;
                    index++;
                }
                event_name_desc->NameCount = static_cast<USHORT>(names_count);
            }
            filter_desc.Ptr = reinterpret_cast<ULONGLONG>(event_name_desc);
            filter_desc.Size = buffer_size;
            
            return 1;
        }
        
        return 0;
    }

    inline ULONG ut::populate_event_payload_filter_desc(ut::provider_enable_info& info, const event_payload_event_filter* event_payload)
    {
        /*typedef struct _PAYLOAD_FILTER_PREDICATE {
            LPWSTR FieldName;
            USHORT CompareOp;
            LPWSTR Value;
        } PAYLOAD_FILTER_PREDICATE, *PPAYLOAD_FILTER_PREDICATE;*/
        auto& filter_desc = info.parameters.EnableFilterDesc[info.parameters.FilterDescCount];
        auto& predicates = info.event_buffer.predicates;
        ULONG predicates_count = 0;
        EVENT_DESCRIPTOR ed = { 0 };
        PVOID event_filter[MAX_EVENT_FILTERS_COUNT] = { 0 };
        std::wstring mans{ L"C:\\data\\microsoft-windows-system-events.dll" };
        ULONG Status = TdhLoadManifestFromBinary((PWSTR)mans.c_str());
        if (Status != ERROR_SUCCESS) {
            printf("TdhCreatePayloadFilter() failed with %lu\n", Status);
        }
        //0. check if manifest provider
        //1. load find eval and load manifest
        //2. polpulate first payload filter
        predicates[predicates_count].CompareOp = event_payload->get_compare_op();
        predicates[predicates_count].FieldName = static_cast<LPWSTR>(const_cast<wchar_t*>(event_payload->get_field_name().c_str()));
        predicates[predicates_count].Value = static_cast<LPWSTR>(const_cast<wchar_t*>(event_payload->get_value().c_str()));
        ed.Id = 5;
        //TdhCreatePayloadFilter();
        Status = TdhCreatePayloadFilter(
            &info.parameters.SourceId,
            &ed,
            TRUE,      // TRUE Match any predicates (OR); FALSE Match all predicates (AND)
            1,
            predicates,
            &event_filter[predicates_count++]);
        if (Status != ERROR_SUCCESS) {
            printf("TdhCreatePayloadFilter() failed with %lu\n", Status);
        }
        Status = TdhAggregatePayloadFilters(
            predicates_count,
            event_filter,
            NULL,
            &filter_desc);
        if (Status != ERROR_SUCCESS) {
            printf("TdhAggregatePayloadFilters() failed with %lu\n", Status);                 
        }

        return 1;
    }

    inline void ut::populate_provider_enable_info(const ut::provider_type& provider, ut::provider_enable_info& info)
    {
        info.parameters.ControlFlags = 0;
        info.parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        info.parameters.SourceId = provider.guid_;

        info.level |= provider.level_;
        info.any |= provider.any_;
        info.all |= provider.all_;
        info.rundown_enabled |= provider.rundown_enabled_;

        info.parameters.EnableProperty |= provider.enable_property_;
        info.parameters.FilterDescCount = 0;
        info.parameters.EnableFilterDesc = &info.event_buffer.filter_desc[0];       
        // There can only be one descriptor for each filter 
        // type as specified by the Type member of the 
        // EVENT_FILTER_DESCRIPTOR structure.
        for (const auto& direct_filters : provider.direct_filters_) {
            for (const auto& direct_filter : direct_filters.list_) {
                switch (direct_filter->get_type()) {
                case EVENT_FILTER_TYPE_SYSTEM_FLAGS: {                  
                    auto system_flags = reinterpret_cast<system_flags_event_filter*>(direct_filter.get());
                    if (ULONG count = populate_system_flags_filter_desc(info, system_flags))
                    {
                        info.parameters.FilterDescCount += count;
                    }
                    break;
                }
                case EVENT_FILTER_TYPE_EVENT_ID: {                  
                    auto event_ids = reinterpret_cast<event_id_event_filter*>(direct_filter.get());
                    if (ULONG count = populate_event_id_filter_desc(info, event_ids))
                    {
                        info.parameters.FilterDescCount += count;
                    }
                    break;
                }
                case EVENT_FILTER_TYPE_EVENT_NAME: {
                    auto event_names = reinterpret_cast<event_name_event_filter*>(direct_filter.get());
                    if (ULONG count = populate_event_name_filter_desc(info, event_names))
                    {
                        info.parameters.FilterDescCount += count;
                    }
                    break;
                }
                case EVENT_FILTER_TYPE_PAYLOAD: {
                    auto event_payload = dynamic_cast<event_payload_event_filter*>(direct_filter.get());
                    if (ULONG count = populate_event_payload_filter_desc(info, event_payload))
                    {
                        info.parameters.FilterDescCount += count;
                    }
                    break;
                }
                case EVENT_FILTER_TYPE_PID: {
                    auto event_pids = reinterpret_cast<event_pid_event_filter*>(direct_filter.get());
                    if (ULONG count = populate_event_pid_filter_desc(info, event_pids))
                    {
                        info.parameters.FilterDescCount += count;
                    }
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
                enable_info.level,
                enable_info.any,
                enable_info.all,
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
