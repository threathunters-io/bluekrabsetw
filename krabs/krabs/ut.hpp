// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <set>

#include "compiler_check.hpp"
#include "trace.hpp"
#include "provider.hpp"

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
        };
        //ENABLE_TRACE_PARAMETERS
        struct enable_trace_parameters {
            std::vector<filter_flags> filter_flags_;
            bool rundown_enabled_ = false;
            UCHAR level_;
            ULONGLONG any_;
            ULONGLONG all_;
            ULONG enable_property_;
        };

        typedef std::map<krabs::guid, enable_trace_parameters> trace_parameters_container;
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

    inline void ut::enable_providers(
        const krabs::trace<krabs::details::ut>& trace)
    {
        if (trace.registrationHandle_ == INVALID_PROCESSTRACE_HANDLE)
            return;

        trace_parameters_container provider_parameters_container;

        // This function essentially takes the union of all the provider flags
        // for a given provider GUID. This comes about when multiple providers
        // for the same GUID are provided and request different provider flags.
        // TODO: Only forward the calls that are requested to each provider.
        for (auto& provider : trace.providers_) {
            auto& trace_parameters = provider_parameters_container[provider.get().guid_];
            trace_parameters.level_ |= provider.get().level_;
            trace_parameters.any_ |= provider.get().any_;
            trace_parameters.all_ |= provider.get().all_;
            trace_parameters.enable_property_ |= provider.get().enable_property_;
            trace_parameters.rundown_enabled_ |= provider.get().rundown_enabled_;

            for (const auto& direct_filters : provider.get().direct_filters_) {
                for (const auto& direct_filter : direct_filters.list_) {
                    switch (direct_filter->get_type()) {
                    case EVENT_FILTER_TYPE_SYSTEM_FLAGS: {
                        filter_flags _filter_flags;
                        auto noneTypeFilter = dynamic_cast<system_flags_event_filter*>(direct_filter.get());
                        _filter_flags.custom_value_ = noneTypeFilter->get_value();
                        _filter_flags.filter_type_ = EVENT_FILTER_TYPE_SYSTEM_FLAGS;
                        _filter_flags.custom_size_ = noneTypeFilter->get_size();
                        trace_parameters.filter_flags_.push_back(_filter_flags);
                        break;
                    }
                    case EVENT_FILTER_TYPE_EVENT_ID: {
                        auto idTypeFilter = dynamic_cast<event_id_event_filter*>(direct_filter.get());
                        filter_flags _filter_flags;
                        _filter_flags.event_ids_.insert(
                            idTypeFilter->get_data().begin(),
                            idTypeFilter->get_data().end());
                        _filter_flags.filter_type_ = EVENT_FILTER_TYPE_EVENT_ID;
                        auto filterEventIdCount = _filter_flags.event_ids_.size();
                        _filter_flags.custom_size_ = FIELD_OFFSET(EVENT_FILTER_EVENT_ID, Events[filterEventIdCount]);
                        trace_parameters.filter_flags_.push_back(_filter_flags);
                        break;
                    }
                    case EVENT_FILTER_TYPE_EVENT_NAME: {
                        auto nameTypeFilter = dynamic_cast<event_name_event_filter*>(direct_filter.get());
                        filter_flags _filter_flags;
                        _filter_flags.event_names_.insert(
                            nameTypeFilter->get_data().begin(),
                            nameTypeFilter->get_data().end());
                        _filter_flags.filter_type_ = EVENT_FILTER_TYPE_EVENT_NAME;
                        //auto filterNameCount = _filter_flags.event_names_.size();
                        auto index = 0;
                        for (auto filter : _filter_flags.event_names_) {
                            // The Names field should be a series of NameCount nul - terminated utf - 8
                            // event names.
                            index += (int)filter.size() + 1;
                        }
                        _filter_flags.custom_size_ = FIELD_OFFSET(EVENT_FILTER_EVENT_NAME, Names[index]);
                        trace_parameters.filter_flags_.push_back(_filter_flags);
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                }
            }
        }

        for (auto& [guid, trace_parameters] : provider_parameters_container) {
            ENABLE_TRACE_PARAMETERS parameters;
            parameters.ControlFlags = 0;
            parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            parameters.SourceId = guid;

            GUID _guid = guid;
            auto& _trace_parameters = trace_parameters;

            parameters.EnableProperty = _trace_parameters.enable_property_;
            parameters.EnableFilterDesc = nullptr;
            parameters.FilterDescCount = 0;
            EVENT_FILTER_DESCRIPTOR filterDesc[15] = { 0 };
            std::vector<BYTE> filterEventIdBuffer;
            std::vector<BYTE> filterNameBuffer;
            for (auto& filter_flags : _trace_parameters.filter_flags_) {
                auto& _filterDesc = filterDesc[parameters.FilterDescCount];
                switch (filter_flags.filter_type_) {
                case EVENT_FILTER_TYPE_SYSTEM_FLAGS: {
                    _filterDesc.Ptr = reinterpret_cast<ULONGLONG>(&filter_flags.custom_value_);
                    _filterDesc.Size = filter_flags.custom_size_;
                    _filterDesc.Type = 0;
                    parameters.FilterDescCount++;
                    break;
                }
                case EVENT_FILTER_TYPE_EVENT_ID: {

                    auto filterEventIdCount = filter_flags.event_ids_.size();

                    if (filterEventIdCount > 0) {
                        _filterDesc.Type = EVENT_FILTER_TYPE_EVENT_ID;
                        filterEventIdBuffer.resize(filter_flags.custom_size_, 0);
                        auto filterEventIds = reinterpret_cast<PEVENT_FILTER_EVENT_ID>(&(filterEventIdBuffer[0]));
                        filterEventIds->FilterIn = TRUE;
                        filterEventIds->Count = static_cast<USHORT>(filterEventIdCount);

                        auto index = 0;
                        for (auto filter : filter_flags.event_ids_) {
                            filterEventIds->Events[index] = filter;
                            index++;
                        }

                        _filterDesc.Ptr = reinterpret_cast<ULONGLONG>(filterEventIds);
                        _filterDesc.Size = filter_flags.custom_size_;
                    }
                    parameters.FilterDescCount++;
                    break;
                }
                case EVENT_FILTER_TYPE_EVENT_NAME: {
                    /*typedef struct _EVENT_FILTER_EVENT_NAME {
                        ULONGLONG MatchAnyKeyword;
                        ULONGLONG MatchAllKeyword;
                        UCHAR     Level;
                        BOOLEAN   FilterIn;
                        USHORT    NameCount;
                        UCHAR     Names[ANYSIZE_ARRAY];
                    } EVENT_FILTER_EVENT_NAME, * PEVENT_FILTER_EVENT_NAME;*/
                    auto filterNamesCount = filter_flags.event_names_.size();
                    if (filterNamesCount > 0) {
                        _filterDesc.Type = EVENT_FILTER_TYPE_EVENT_NAME;
                        filterNameBuffer.resize(filter_flags.custom_size_, 0);
                        auto filterEventNames = reinterpret_cast<PEVENT_FILTER_EVENT_NAME>(&(filterNameBuffer[0]));
                        filterEventNames->FilterIn = TRUE;
                        filterEventNames->Level = _trace_parameters.level_;
                        filterEventNames->MatchAnyKeyword = _trace_parameters.any_;
                        filterEventNames->MatchAllKeyword = _trace_parameters.all_;
                        auto index = 0;
                        for (auto filter : filter_flags.event_names_) {
                            // The Names field should be a series of NameCount nul - terminated utf - 8
                            // event names.
                            std::vector<unsigned char> buff(filter.size() + 1); // initializes to all 0's.
                            std::copy(filter.begin(), filter.end(), buff.begin());
                            for (auto& s : buff) {
                                filterEventNames->Names[index] = s;
                                index++;
                            }
                            filterEventNames->NameCount = static_cast<USHORT>(filterNamesCount);
                        }
                        _filterDesc.Ptr = reinterpret_cast<ULONGLONG>(filterEventNames);
                        _filterDesc.Size = filter_flags.custom_size_;
                    }
                    parameters.FilterDescCount++;

                    break;
                }
                default: {
                    break;
                }
                }
            }

            parameters.EnableFilterDesc = &filterDesc[0];

            ULONG status = EnableTraceEx2(trace.registrationHandle_,
                &_guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                _trace_parameters.level_,
                _trace_parameters.any_,
                _trace_parameters.all_,
                0,
                &parameters);
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
