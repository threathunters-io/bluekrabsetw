
#pragma once

#ifndef  WIN32_LEAN_AND_MEAN
#define  WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <tdh.h>
//#include <evntrace.h>

#include <memory>

#include "filtering/direct_event_filter.hpp"


#pragma comment(lib, "tdh.lib")

namespace krabs { namespace details {

    template <typename T>
    class filter_descriptor {
    public:
        filter_descriptor(T& trace);

        void set_event_payload();
        void set_event_id(const event_id_event_filter& direct_filter);
        void set_event_pid();
        void set_event_name();
        void set_system_flags(const system_flags_event_filter& direct_filter);

    private:
        ULONG filter_descriptor_count_ = 0;
        EVENT_FILTER_DESCRIPTOR filter_desc_[MAX_EVENT_FILTERS_COUNT] = { 0 };
        std::unique_ptr<char[]> id_cache_;
        std::unique_ptr<char[]> pid_cache_;
        std::unique_ptr<char[]> exe_name_cache_;
        std::unique_ptr<char[]> event_name_cache_;
        unsigned int pids_cache_[MAX_EVENT_FILTER_PID_COUNT] = { 0 };
        PAYLOAD_FILTER_PREDICATE predicates_cache_[MAX_PAYLOAD_PREDICATES] = { 0 };

    private:
        //T& trace_;

    private:
        template <typename T>
        friend class krabs::trace;
    };


    // Implementation
    // ------------------------------------------------------------------------

    template <typename T>
    filter_descriptor<T>::filter_descriptor(T& trace)
        : trace_(trace)
    {}

    template <typename T>
    void filter_descriptor<T>::set_event_payload() {

    }

    template <typename T>
    void filter_descriptor<T>::set_event_id(const event_id_event_filter& direct_filter)
    {
        /*typedef struct _EVENT_FILTER_EVENT_ID {
            BOOLEAN FilterIn;
            UCHAR Reserved;
            USHORT Count;
            USHORT Events[ANYSIZE_ARRAY];
        } EVENT_FILTER_EVENT_ID, * PEVENT_FILTER_EVENT_ID;*/

        auto& filter_desc = filter_desc_[filter_descriptor_count_++];
        auto count = direct_filter.get_data().size();
        if (count > 0) {
            auto cache_size = FIELD_OFFSET(EVENT_FILTER_EVENT_ID, Events[count]);
            id_cache_ = std::make_unique<char[]>(cache_size);
            auto event_id_desc = reinterpret_cast<PEVENT_FILTER_EVENT_ID>(id_cache_.get());
            event_id_desc->FilterIn = TRUE;
            event_id_desc->Count = static_cast<USHORT>(event_ids_count);
            
            auto i = 0;
            for (auto event_id : direct_filter.get_data()) {
                event_id_desc->Events[i++] = event_id;
            }

            filter_desc.Type = EVENT_FILTER_TYPE_EVENT_ID;
            filter_desc.Ptr = reinterpret_cast<ULONGLONG>(event_id_desc);
            filter_desc.Size = cache_size;
        }
    }

    template <typename T>
    void filter_descriptor<T>::set_event_pid() {

    }
    template <typename T>
    void filter_descriptor<T>::set_event_name() {

    }

    template <typename T>
    void filter_descriptor<T>::set_system_flags(const system_flags_event_filter& direct_filter)
    {
        auto& filter_desc = filter_desc_[filter_descriptor_count_++];
        filter_desc.Ptr = direct_filter.get_value();
        filter_desc.Size = direct_filter.get_size();
        filter_desc.Type = EVENT_FILTER_TYPE_SYSTEM_FLAGS;
    }
} /* namespace details */ } /* namespace krabs */