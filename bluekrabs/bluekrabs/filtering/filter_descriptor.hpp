#pragma once
#include <set>
#include <string>
#include <utility>
#include <vector>
#include <memory>
#include <stdexcept>
#include <sstream>

//Exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEA
#include <windows.h>
#include <tdh.h>
#pragma comment(lib, "tdh")

namespace krabs {

    //
    //		EVENT_FILTER_TYPE values for the Type field of EVENT_FILTER_DESCRIPTOR.
    //		* /
    //#define EVENT_FILTER_TYPE_NONE               (0x00000000)
    //#define EVENT_FILTER_TYPE_SCHEMATIZED        (0x80000000) // Provider-side.
    //#define EVENT_FILTER_TYPE_SYSTEM_FLAGS       (0x80000001) // Internal use only.
    //#define EVENT_FILTER_TYPE_TRACEHANDLE        (0x80000002) // Initiate rundown.
    //#define EVENT_FILTER_TYPE_PID                (0x80000004) // Process ID.
    //#define EVENT_FILTER_TYPE_EXECUTABLE_NAME    (0x80000008) // EXE file name.
    //#define EVENT_FILTER_TYPE_PACKAGE_ID         (0x80000010) // Package ID.
    //#define EVENT_FILTER_TYPE_PACKAGE_APP_ID     (0x80000020) // Package Relative App Id (PRAID).
    //#define EVENT_FILTER_TYPE_PAYLOAD            (0x80000100) // TDH payload filter.
    //#define EVENT_FILTER_TYPE_EVENT_ID           (0x80000200) // Event IDs.
    //#define EVENT_FILTER_TYPE_EVENT_NAME         (0x80000400) // Event name (TraceLogging only).
    //#define EVENT_FILTER_TYPE_STACKWALK          (0x80001000) // Event IDs for stack.
    //#define EVENT_FILTER_TYPE_STACKWALK_NAME     (0x80002000) // Event name for stack (TraceLogging only).
    //#define EVENT_FILTER_TYPE_STACKWALK_LEVEL_KW (0x80004000) // Filter stack collection by level and keyword.
    //#define EVENT_FILTER_TYPE_CONTAINER          (0x80008000) // Filter by Container ID.

    struct filter_descriptor_base {
        filter_descriptor_base() {}

        virtual EVENT_FILTER_DESCRIPTOR operator()() const = 0;
    };

    struct system_flags : filter_descriptor_base {
        system_flags(unsigned long long a1, unsigned long a2)
            : descriptor_({ 0 })
            , data_(a1)
            , size_(a2)
        {}

        EVENT_FILTER_DESCRIPTOR operator()() const override
        {
            descriptor_.Ptr = reinterpret_cast<ULONGLONG>(&data_);
            descriptor_.Size = size_;
            descriptor_.Type = EVENT_FILTER_TYPE_SYSTEM_FLAGS;

            return descriptor_;
        }

    private:
        mutable unsigned long long data_;
        unsigned long size_;
        mutable EVENT_FILTER_DESCRIPTOR descriptor_;
    };

    struct event_ids : filter_descriptor_base {
        event_ids(std::set<unsigned short> a1, bool a2)
            : descriptor_({ 0 })
            , data_(a1)
            , filter_in_(a2)
        {}

        EVENT_FILTER_DESCRIPTOR operator()() const override
        {
            /*typedef struct _EVENT_FILTER_EVENT_ID {
                BOOLEAN FilterIn;
                UCHAR Reserved;
                USHORT Count;
                USHORT Events[ANYSIZE_ARRAY];
            } EVENT_FILTER_EVENT_ID, * PEVENT_FILTER_EVENT_ID;*/

            auto count = data_.size();
            if (count > 0) {
                auto cache_size = FIELD_OFFSET(EVENT_FILTER_EVENT_ID, Events[count]);
                cache_ = std::make_unique<char[]>(cache_size);
                auto tmp = reinterpret_cast<PEVENT_FILTER_EVENT_ID>(cache_.get());
                tmp->FilterIn = filter_in_;
                tmp->Count = static_cast<unsigned short>(count);
                int i = 0;
                for (auto item : data_) {
                    tmp->Events[i++] = item;
                }
                descriptor_.Ptr = reinterpret_cast<ULONGLONG>(cache_.get());
                descriptor_.Size = cache_size;
                descriptor_.Type = EVENT_FILTER_TYPE_EVENT_ID;
            }

            return descriptor_;
        }

    private:
        std::set<unsigned short> data_;
        bool filter_in_; // When this member is TRUE, filtering is enabled for the specified event IDs. When this member is FALSE, filtering is disabled for the event IDs.
        mutable EVENT_FILTER_DESCRIPTOR descriptor_;
        mutable std::unique_ptr<char[]> cache_;
    };

    struct process_pids : filter_descriptor_base {
        process_pids(std::set<unsigned int> a1)
            : descriptor_({ 0 })
            , data_(a1)
        {}

        EVENT_FILTER_DESCRIPTOR operator()() const override
        {
            /*typedef struct _EVENT_FILTER_EVENT_ID {
                BOOLEAN FilterIn;
                UCHAR Reserved;
                USHORT Count;
                USHORT Events[ANYSIZE_ARRAY];
            } EVENT_FILTER_EVENT_ID, * PEVENT_FILTER_EVENT_ID;*/

            auto count = data_.size();
            if (count > 0) {
                int i = 0;
                for (auto item : data_) {
                    if (i < MAX_EVENT_FILTER_PID_COUNT) {
                        cache_[i++] = item;
                    }
                }
                descriptor_.Ptr = reinterpret_cast<ULONGLONG>(cache_);
                descriptor_.Size = sizeof(unsigned int) * i;
                descriptor_.Type = EVENT_FILTER_TYPE_PID;
            }

            return descriptor_;
        }

    private:
        std::set<unsigned int> data_;
        mutable EVENT_FILTER_DESCRIPTOR descriptor_;
        mutable unsigned int cache_[MAX_EVENT_FILTER_PID_COUNT] = { 0 };
    };

    struct event_names : filter_descriptor_base {
        event_names(std::set<std::string> a1, bool a2)
            : descriptor_({ 0 })
            , data_(a1)
            , filter_in_(a2)
        {}

        EVENT_FILTER_DESCRIPTOR operator()() const override
        {
            /*typedef struct _EVENT_FILTER_EVENT_NAME {
                ULONGLONG MatchAnyKeyword;
                ULONGLONG MatchAllKeyword;
                UCHAR     Level;
                BOOLEAN   FilterIn;
                USHORT    NameCount;
                UCHAR     Names[ANYSIZE_ARRAY];
            } EVENT_FILTER_EVENT_NAME, * PEVENT_FILTER_EVENT_NAME;*/

            auto count = data_.size();
            if (count > 0) {
                auto cache_size = FIELD_OFFSET(EVENT_FILTER_EVENT_NAME, Names[count]);
                cache_ = std::make_unique<char[]>(cache_size);
                auto tmp = reinterpret_cast<PEVENT_FILTER_EVENT_NAME>(cache_.get());
                tmp->FilterIn = filter_in_;
                tmp->Level = 0;
                tmp->MatchAnyKeyword = 0;
                tmp->MatchAllKeyword = 0;
                tmp->NameCount = static_cast<USHORT>(count);
                // The Names field should be a series of
                // NameCount null terminated utf-8
                // event names.
                auto i = 0;
                for (auto item1 : data_) {
                    item1.push_back('\0');
                    for (auto& item2 : item1) {
                        tmp->Names[i++] = item2;
                    }
                }

                descriptor_.Ptr = reinterpret_cast<ULONGLONG>(cache_.get());
                descriptor_.Size = cache_size;
                descriptor_.Type = EVENT_FILTER_TYPE_EVENT_NAME;
            }

            return descriptor_;
        }

    private:
        std::set<std::string> data_;
        bool filter_in_;
        mutable EVENT_FILTER_DESCRIPTOR descriptor_;
        mutable std::unique_ptr<char[]> cache_;
    };
   
    //            EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR Example_Event_1 = { 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0 };
//#define Example_Event_1_value 0x1
//            EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR Example_Event_2 = { 0x2, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0 };
//#define Example_Event_2_value 0x2

    struct event_payloads : filter_descriptor_base {
        // take by value and move to avoid unnecessary copies
        event_payloads(
            const GUID& guid, 
            const EVENT_DESCRIPTOR& desc, 
            const std::wstring& path, 
            std::vector<std::shared_ptr<PAYLOAD_FILTER_PREDICATE>> a1,
			bool a2
        )
            : descriptor_({ 0 })
            , path_(path)
            , data_(a1)
            , guid_(guid)
			, desc_(desc)
			, filter_in_(a2)
        {}
        
        EVENT_FILTER_DESCRIPTOR operator()() const override
        {   
            WCHAR buf[MAX_PATH];
            DWORD len = ExpandEnvironmentStringsW(path_.c_str(), buf, _countof(buf));
            if (len == 0 || len > _countof(buf))
            {
				throw std::runtime_error("ExpandEnvironmentStringsW failed in event_payloads");
            }
            std::wstring path = buf;


            auto status = ::TdhLoadManifestFromBinary(const_cast<PWSTR>(path.c_str()));
            if (status != ERROR_SUCCESS)
            {
				throw std::runtime_error("TdhLoadManifestFromBinary failed in event_payloads");
            }
        	
            if (data_.empty())
            {
                // No predicates — nothing to create
                return descriptor_;
            }

            for (size_t i = 0; i < data_.size() && i < MAX_PAYLOAD_PREDICATES; ++i)
            {
                auto& item = data_[i];
				predicate_[i].FieldName = item->FieldName;
                predicate_[i].CompareOp = item->CompareOp;
                predicate_[i].Value = item->Value;
            }



            /*A Boolean value that indicates how events are handled when multiple conditions are specified.

                When this parameter is TRUE, an event will be written to a session if any of the specified conditions specified in the filter are TRUE.

                When this parameter is FALSE, an event will be written to a session only if all of the specified conditions specified in the filter are TRUE.*/
            // TdhCreatePayloadFilter returns a single filter pointer even when
            // multiple predicates are provided. Allocate space for one PVOID
            // and request creation with the full predicate count.
            event_filters_ = std::make_unique<PVOID[]>(1);
            status = TdhCreatePayloadFilter(
                &guid_,
                &desc_,
                static_cast<BOOLEAN>(filter_in_),
                static_cast<ULONG>(data_.size()),
                predicate_,
                event_filters_.get());

            if (status != ERROR_SUCCESS)
            {
                // Format a readable message for the TDH error
                DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
                LPSTR msg = nullptr;
                FormatMessageA(flags, NULL, status, 0, reinterpret_cast<LPSTR>(&msg), 0, NULL);
                std::ostringstream oss;
                oss << "TdhCreatePayloadFilter failed in event_payloads: 0x" << std::hex << status;
                if (msg)
                {
                    oss << " - " << msg;
                    LocalFree(msg);
                }

                throw std::runtime_error(oss.str());
            }

            status = TdhAggregatePayloadFilters(
                static_cast<ULONG>(1),
                event_filters_.get(),
                NULL,
                &descriptor_);
            if (status != ERROR_SUCCESS)
            {
                // Cleanup created filter before throwing
                TdhDeletePayloadFilter(&event_filters_[0]);

                DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
                LPSTR msg = nullptr;
                FormatMessageA(flags, NULL, status, 0, reinterpret_cast<LPSTR>(&msg), 0, NULL);
                std::ostringstream oss;
                oss << "TdhAggregatePayloadFilters failed in event_payloads: 0x" << std::hex << status;
                if (msg)
                {
                    oss << " - " << msg;
                    LocalFree(msg);
                }

                throw std::runtime_error(oss.str());
            }

            // Keep the created payload filter alive in event_filters_ so
            // the descriptor Ptr remains valid for EnableTraceEx2.

            return descriptor_;
        }

    private:
		std::wstring path_;
		GUID guid_;
        std::vector<std::shared_ptr<PAYLOAD_FILTER_PREDICATE>> data_;
        EVENT_DESCRIPTOR desc_;
        bool filter_in_;

        mutable PAYLOAD_FILTER_PREDICATE predicate_ [MAX_PAYLOAD_PREDICATES] = { 0 };
        mutable EVENT_FILTER_DESCRIPTOR descriptor_;
        mutable std::unique_ptr<char[]> cache_;
        // Keep the created payload filter(s) alive until the trace is enabled
        mutable std::unique_ptr<PVOID[]> event_filters_;
    };

    struct filter_descriptor {
        unsigned long count = 0;
        EVENT_FILTER_DESCRIPTOR descriptor[MAX_EVENT_FILTERS_COUNT];
    };

    /**
     * <summary>
     *
     * </summary>
     */
    struct pre_event_filter {
        pre_event_filter() {}
        pre_event_filter(std::vector<std::shared_ptr<filter_descriptor_base>> list)
            : descriptor_({ 0 })
            , list_(list)
        {
        }

        filter_descriptor operator()() const
        {
            auto& count = descriptor_.count;
            if (count == 0) {
                for (auto& item : list_)
                {
                    descriptor_.descriptor[count++] = item->operator()();
                }
            }

            return descriptor_;
        }

        std::vector<std::shared_ptr<filter_descriptor_base>> list_;
        mutable filter_descriptor descriptor_;

    };

} /* namespace krabs */