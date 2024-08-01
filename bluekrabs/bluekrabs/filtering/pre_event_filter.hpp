#include <set>
#include <string>
#include <utility>

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

    struct pre_predicate_base {
        pre_predicate_base() {}

        virtual EVENT_FILTER_DESCRIPTOR operator()() const = 0;
    };

    struct filter_descriptor {
        unsigned long count = 0;
        EVENT_FILTER_DESCRIPTOR descriptor[MAX_EVENT_FILTERS_COUNT];
    };

    struct system_flags : pre_predicate_base {
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

    struct event_ids : pre_predicate_base {
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

    struct process_pids : pre_predicate_base {
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

    struct event_names : pre_predicate_base {
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

    struct event_payloads : pre_predicate_base {
        event_payloads(std::set<std::string> a1, bool a2)
            : descriptor_({ 0 })
            , data_(a1)
            , filter_in_(a2)
        {}

        EVENT_FILTER_DESCRIPTOR operator()() const override
        {
            /*typedef struct _PAYLOAD_FILTER_PREDICATE {
                LPWSTR FieldName;
                USHORT CompareOp;
                LPWSTR Value;
            } PAYLOAD_FILTER_PREDICATE, *PPAYLOAD_FILTER_PREDICATE;
            
            EVENT_FILTER_TYPE_PAYLOAD
            
            */



            return descriptor_;
        }

    private:
        std::set<std::string> data_;
        bool filter_in_;
        mutable EVENT_FILTER_DESCRIPTOR descriptor_;
        mutable PAYLOAD_FILTER_PREDICATE cache_[MAX_PAYLOAD_PREDICATES] = { 0 };
        //mutable std::unique_ptr<char[]> cache_;
    };

    
    /**
     * <summary>
     *   
     * </summary>
     */
    struct pre_event_filter {
        pre_event_filter() {}
        pre_event_filter(std::vector<std::shared_ptr<pre_predicate_base>> list)
            : descriptor_({ 0 })
            , list_(list)
        {}

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

        std::vector<std::shared_ptr<pre_predicate_base>> list_;
        mutable filter_descriptor descriptor_;

    };
} /* namespace krabs */