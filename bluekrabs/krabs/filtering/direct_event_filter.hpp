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

    struct direct_event_filter_base {
        virtual const unsigned int get_type() const = 0;
        virtual const unsigned long get_size() const = 0;
    };

    struct direct_event_filters {
        direct_event_filters() {}
        direct_event_filters(std::vector<std::shared_ptr<direct_event_filter_base>> list)
            : list_(list)
        {}

        std::vector<std::shared_ptr<direct_event_filter_base>> list_;
    };

    /*template <typename T>
    struct none_type_filter : direct_event_filter_base {
        none_type_filter(T value, unsigned long size)
            : value_(value),
            type_(EVENT_FILTER_TYPE_NONE),
            size_(size)
        {}

        const unsigned int get_type() const override {
            return type_;
        }

        const unsigned long get_size() const override {
            return size_;
        }

        const T& get_value() const
        {
            return value_;
        }

    private:
        T value_;
        unsigned int type_;
        unsigned long size_;
    };*/

    struct base_descriptor {
        base_descriptor(unsigned int a1)
            : type_(a1)
            {}

        virtual EVENT_FILTER_DESCRIPTOR operator()() const = 0;

        unsigned int type_;
    };

    struct system_flags_descriptor : base_descriptor {
        system_flags_descriptor(unsigned long long a1, unsigned long a2)
            : base_descriptor(EVENT_FILTER_TYPE_SYSTEM_FLAGS)
            , descriptor_({ 0 })
            , data_(a1)
            , size_(a2)
        {}

        EVENT_FILTER_DESCRIPTOR operator()() const override
        {
            descriptor_.Ptr = reinterpret_cast<ULONGLONG>(&data_);
            descriptor_.Size = size_;
            descriptor_.Type = type_;

            return descriptor_;
        }

    private:
        mutable unsigned long long data_;
        unsigned long size_;
        mutable EVENT_FILTER_DESCRIPTOR descriptor_;
    };

    struct event_id_descriptor : base_descriptor {
        event_id_descriptor(std::set<unsigned short> a1, bool a2)
            : base_descriptor(EVENT_FILTER_TYPE_EVENT_ID)
            , descriptor_({ 0 })
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
                descriptor_.Type = type_;
            }
                                                             
            return descriptor_;
        }

    private:
        std::set<unsigned short> data_;
        bool filter_in_;
        mutable EVENT_FILTER_DESCRIPTOR descriptor_;
        mutable std::unique_ptr<char[]> cache_;
    };

    struct pid_descriptor : base_descriptor {
        pid_descriptor(std::set<unsigned int> a1)
            : base_descriptor(EVENT_FILTER_TYPE_PID)
            , descriptor_({ 0 })
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
                descriptor_.Type = type_;
            }

            return descriptor_;
        }

    private:
        std::set<unsigned int> data_;
        mutable EVENT_FILTER_DESCRIPTOR descriptor_;
        mutable unsigned int cache_[MAX_EVENT_FILTER_PID_COUNT] = { 0 };
    };

    struct event_name_descriptor : base_descriptor {
        event_name_descriptor(std::set<std::string> a1, bool a2)
            : base_descriptor(EVENT_FILTER_TYPE_EVENT_NAME)
            , descriptor_({ 0 })
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
                descriptor_.Type = type_;
            }

            return descriptor_;
        }

    private:
        std::set<std::string> data_;
        bool filter_in_;
        mutable EVENT_FILTER_DESCRIPTOR descriptor_;
        mutable std::unique_ptr<char[]> cache_;
    };

    struct payload_descriptor : base_descriptor {
        payload_descriptor(std::set<std::string> a1, bool a2)
            : base_descriptor(EVENT_FILTER_TYPE_PAYLOAD)
            , descriptor_({ 0 })
            , data_(a1)
            , filter_in_(a2)
        {}

        EVENT_FILTER_DESCRIPTOR operator()() const override
        {
            /*typedef struct _PAYLOAD_FILTER_PREDICATE {
                LPWSTR FieldName;
                USHORT CompareOp;
                LPWSTR Value;
            } PAYLOAD_FILTER_PREDICATE, *PPAYLOAD_FILTER_PREDICATE;*/

            

            return descriptor_;
        }

    private:
        std::set<std::string> data_;
        bool filter_in_;
        mutable EVENT_FILTER_DESCRIPTOR descriptor_;
        mutable PAYLOAD_FILTER_PREDICATE cache_[MAX_PAYLOAD_PREDICATES] = { 0 };
        //mutable std::unique_ptr<char[]> cache_;
    };

    struct descriptor_info {
        unsigned long count;
        EVENT_FILTER_DESCRIPTOR descriptor[MAX_EVENT_FILTERS_COUNT];
    };

    /**
     * <summary>
     *   Accepts an event if any of the predicates in the vector matches
     * </summary>
     */
    struct direct_event_filters1 {
        direct_event_filters1(std::vector<base_descriptor*> list)
            : list_(list)
            , descriptor_({0})
            , count_(0)
        {}

        descriptor_info operator()() const
        {
            auto& count = descriptor_.count;
            if (count == 0) {
                for (auto& item : list_) {
                    switch (item->type_) {
                    case EVENT_FILTER_TYPE_SYSTEM_FLAGS: {
                        auto tmp = static_cast<system_flags_descriptor*>(const_cast<base_descriptor*>(item));
                        if (tmp) {
                            descriptor_.descriptor[count++] = (*tmp)();
                        }
                        break;
                    }
                    case EVENT_FILTER_TYPE_EVENT_ID: {
                        auto tmp = static_cast<event_id_descriptor*>(const_cast<base_descriptor*>(item));
                        if (tmp) {
                            descriptor_.descriptor[count++] = (*tmp)();
                        }
                        break;
                    }
                    case EVENT_FILTER_TYPE_EVENT_NAME: {
                        auto tmp = static_cast<event_name_descriptor*>(const_cast<base_descriptor*>(item));
                        if (tmp) {
                            descriptor_.descriptor[count++] = (*tmp)();
                        }
                        break;
                    }
                    case EVENT_FILTER_TYPE_PAYLOAD: {
                        auto tmp = static_cast<payload_descriptor*>(const_cast<base_descriptor*>(item));
                        if (tmp) {
                            descriptor_.descriptor[count++] = (*tmp)();
                        }
                        break;
                    }
                    case EVENT_FILTER_TYPE_PID: {
                        auto tmp = static_cast<pid_descriptor*>(const_cast<base_descriptor*>(item));
                        if (tmp) {
                            descriptor_.descriptor[count++] = (*tmp)();
                        }
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                }
            }
            
            return descriptor_;
        }
    private:
        mutable unsigned long count_;
        mutable descriptor_info descriptor_;
        std::vector<base_descriptor*> list_;
    };






    struct system_flags_event_filter : direct_event_filter_base {
        system_flags_event_filter(unsigned long long flags, unsigned long size)
            : flags_(flags),
            type_(EVENT_FILTER_TYPE_SYSTEM_FLAGS),
            size_(size)
        {}

        const unsigned int get_type() const override {
            return type_;
        }

        const unsigned long get_size() const override {
            return size_;
        }

        const unsigned long long& get_value() const
        {
            return flags_;
        }

    private:
        unsigned long long flags_;
        unsigned int type_;
        unsigned long size_;
    };

    struct event_id_event_filter : direct_event_filter_base {
        event_id_event_filter(std::set<unsigned short> ids, bool filter_in)
            : ids_(ids),
            filter_in_(filter_in),
            type_(EVENT_FILTER_TYPE_EVENT_ID),
            size_(0)
        {}

        unsigned const int get_type() const override {
            return type_;
        }

        unsigned long const get_size() const override {
            return size_;
        }

        const std::set<unsigned short>& get_data() const
        {
            return ids_;
        }

        const bool& get_filter_in() const
        {
            return filter_in_;
        }

    private:
        std::set<unsigned short> ids_;
        bool filter_in_;
        unsigned int type_;
        unsigned long size_;
    };

    struct event_pid_event_filter : direct_event_filter_base {
        event_pid_event_filter(std::set<unsigned short> ids, bool filter_in)
            : pids_(ids),
            filter_in_(filter_in),
            type_(EVENT_FILTER_TYPE_PID),
            size_(0)
        {}

        unsigned const int get_type() const override {
            return type_;
        }

        unsigned long const get_size() const override {
            return size_;
        }

        const std::set<unsigned short>& get_data() const
        {
            return pids_;
        }

        const bool& get_filter_in() const
        {
            return filter_in_;
        }

    private:
        std::set<unsigned short> pids_;
        bool filter_in_;
        unsigned int type_;
        unsigned long size_;
    };

    struct event_name_event_filter : direct_event_filter_base {
        event_name_event_filter(std::set<std::string> names, bool filter_in)
            : names_(names),
            filter_in_(filter_in),
            type_(EVENT_FILTER_TYPE_EVENT_NAME),
            size_(0)
        {}

        unsigned const int get_type() const override {
            return type_;
        }

        unsigned long const get_size() const override {
            return size_;
        }

        const std::set<std::string>& get_data() const
        {
            return names_;
        }

        const bool& get_filter_in() const
        {
            return filter_in_;
        }

    private:
        std::set<std::string> names_;
        bool filter_in_;
        unsigned int type_;
        unsigned long size_;
    };

    /*
    typedef struct _PAYLOAD_FILTER_PREDICATE {
      LPWSTR FieldName;
      USHORT CompareOp;
      LPWSTR Value;
    } PAYLOAD_FILTER_PREDICATE, *PPAYLOAD_FILTER_PREDICATE;
    */
    struct event_payload_event_filter : direct_event_filter_base {
        event_payload_event_filter(const std::wstring& field_name, unsigned short compare_op, const std::wstring& value)
            : field_name_(field_name),
            compare_op_(compare_op),
            type_(EVENT_FILTER_TYPE_PAYLOAD),
            value_(value),
            size_(0)
        {}

        unsigned const int get_type() const override {
            return type_;
        }

        unsigned long const get_size() const override {
            return size_;
        }

        const std::wstring& get_field_name() const
        {
            return field_name_;
        }

        const std::wstring& get_value() const
        {
            return value_;
        }

        const unsigned short& get_compare_op() const
        {
            return compare_op_;
        }

    private:
        std::wstring field_name_;
        unsigned short compare_op_;
        std::wstring value_;
        unsigned int type_;
        unsigned long size_;
    };
} /* namespace krabs */