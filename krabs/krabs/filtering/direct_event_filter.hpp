#include <set>
#include <string>


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