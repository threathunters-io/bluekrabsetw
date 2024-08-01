#pragma once

#include "../Conversions.hpp"
#include "../EventRecordError.hpp"
#include "../EventRecord.hpp"
#include "../EventRecordMetadata.hpp"
#include "../Guid.hpp"
#include "../IEventRecord.hpp"
#include "../IEventRecordError.hpp"
#include "../NativePtr.hpp"
#include "Predicate.hpp"

using namespace System;
using namespace System::Collections::Generic;
using namespace System::Runtime::InteropServices;

namespace Microsoft {
    namespace O365 {
        namespace Security {
            namespace ETW {

                public interface class IPrePredicate
                {
                public:
                    virtual EVENT_FILTER_DESCRIPTOR operator()();
                };

                public ref class SystemFlags : public IPrePredicate
                {
                public:
                    SystemFlags(unsigned long long a1, unsigned long a2)
                        : data_(a1)
                        , size_(a2)
                    {}

                    virtual EVENT_FILTER_DESCRIPTOR operator()()
                    {
                        auto native_filter = new krabs::system_flags(data_, size_);

                        return native_filter->operator()();
                    }
                                   
                private:                  
                    unsigned long long data_;
                    unsigned long size_;
                };

                public ref class EventIds : IPrePredicate
                {
                public:
                    EventIds(IEnumerable<int>^ a1)
                        : data_(gcnew List<int>(a1))
                        , filter_in_(true)
                    {}

                    /*EventIds(... array<int>^ a1)
                        : data_(gcnew List<int>(a1))
                        , filter_in_(true)
                    {}*/

                    virtual EVENT_FILTER_DESCRIPTOR operator()()
                    {
                        std::set<unsigned short> x;
                        for each (auto y in data_)
                        {
                            x.insert(static_cast<unsigned short>(y));
                        }

                        auto native_filter = new krabs::event_ids(x, filter_in_);

                        return native_filter->operator()();
                    }

                private:
                    List<int>^ data_;
                    bool filter_in_;
                };

                public ref class ProcessIds : IPrePredicate
                {
                public:
                    ProcessIds(IEnumerable<int>^ a1)
                        : data_(gcnew List<int>(a1))
                    {}

                    ProcessIds(... array<int>^ a1)
                        : data_(gcnew List<int>(a1))
                    {}

                    virtual EVENT_FILTER_DESCRIPTOR operator()()
                    {
                        std::set<unsigned short> x;
                        for each (auto y in data_)
                        {
                            x.insert(static_cast<unsigned short>(y));
                        }

                        auto native_filter = new krabs::event_ids(x, 0);

                        return native_filter->operator()();
                    }

                private:
                    List<int>^ data_;
                };

                public ref class EventNames : IPrePredicate
                {
                public:
                    EventNames(bool a2, IEnumerable<String^>^ a1)
                        : data_(gcnew List<String^>(a1))
                        , filter_in_(a2)
                    {}

                    EventNames(bool a2, ... array<String^>^ a1)
                        : data_(gcnew List<String^>(a1))
                        , filter_in_(a2)
                    {}

                    virtual EVENT_FILTER_DESCRIPTOR operator()()
                    {
                        std::set<std::string> x;
                        for each (auto y in data_)
                        {
                            x.insert(msclr::interop::marshal_as<std::string>(y));
                        }

                        auto native_filter = new krabs::event_names(x, filter_in_);

                        return native_filter->operator()();
                    }

                private:
                    List<String^>^ data_;
                    bool filter_in_;
                };

                public ref class PreEventFilter
                {
                public:
                    PreEventFilter(IEnumerable<IPrePredicate^>^ filters)
                        : directFilterList_(gcnew List<IPrePredicate^>(filters)),
                        filter_(new krabs::pre_event_filter())
                    {}

                    PreEventFilter(... array<IPrePredicate^>^ filters)
                        : directFilterList_(gcnew List<IPrePredicate^>(filters)),
                        filter_(new krabs::pre_event_filter())
                    {}
                    
                internal:
                    operator krabs::pre_event_filter& ()
                    {
                        auto count = 0;
                        for each (auto filter in directFilterList_)
                        {                                 
                            filter_->descriptor_.descriptor[count++] = filter->operator()();
                        }

                        filter_->descriptor_.count = count;
                        return *filter_;
                    }

                    NativePtr<krabs::pre_event_filter> filter_;
                    List<IPrePredicate^>^ directFilterList_;
                };
            }
        }
    }
}

