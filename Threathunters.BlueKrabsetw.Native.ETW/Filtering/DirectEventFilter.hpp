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

                public interface class IDirectEventFilter
                {
                public:
                    virtual unsigned int GetEventType();
                    virtual unsigned long GetSize();
                };

                public ref class SystemFlagsEventFilter : IDirectEventFilter
                {
                public:
                    SystemFlagsEventFilter(unsigned long long flags, unsigned long size)
                        : flags_(flags),
                        type_(EVENT_FILTER_TYPE_SYSTEM_FLAGS),
                        size_(size)
                    { 
                    }

                    virtual unsigned int GetEventType()
                    {
                        return type_;
                    }

                    virtual unsigned long GetSize()
                    {
                        return size_;
                    }

                    unsigned long long GetFlag()
                    {
                        return flags_;
                    }


                private:
                    unsigned long long flags_;
                    unsigned int type_;
                    unsigned long size_;
                };

                public ref class EventIdFilter : IDirectEventFilter
                {
                public:
                    EventIdFilter(IEnumerable<int>^ ids)
                        : ids_(gcnew List<int>(ids)),
                        type_(EVENT_FILTER_TYPE_EVENT_ID),
                        size_(0)
                    { 
                    }

                    EventIdFilter(... array<int>^ ids)
                        : ids_(gcnew List<int>(ids)),
                        type_(EVENT_FILTER_TYPE_EVENT_ID),
                        size_(0)
                    { 
                    }

                    virtual unsigned int GetEventType()
                    {
                        return type_;
                    }

                    virtual unsigned long GetSize()
                    {
                        return size_;
                    }

                    List<int>^ GetList()
                    {
                        return ids_;
                    }

                private:
                    List<int>^ ids_;
                    unsigned int type_;
                    unsigned long size_;
                };


                public ref class DirectEventFilters
                {
                public:
                    DirectEventFilters(IEnumerable<IDirectEventFilter^>^ filters)
                        : directFilterList_(gcnew List<IDirectEventFilter^>(filters)),
                        filter_(new krabs::direct_event_filters())
                    { 
                    }

                    DirectEventFilters(... array<IDirectEventFilter^>^ filters)
                        : directFilterList_(gcnew List<IDirectEventFilter^>(filters)),
                        filter_(new krabs::direct_event_filters())
                    { 
                    }

                internal:
                    operator krabs::direct_event_filters& ()
                    {

                        for each (auto filter in directFilterList_)
                        {
                            switch (filter->GetEventType()) {
                            case EVENT_FILTER_TYPE_SYSTEM_FLAGS: {
                                if (auto typeFilter = dynamic_cast<SystemFlagsEventFilter^>(filter))
                                {
                                    auto p = std::make_shared<krabs::system_flags_event_filter>(typeFilter->GetFlag(), typeFilter->GetSize());
                                    filter_->list_.emplace_back(p);
                                }
                                break;
                            }
                            case EVENT_FILTER_TYPE_EVENT_ID: {
                                if (auto typeFilter = dynamic_cast<EventIdFilter^>(filter))
                                {
                                    std::set<unsigned short> tmp;
                                    for each (auto l in typeFilter->GetList())
                                    {
                                        tmp.insert(static_cast<unsigned short>(l));
                                    }
                                    auto p = std::make_shared<krabs::event_id_event_filter>(tmp, TRUE);
                                    filter_->list_.emplace_back(p);
                                }
                                break;
                            }
                            default: {

                            }
                            }
                        }
                        return *filter_;
                    }

                    NativePtr<krabs::direct_event_filters> filter_;
                    List<IDirectEventFilter^>^ directFilterList_;
                };
            }
        }
    }
}