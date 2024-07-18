// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Selected statistics about an ETW trace
    /// </summary>
    public value class TraceStats
    {
    public:
        /// <summary>count of trace buffers</summary>
        initonly uint32_t BuffersCount;

        /// <summary>count of free buffers</summary>
        initonly uint32_t BuffersFree;

        /// <summary>count of buffers written</summary>
        initonly uint32_t BuffersWritten;

        /// <summary>count of buffers lost</summary>
        initonly uint32_t BuffersLost;

        /// <summary>count of total events</summary>
        initonly uint64_t EventsTotal;

        /// <summary>count of events handled</summary>
        initonly uint64_t EventsHandled;

        /// <summary>count of events lost</summary>
        initonly uint32_t EventsLost;

        /// <summary>count of trace buffers</summary>
        initonly uint32_t BuffersSize;

        /// <summary>count of free buffers</summary>
        initonly uint32_t MinimumBuffers;

        /// <summary>count of buffers written</summary>
        initonly uint32_t MaximumBuffers;

        /// <summary>count of buffers lost</summary>
        initonly uint32_t MaximumFileSize;

        /// <summary>count of total events</summary>
        initonly uint32_t LogFileMode;

        /// <summary>count of events handled</summary>
        initonly uint32_t FlushTimer;

        /// <summary>count of events lost</summary>
        initonly uint32_t EnableFlags;
        
        /// <summary>count of total events</summary>
        initonly String^ LogFileName;

        /// <summary>count of events handled</summary>
        initonly String^ LoggerName;

        /// <summary>count of events lost</summary>
        initonly uint32_t FlushThreshold;

    internal:
        TraceStats(const krabs::trace_stats& stats)
            : BuffersCount(stats.buffers_count)
            , BuffersFree(stats.buffers_free)
            , BuffersWritten(stats.buffers_written)
            , BuffersLost(stats.buffers_lost)
            , EventsTotal(stats.events_total)
            , EventsHandled(stats.events_handled)
            , EventsLost(stats.events_lost)
            , BuffersSize(stats.buffer_size)
            , MinimumBuffers(stats.minimum_buffers)
            , MaximumBuffers(stats.maximum_buffers)
            , MaximumFileSize(stats.maximum_file_size)
            , LogFileMode(stats.log_file_mode)
            , FlushTimer(stats.flush_timer)
            , EnableFlags(stats.enable_flags)
            , LogFileName(msclr::interop::marshal_as<String^>(stats.log_file_name))
            , LoggerName(msclr::interop::marshal_as<String^>(stats.logger_name))
            , FlushThreshold(stats.flush_threshold)
        { }
    };

} } } }