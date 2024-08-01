// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")


//
//                              /\
//                             ( /   @ @    ()
//                              \  __| |__  /
//                               -/   "   \-
//                              /-|       |-\
//                             / /-\     /-\ \
//                              / /-`---'-\ \
//                               /         \
//
// Summary
// ----------------------------------------------------------------------------
// Krabs is a wrapper around ETW because ETW is the worst API ever made.

#pragma warning(push)
#pragma warning(disable: 4512) // stupid spurious "can't generate assignment error" warning
#pragma warning(disable: 4634) // DocXml comment warnings in native C++
#pragma warning(disable: 4635) // DocXml comment warnings in native C++

#include "bluekrabs/compiler_check.hpp"
#include "bluekrabs/ut.hpp"
#include "bluekrabs/kt.hpp"
#include "bluekrabs/guid.hpp"
#include "bluekrabs/trace.hpp"
#include "bluekrabs/trace_context.hpp"
#include "bluekrabs/client.hpp"
#include "bluekrabs/errors.hpp"
#include "bluekrabs/schema.hpp"
#include "bluekrabs/schema_locator.hpp"
#include "bluekrabs/parse_types.hpp"
#include "bluekrabs/collection_view.hpp"
#include "bluekrabs/size_provider.hpp"
#include "bluekrabs/parser.hpp"
#include "bluekrabs/property.hpp"
#include "bluekrabs/provider.hpp"
#include "bluekrabs/etw.hpp"
#include "bluekrabs/tdh_helpers.hpp"
#include "bluekrabs/kernel_providers.hpp"

#include "bluekrabs/testing/proxy.hpp"
#include "bluekrabs/testing/filler.hpp"
#include "bluekrabs/testing/synth_record.hpp"
#include "bluekrabs/testing/record_builder.hpp"
#include "bluekrabs/testing/event_filter_proxy.hpp"
#include "bluekrabs/testing/record_property_thunk.hpp"

#include "bluekrabs/filtering/view_adapters.hpp"
#include "bluekrabs/filtering/comparers.hpp"
#include "bluekrabs/filtering/predicates.hpp"
#include "bluekrabs/filtering/event_filter.hpp"

#pragma warning(pop)