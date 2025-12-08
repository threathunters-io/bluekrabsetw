// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use the any_of/all_of/none_of filter predicate vectors.

#include <iostream>
#include <cassert>
#include <chrono>
#include <thread>

#include "..\..\bluekrabs\krabs.hpp"
#include "examples.h"

void user_trace_010_direct_filter::start()
{
    krabs::user_trace trace(L"My Named Trace");
    krabs::provider<> provider(L"Microsoft-Windows-RPC");
    krabs::guid microsoft_windows_rpc{ L"{6ad52b32-d609-4be9-ae07-ce8dae937e39}" };
    //auto custom_filter = std::make_shared<krabs::system_flags_event_filter>(0xFFFFFFFFFFFF, 4);// krabs::none_type_filter((unsigned long long)0xFFFFFFFFFFFF, 4);
    //auto eventid = std::make_shared<krabs::event_id_event_filter>(std::set<unsigned short>{ 5 }, true);
    //auto pid = std::make_shared<krabs::event_pid_event_filter>(std::set<unsigned short>{ 4 }, true);
    //auto eventname = std::make_shared<krabs::event_name_event_filter>(std::set<std::string>{ "name1", "name2" }, true);
    //auto eventid = krabs::event_id_type_filter({ 5 }, true);
    //auto payload_filter = std::make_shared<krabs::event_payload_event_filter>(L"DesiredAccess", (unsigned short)PAYLOADFIELD_GE, L"12288");
    //auto sy = krabs::system_flags_descriptor(0xFFFFFFFFFFFF, 4);
    //auto id = krabs::event_id_descriptor(std::set<unsigned short>{ 5, 12, 31, 131, 133 }, true);
    //auto d1 = sy();
    //auto d2 = id();
    //krabs::direct_event_filters1 direct_filter1({ &sy,&id });
    //auto a = direct_filter1();
    //krabs::direct_event_filters direct_filter({
     //   eventid,
      //  payload_filter,
      //  custom_filter,
      //  pid
        //eventname
      //  });




    HKEY key;
    DWORD type = 0;
    DWORD size = 0;
    ::RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\{6ad52b32-d609-4be9-ae07-ce8dae937e39}", 0, KEY_READ, &key);
    ::RegQueryValueExW(key, L"MessageFileName", nullptr, &type, nullptr, &size);
    std::vector<wchar_t> buf(size / sizeof(wchar_t));
    ::RegQueryValueExW(key, L"MessageFileName", nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()), &size);

    std::vector<std::shared_ptr<PAYLOAD_FILTER_PREDICATE>>p;
    /*p.emplace_back(std::make_shared<PAYLOAD_FILTER_PREDICATE>(PAYLOAD_FILTER_PREDICATE{ const_cast<LPWSTR>(L"Endpoint"), PAYLOADFIELD_ISNOT, const_cast<LPWSTR>(L"eventlog") }));
    p.emplace_back(std::make_shared<PAYLOAD_FILTER_PREDICATE>(PAYLOAD_FILTER_PREDICATE{ const_cast<LPWSTR>(L"Endpoint"), PAYLOADFIELD_ISNOT, const_cast<LPWSTR>(L"\\PIPE\\srvsvc") }));
    p.emplace_back(std::make_shared<PAYLOAD_FILTER_PREDICATE>(PAYLOAD_FILTER_PREDICATE{ const_cast<LPWSTR>(L"Endpoint"), PAYLOADFIELD_ISNOT, const_cast<LPWSTR>(L"\\PIPE\\wkssvc") }));*/
	p.emplace_back(std::make_shared<PAYLOAD_FILTER_PREDICATE>(PAYLOAD_FILTER_PREDICATE{ const_cast<LPWSTR>(L"Endpoint"), PAYLOADFIELD_CONTAINS, const_cast<LPWSTR>(L"epmapper") }));
   p.emplace_back(std::make_shared<PAYLOAD_FILTER_PREDICATE>(PAYLOAD_FILTER_PREDICATE{ const_cast<LPWSTR>(L"Endpoint"), PAYLOADFIELD_ISNOT, const_cast<LPWSTR>(L"ntsvcs") }));
    
    /*static wchar_t field[] = L"Endpoint";
    static wchar_t val[] = L"epmapper";
    auto pred = std::make_shared<PAYLOAD_FILTER_PREDICATE>(PAYLOAD_FILTER_PREDICATE{ field, PAYLOADFIELD_ISNOT, val });
    std::vector<std::shared_ptr<PAYLOAD_FILTER_PREDICATE>> p;
    p.emplace_back(pred);*/

    // <event value = "5" symbol = "RpcClientCallStart_V1" version = "1" task = "RpcClientCall" opcode = "win:Start" level = "win:Informational" template = "RpcClientCallStartArgs_V1" / >

    EVENT_DESCRIPTOR desc5 = { 5, 1, 0, 0, 0, 0, 0 };
    //EVENT_DESCRIPTOR desc6 = { 6, 1, 0, 4, 1, 2, 0 };

    auto payload_filter5 = std::make_shared<krabs::event_payloads>(microsoft_windows_rpc, desc5, buf.data(), p, true );
    //auto payload_filter6 = std::make_shared<krabs::event_payloads>(microsoft_windows_rpc, desc6, buf.data(), p, true);


    //payload_filter5->operator()();
	//payload_filter6->operator()();


    auto a1 = std::make_shared<krabs::system_flags>(0xFFFFFFFFFFFF, 4);
    auto a2 = std::make_shared<krabs::event_ids>(std::set<unsigned short>{ 5 }, true);
    krabs::pre_event_filter pre_filter({ payload_filter5/*, a2*//*, payload_filter6*/ });

    

    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //assert(schema.event_id() == 5);
        krabs::parser parser(schema);

        if (schema.event_id() == 5)
        {
            std::wcout << L" ProviderID=" << schema.provider_name() << std::endl;
            std::wcout << L" EventID=" << schema.event_id() << std::endl;
            /*auto s = parser.parse<std::wstring>(L"Endpoint");
            std::wcout << L" Endpoint=" << s << std::endl;*/
            auto s = parser.parse<std::wstring>(L"Endpoint");
            std::wcout << L"Endpoint='" << s << L"' len=" << s.size() << std::endl;

        }
        
        });

    provider.add_filter(pre_filter);
    trace.enable(provider);
    trace.start();
}