// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace with an ETL file
#include <iostream>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"



HANDLE pktmon_service_start() 
{
	SC_HANDLE hManager;
	SC_HANDLE hService;
	HANDLE hDriver;
	BOOL status;

	hManager = OpenSCManagerA(NULL, "ServicesActive", SC_MANAGER_CONNECT); // SC_MANAGER_CONNECT == 0x01
	if (!hManager) {
		return NULL;
	}
	hService = OpenServiceA(hManager, "ndiscap", SERVICE_START | SERVICE_STOP); // 0x10 | 0x20 == 0x30
	hService = OpenServiceA(hManager, "PktMon", SERVICE_START | SERVICE_STOP); // 0x10 | 0x20 == 0x30
	CloseServiceHandle(hManager);

	status = StartServiceA(hService, 0, NULL);
	CloseServiceHandle(hService);

	hDriver = CreateFileA("\\\\.\\PktMonDev", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); // 0x80000000 | 0x40000000 == 0xC0000000; OPEN_EXISTING == 0x03; FILE_ATTRIBUTE_NORMAL == 0x80
	if (hDriver == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	return hDriver;
}

HANDLE ndiscap_service_start()
{
	SC_HANDLE hManager;
	SC_HANDLE hService;
	HANDLE hDriver;
	BOOL status;

	hManager = OpenSCManagerA(NULL, "ServicesActive", SC_MANAGER_CONNECT); // SC_MANAGER_CONNECT == 0x01
	if (!hManager) {
		return NULL;
	}
	hService = OpenServiceA(hManager, "ndiscap", SERVICE_START | SERVICE_STOP); // 0x10 | 0x20 == 0x30
	CloseServiceHandle(hManager);

	status = StartServiceA(hService, 0, NULL);
	CloseServiceHandle(hService);

	return hDriver;
}

DWORD initiate_capture(HANDLE hDriver) {
	BOOL status;
	DWORD IOCTL_start = 0x220404;
	DWORD IOCTL_filter = 0x220410;

	LPVOID IOCTL_start_InBuffer = NULL;
	DWORD IOCTL_start_bytesReturned = 0;
	//00   00   00   00    01   00   00   00   00   00   00   00    01   00   00   00    01   00    00    00
	char IOCTL_start_message[0x14] = { 0x0, 0x0, 0x0, 0x0, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x01, 0x0, 0x0, 0x0, 0x01, 0x0, 0x00, 0x00 };

	LPVOID IOCTL_filter_InBuffer = NULL;
	DWORD IOCTL_filter_bytesReturned = 0;
	char IOCTL_filter_message[0xD8] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x37, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	IOCTL_filter_InBuffer = (LPVOID)malloc(0xD8);
	memcpy(IOCTL_filter_InBuffer, IOCTL_filter_message, 0xD8);
	/*status = DeviceIoControl(hDriver, IOCTL_filter, IOCTL_filter_InBuffer, 0xD8, NULL, 0, &IOCTL_filter_bytesReturned, NULL);
	if (!status) {
		printf("[!] Error! Filter creation failed!\n");
		return -1;
	}*/


	IOCTL_start_InBuffer = (LPVOID)malloc(0x14);
	memcpy(IOCTL_start_InBuffer, IOCTL_start_message, 0x14);
	status = DeviceIoControl(hDriver, IOCTL_start, IOCTL_start_InBuffer, 0x14, NULL, 0, &IOCTL_start_bytesReturned, NULL);
	if (status) {
		return 0;
	}
	auto error = GetLastError();
	return -1;
}

void user_trace_013_pktmon::start()
{
	HANDLE hDriver;
    krabs::user_trace trace(L"pktmon_poc");
    //krabs::provider<> provider(krabs::guid(L"{4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac}"));
	//krabs::provider<> provider(L"Microsoft-Windows-NDIS-PacketCapture");
	krabs::provider<> provider(L"Microsoft-Windows-NDIS");
	provider.enable_property(provider.enable_property() | EVENT_ENABLE_PROPERTY_PROCESS_START_KEY | EVENT_ENABLE_PROPERTY_SID | EVENT_ENABLE_PROPERTY_TS_ID);
	
	//hDriver = pktmon_service_start();
	if (false) {
		std::wcout << L"[*] Starting PktMon service..." << std::endl;
		if (hDriver == NULL) {
			std::wcout << L"[-] Error! Service PktMon could not be started!" << std::endl;
			return;
		}
		std::wcout << L"[+] SERVICE STARTED SUCCESSFULLY!" << std::endl;

		std::wcout << L"[+] Initializing capture..." << std::endl;
		if (initiate_capture(hDriver) == -1) {
			std::wcout << L"[-] Error! Could not start capturing!" << std::endl;
			return;
		}
	}
	else {
		ndiscap_service_start();
	}
	

    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {

        // Once an event is received, if we want krabs to help us analyze it, we need
        // to snap in a schema to ask it for information.
        krabs::schema schema(record, trace_context.schema_locator);
		
        // We then have the ability to ask a few questions of the event.        
        krabs::parser parser(schema);
		//if (schema.event_id() == 120) {
		//	std::wcout << L"Event " << schema.event_id();
		//	std::wcout << L"(" << schema.event_name() << L") received." << std::endl;
		//	auto pid = record.EventHeader.ProcessId;
		//	std::wcout << L" ProcessIP=" << pid << std::endl;
		//	uint32_t dest = parser.parse<uint32_t>(L"DestinationIP");
		//	//auto ip4d = parser::parse<ip_address>(dest);
		//	std::wcout << L" DestinationIP=" << dest << std::endl;
		//	//std::wcout << L" DestinationIP=" << ip4d << std::endl;
		//	uint32_t source = parser.parse<uint32_t>(L"SourceIP");
		//	//auto ip4s = parser::parse<ip_address>(source);
		//	std::wcout << L" SourceIP=" << source << std::endl;;
		//	//std::wcout << L" SourceIP=" << ip4s << std::endl;;
		//	
		//	auto extended_data_count = record.ExtendedDataCount;
		//	for (USHORT i = 0; i < extended_data_count; i++)
		//	{
		//		auto& extended_data = record.ExtendedData[i];

		//		if (extended_data.ExtType == EVENT_HEADER_EXT_TYPE_TS_ID)
		//		{
		//			auto result = (reinterpret_cast<_EVENT_EXTENDED_ITEM_TS_ID*>(extended_data.DataPtr))->SessionId;
		//			std::wcout << L"(" << "EVENT_EXTENDED_ITEM_TS_ID" << L") received." << result << std::endl;
		//		}
		//		if (extended_data.ExtType == EVENT_HEADER_EXT_TYPE_SID)
		//		{

		//		}
		//		if (extended_data.ExtType == EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY)
		//		{
		//			auto result = (reinterpret_cast<_EVENT_EXTENDED_ITEM_PROCESS_START_KEY*>(extended_data.DataPtr))->ProcessStartKey;
		//			std::wcout << L"(" << "EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY" << L") received." << result << std::endl;
		//		}
		//	}
		//}
		
			std::wcout << L"Event " << schema.event_id();
			std::wcout << L"(" << schema.event_name() << L") received." << std::endl;
		
		

        });

    trace.enable(provider);
    trace.start();  
}