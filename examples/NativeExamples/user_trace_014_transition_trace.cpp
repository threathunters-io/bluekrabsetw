// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace with an ETL file
#pragma once

#include <iostream>
#include <chrono>
#include <thread>

#include "..\..\bluekrabs\krabs.hpp"
#include "examples.h"



void user_trace_014_transition_trace::start()
{
	
	krabs::user_trace trace(L"test_sense");

	
	auto config = trace.query_config();

	std::wcout << L"config" << std::endl;
}