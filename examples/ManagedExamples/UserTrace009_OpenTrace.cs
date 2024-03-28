// This example demonstrates rundown events that capture system state.

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace009_OpenTrace
    {
        public static void Start()
        {
            

            var trace = new UserTrace("test_sense");

            // Rundown events are not true real-time tracing events. Instead they describe the state of the system.
            // Usually these are just extra events in the provider. For example, Microsoft-Windows-Kernel-Process
            // has ProcessRundown events as well as ProcessStart events.            
            var provider = new Provider(Guid.Parse("{16c6501a-ff2d-46ea-868d-8f96cb0cb52d}"));
            //provider.Any = 0x10;  // WINEVENT_KEYWORD_PROCESS
            // ...but the rundown events often cannot be enabled by keyword alone.
            // The trace needs to be sent EVENT_CONTROL_CODE_CAPTURE_STATE.
            // This is what EnableRundownEvents() does.
            //provider.EnableRundownEvents();
            

            

            // process rundown events - i.e. running processes
            //var processRundownFilter = new EventFilter(Filter.EventIdIs(15));  // ProcessRundown
            provider.OnEvent += (record) =>
            {
                // Records have general properties that are applicable to every ETW
                // record regardless of schema. They give us general information.
                Console.WriteLine("Event " + record.Id + " (" + record.Name + ") received.");
            };
            //provider.AddFilter(processRundownFilter);

            trace.Enable(provider);
            trace.Open();
            trace.Process();
        }
    }
}