// This example demonstrates rundown events that capture system state.

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Threading;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace013_FromFile
    {
        public static void Start()
        {
            var trace = new UserTrace();

            // Rundown events are not true real-time tracing events. Instead they describe the state of the system.
            // Usually these are just extra events in the provider. For example, Microsoft-Windows-Kernel-Process
            // has ProcessRundown events as well as ProcessStart events.            
            var providerApi = new Provider("Microsoft-Windows-Kernel-Audit-API-Calls");
            //provider.Any = 0x10;  // WINEVENT_KEYWORD_PROCESS
            // ...but the rundown events often cannot be enabled by keyword alone.
            // The trace needs to be sent EVENT_CONTROL_CODE_CAPTURE_STATE.
            // This is what EnableRundownEvents() does.
            //provider.EnableRundownEvents();

            // process rundown events - i.e. running processes
            //var processRundownFilter = new EventFilter(Filter.EventIdIs(15));  // ProcessRundown
            providerApi.OnEvent += (record) =>
            {
                // Records have general properties that are applicable to every ETW
                // record regardless of schema. They give us general information.
                Console.WriteLine("ProviderName=  " + record.ProviderName);
                Console.WriteLine("Event= " + record.Id + " (" + record.Name + ") received.");
            };
            //provider.AddFilter(processRundownFilter);
            trace.Enable(providerApi);
            trace.SetTraceFilename("");
            trace.Open();

            Thread workerThread = new Thread(() => {
                trace.Process();
            });

            workerThread.Start();
        }
    }
}
