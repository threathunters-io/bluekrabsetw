// This example demonstrates rundown events that capture system state.

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Threading;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace011_UpdateTrace
    {
        public static void Start()
        {
            var trace = new UserTrace("update_trace");

            // Rundown events are not true real-time tracing events. Instead they describe the state of the system.
            // Usually these are just extra events in the provider. For example, Microsoft-Windows-Kernel-Audit-API-Calls
            // has ProcessRundown events as well as ProcessStart events.            
            var provider = new Provider("Microsoft-Windows-Kernel-Audit-API-Calls");
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
                Console.WriteLine("Time " + record.Timestamp);
                Console.WriteLine("Event " + record.Id + " (" + record.Name + ") received.");
            };
            //provider.AddFilter(processRundownFilter);
            Action QueryStats = () => {
                var stats = trace.QueryStats();
                Console.WriteLine("Current Config:");
                Console.WriteLine("Min Buffer: " + stats.MinimumBuffers);
                Console.WriteLine("Max buffer: " + stats.MaximumBuffers);
                Console.WriteLine("Max Flush: " + stats.FlushTimer);
            };

            trace.Enable(provider);
            var workerThread = new Thread(() => { 
                trace.Start();
            });
            workerThread.Start();         
            Thread.Sleep(1000);
            QueryStats();
            EventTraceProperties eventTraceProperties = new EventTraceProperties();
            eventTraceProperties.MaximumBuffers = 128;
            eventTraceProperties.FlushTimer = 10;
            trace.SetTraceProperties(eventTraceProperties);
            trace.Update();
            QueryStats();
            Thread.Sleep(1000);
            trace.Stop();
            workerThread.Join();
        }
    }
}