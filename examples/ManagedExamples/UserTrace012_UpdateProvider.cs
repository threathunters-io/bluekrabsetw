// This example demonstrates rundown events that capture system state.

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Threading;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace012_UpdateProvider
    {
        public static void Start()
        {
            var trace = new UserTrace("update_provider");

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
            Thread workerThread = new Thread(() => { 
                trace.Start();
            });

            workerThread.Start();
            Thread.Sleep(1000);
            var providerPowershell = new Provider("Microsoft-Windows-PowerShell");
            providerPowershell.OnEvent += (record) =>
            {
                // Records have general properties that are applicable to every ETW
                // record regardless of schema. They give us general information.
                Console.WriteLine("ProviderName=  " + record.ProviderName);
                Console.WriteLine("Event= " + record.Id + " (" + record.Name + ") received.");
            };

            trace.Enable(providerPowershell);
            trace.Disable(providerApi);

        }

        public static void Start1()
        {
            var trace = new UserTrace("SecSense");

            // Rundown events are not true real-time tracing events. Instead they describe the state of the system.
            // Usually these are just extra events in the provider. For example, Microsoft-Windows-Kernel-Process
            // has ProcessRundown events as well as ProcessStart events.            
            var secProvider = new Provider(Guid.Parse("{16c6501a-ff2d-46ea-868d-8f96cb0cb52d}"));
            var fileProvider = new Provider(Guid.Parse("{edd08927-9cc4-4e65-b970-c2560fb5c289}"));
            
            //provider.Any = 0x10;  // WINEVENT_KEYWORD_PROCESS
            // ...but the rundown events often cannot be enabled by keyword alone.
            // The trace needs to be sent EVENT_CONTROL_CODE_CAPTURE_STATE.
            // This is what EnableRundownEvents() does.
            //provider.EnableRundownEvents();

            // process rundown events - i.e. running processes
            //var processRundownFilter = new EventFilter(Filter.EventIdIs(15));  // ProcessRundown
            secProvider.OnEvent += (record) =>
            {
                // Records have general properties that are applicable to every ETW
                // record regardless of schema. They give us general information.
                Console.WriteLine("Event " + record.Id + " (" + record.Name + ") received.");
            };
            //provider.AddFilter(processRundownFilter);

            fileProvider.OnEvent += (record) =>
            {
                // Records have general properties that are applicable to every ETW
                // record regardless of schema. They give us general information.
                Console.WriteLine("Event " + record.Id + " (" + record.Name + ") received.");
            };

            trace.Enable(secProvider);
            trace.Open();
            trace.Enable(fileProvider);
            Thread workingThread = new Thread(() => {
                trace.Process();
            });

            workingThread.Start();
            Thread.Sleep(1000);
            trace.Close();
            workingThread.Join();

        }
    }




    
}


