// This example demonstrates rundown events that capture system state.

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Threading;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace009_OpenTrace
    {
        public static void Start()
        {
            

            var trace = new UserTrace("SecSense");

            // Rundown events are not true real-time tracing events. Instead they describe the state of the system.
            // Usually these are just extra events in the provider. For example, Microsoft-Windows-Kernel-Process
            // has ProcessRundown events as well as ProcessStart events.            
            var providerSec = new Provider(Guid.Parse("{16c6501a-ff2d-46ea-868d-8f96cb0cb52d}"));
            var providerFile = new Provider("Microsoft-Windows-Kernel-File");

            //provider.Any = 0x10;  // WINEVENT_KEYWORD_PROCESS
            // ...but the rundown events often cannot be enabled by keyword alone.
            // The trace needs to be sent EVENT_CONTROL_CODE_CAPTURE_STATE.
            // This is what EnableRundownEvents() does.
            //provider.EnableRundownEvents();

            // process rundown events - i.e. running processes
            //var processRundownFilter = new EventFilter(Filter.EventIdIs(15));  // ProcessRundown
            IEventRecordDelegate onEvent = (record) =>
            {
                // Records have general properties that are applicable to every ETW
                // record regardless of schema. They give us general information.
                Console.WriteLine("Event " + record.Id + " (" + record.Name + ") received.");
            };
            //provider.AddFilter(processRundownFilter);
            providerSec.OnEvent += onEvent;
            providerFile.OnEvent += onEvent;
            trace.Enable(providerSec);
            trace.Enable(providerFile);
            trace.Open();
            DateTime startTime = DateTime.Now;
            Thread workingThread = new Thread(() => {
                trace.Process(startTime, true);
                //trace.Process();
            });
            
            workingThread.Start();
            Thread.Sleep(100000);
            trace.Close();
            workingThread.Join();
        }

        private static void ProviderFile_OnEvent(IEventRecord record)
        {
            throw new NotImplementedException();
        }
    }
}