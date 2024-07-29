// This example demonstrates rundown events that capture system state.

using System;
using System.Collections.Generic;
using Microsoft.O365.Security.ETW;

namespace ManagedExamples
{
    public static class UserTrace008_DirectFilter
    {
        public static void Start()
        {
            var trace = new UserTrace("UserTrace006_Rundown");

            // Rundown events are not true real-time tracing events. Instead they describe the state of the system.
            // Usually these are just extra events in the provider. For example, Microsoft-Windows-Kernel-Process
            // has ProcessRundown events as well as ProcessStart events.
            var provider = new Provider("Microsoft-Windows-Kernel-Registry");
            //provider.Any = 0x10;  // WINEVENT_KEYWORD_PROCESS
            // ...but the rundown events often cannot be enabled by keyword alone.
            // The trace needs to be sent EVENT_CONTROL_CODE_CAPTURE_STATE.
            // This is what EnableRundownEvents() does.
            //provider.EnableRundownEvents();
           
            var f4 = new SystemFlags(0xFFFFFFFFFFFF, 4);
            List<int> ids = new List<int>();
            ids.Add(5);
            var f5 = new EventIds(ids); 

            var pre = new PreEventFilter( 
                f4,
                f5
            );
            
            provider.AddFilter(pre);
            provider.OnEvent += ProcessEventHandler;

            trace.Enable(provider);
            trace.Start();
        }

        private static void ProcessEventHandler(IEventRecord record)
        {
            //if(record.Id == 5)
            //{
                //var pid = record.GetUInt32("ProcessID");
                var keyName = record.GetUnicodeString("KeyName");
                var valueName = record.GetUnicodeString("ValueName");
                var capturedDataSize = record.GetUInt16("CapturedDataSize");
                var previousDataCapturedSize = record.GetUInt16("PreviousDataCapturedSize");
                Console.WriteLine($"EventId={record.Id}");
                Console.WriteLine($"KeyName={keyName}");
                Console.WriteLine($"ValueName={valueName}");
                Console.WriteLine($"CapturedDataSize={capturedDataSize}");
                Console.WriteLine($"PreviousDataCapturedSize={previousDataCapturedSize}");
            //}
           
        }
    }
}