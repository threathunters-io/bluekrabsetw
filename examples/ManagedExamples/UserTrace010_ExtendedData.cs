// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example demonstrates collecting stack traces as part of events.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.O365.Security.ETW;
using Microsoft.Win32.SafeHandles;

namespace ManagedExamples
{
    public static class UserTrace010_ExtendedData
    {
        public static void Start()
        {
            if (!(new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)))
            {
                Console.WriteLine("Microsoft-Windows-Kernel-* providers can only be traced by Administrators");
                return;
            }

            var trace = new UserTrace("UserTrace010_ExtendedData");
            ////////////////////////////////////////////////////////////////////////////////
            // Microsoft-Windows-Kernel-Process
            // 
            var processProvider = new Provider("Microsoft-Windows-Kernel-Process");
            processProvider.TraceFlags |= TraceFlags.IncludeStackTrace;
            processProvider.TraceFlags |= TraceFlags.IncludeUserSid;
            processProvider.TraceFlags |= TraceFlags.IncludeProcessStartKey;
            processProvider.TraceFlags |= TraceFlags.SourceContainerTrackingEventKey;
            processProvider.TraceFlags |= TraceFlags.IncludeProcessEventKey;
            processProvider.TraceFlags |= TraceFlags.IncludeTerminalSessionId;
            processProvider.TraceFlags |= (TraceFlags)8;

            processProvider.OnEvent += (record) =>
            {
                String Sid;
                record.TryGetSid(out Sid);

                UInt64 ProcessStartKey;
                record.TryGetProcessStartKey(out ProcessStartKey);

                UInt64 EventKey;
                record.TryGetEventKey(out EventKey);

                UInt64 TsId;
                record.TryGetTsId(out TsId);
            };

            trace.Enable(processProvider);
            trace.Start();
        }
    }
}

