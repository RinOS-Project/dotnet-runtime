// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma once

// Target-only adapter for the RinOS crashd boundary. Initialization is an
// ordinary startup operation; Notify is deliberately limited to one fixed
// write from the fatal-signal path.
class RinOSCrashReportHandoff
{
public:
    bool Initialize();
    bool Notify(int signal, bool reportFileReady);

private:
    int m_fd = -1;
    unsigned long long m_processId = 0;
    unsigned long long m_processInstanceCookie = 0;
};
