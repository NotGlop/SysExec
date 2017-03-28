# SysExec

SysExec is a tool for exploiting the vulnerability initially disclosed here: https://bugs.chromium.org/p/project-zero/issues/detail?id=222.
Although the vulnerability was not initially patched, Microsoft finally decided to fix it with MS16-075: https://technet.microsoft.com/en-us/library/security/ms16-075.aspx

# Usage:
    sysexec.exe <program>
    
    <program>: program to be run under SYSTEM privileges, non-interactive mode
    
    
    
# How it works

The current version will trigger tracing events by starting the RASMAN service.
Since this service can only be started (but not stopped) by unprivileged user, you will only get one chance.
However, you can trigger other services such as IpHlpSvc or RASPLAP if RASMAN is already started.
