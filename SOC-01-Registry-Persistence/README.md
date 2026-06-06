# SOC-01 Registry Persistence via Run Key

## Alert

Registry Persistence Detected

## Investigation Summary

A registry Run Key was created to achieve persistence using a hidden PowerShell command.

## Evidence Collected

- Parent Process: cmd.exe
- Child Process: reg.exe
- Registry Path:
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- Value Name:
  Updater
- Command:
  powershell.exe -nop -w hidden

## MITRE ATT&CK

- T1547.001 Registry Run Keys / Startup Folder

## Timeline

17:11:46 - Registry key created

17:41:45 - Registry key removed

## Response Actions

1. Preserve evidence
2. Isolate system
3. Remove malicious registry key
4. Check additional persistence mechanisms
5. Review network activity
6. Escalate if required

## Lessons Learn

Process logs can reveal registry persistence activity even when direct registry logging is unavailable.
