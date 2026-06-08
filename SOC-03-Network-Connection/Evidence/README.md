# SOC-03 Network Connection Detection

## Alert

PowerShell Network Connection Detected

## Investigation Summary

A PowerShell process initiated outbound network connections to external IP addresses. The activity was generated using the `Invoke-WebRequest` command and successfully created Sysmon Event ID 3 logs. The investigation focused on identifying the process responsible for the connection, the user account involved, and the destination IP addresses contacted.

## MITRE ATT&CK Mapping

| Technique                                     | ID        |
| --------------------------------------------- | --------- |
| Command and Scripting Interpreter: PowerShell | T1059.001 |
| Application Layer Protocol: Web Protocols     | T1071.001 |
| Ingress Tool Transfer                         | T1105     |

## Indicators of Compromise

| Indicator        | Value                    |
| ---------------- | ------------------------ |
| Event ID         | Sysmon Event ID 3        |
| Source Process   | powershell.exe           |
| User             | SOC-Lab                  |
| Command          | Invoke-WebRequest        |
| Protocol         | TCP                      |
| Destination Port | 80                       |
| Network Activity | Outbound HTTP Connection |

## Detection Logic

```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" "EventID>3<"
| rex "Image'>(?<Image>[^<]+)"
| rex "User'>(?<User>[^<]+)"
```

## Findings

* PowerShell initiated an outbound network connection.
* Sysmon Event ID 3 successfully logged the connection details.
* The activity was generated using Invoke-WebRequest.
* Destination IP addresses were captured within the Sysmon logs.
* The user responsible for the activity was identified as SOC-Lab.
* No additional suspicious processes were observed during the investigation.

## Evidence

### Network Connection Event

![Network Connection Event](Evidence/Network_Connection_Event.png)

### Destination IP Detection

![Destination IP Detection](Evidence/Destination_IP_Detection.png)

### SPL Query

![SPL Query](Evidence/SPL-Query.png)

## Analyst Conclusion

The investigation confirmed that PowerShell established outbound network connections and generated Sysmon Event ID 3 logs. The activity was performed using Invoke-WebRequest for lab simulation purposes. The exercise demonstrates how SOC analysts can identify network-capable processes, investigate destination IP addresses, and validate network activity through Sysmon telemetry and Splunk searches.

