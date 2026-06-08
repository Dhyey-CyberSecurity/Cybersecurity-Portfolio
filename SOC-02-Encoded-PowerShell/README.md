# SOC-02 Encoded PowerShell Execution

## Alert
Encoded powershell detected

## MITRE ATT&CK Mapping

| Technique | ID |
|------------|------------|
| Obfuscated/Encoded Files and Information | T1027 |
| PowerShell | T1059.001 |

## Indicators of Compromise

| Indicator | Value |
|------------|------------|
| Parent Process | cmd.exe |
| Child Process | powershell.exe |
| PowerShell Flag | -nop |
| PowerShell Flag | -w hidden |
| PowerShell Flag | -enc |

## Evidence

### Encoded PowerShell Execution

![Encoded PowerShell](Evidence/Encoded_PowerShell_Execution.png)

### Parent Child Relationship

![Parent Child](Evidence/Parent_Child_Relationship.png)

### PowerShell Evasion Flags

![PowerShell](Evidence/PowerShell_Evasion_Flags.png)

### SPL Query

![SPL Query](Evidence/SPL-Query.png)
