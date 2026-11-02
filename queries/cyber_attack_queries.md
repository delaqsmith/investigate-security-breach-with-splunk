# SPL Queries Used

## 1. Failed Logon Analysis
```spl
index=botsv3 sourcetype=wineventlog EventCode=4625 | stats count by Account_Name, host | sort -count
```

## 2. Process Creation by Host
```spl
index=botsv3 sourcetype=wineventlog EventCode=4688 | stats count by host | sort -count
```

## 3. PowerShell Activity on BSTOLL-L
```spl
index=botsv3 sourcetype=wineventlog EventCode=4688 host="BSTOLL-L*" New_Process_Name="*powershell*" | table _time, Account_Name, New_Process_Name, Process_Command_Line
```

## 4. Reconnaissance Detection
```spl
index=botsv3 sourcetype=wineventlog EventCode=4688 host="BSTOLL-L*" (Process_Command_Line="*netstat*" OR Process_Command_Line="*reg query*" OR Process_Command_Line="*wmic*") | table _time, Process_Command_Line
```

## 5. Detection Query
```spl
index=botsv3 sourcetype=wineventlog EventCode=4688 Process_Command_Line="*powershell*-enc*" | stats count by host, Account_Name, Process_Command_Line | where count > 0
```