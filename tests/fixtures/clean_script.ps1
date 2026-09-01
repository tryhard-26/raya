# Clean administrative script
Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object -Property Id, ProcessName, CPU | Format-Table -AutoSize
Write-Output "System health check finished successfully."
