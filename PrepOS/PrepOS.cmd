powershell -ExecutionPolicy Unrestricted -file "%~dp0ModifySecurityEventLogACL.ps1"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
%~dp0LGPO.exe /ac %~dp0audit.csv /v
gpupdate /target:computer /force
auditpol /get /Subcategory:{0CCE9225-69AE-11D9-BED3-505054503030},{0CCE9226-69AE-11D9-BED3-505054503030} /r
net localgroup "Event Log Readers" %USERNAME% /add
Echo Please logoff and login again to get "Event Log Readers" group membership
@pause
