# HOOK PasswordChangeNotify

## Synopsis

The tool implements permission persistence through HOOK PasswordChangeNotify. 

## Description

PasswordChangeNotify is a Windows API named PsamPasswordNotificationRoutine in Microsoft's official documentation. When the user resets the password, the system will first check whether the new password meets the complexity requirements. If the password meets the requirements, the LSA will call the PasswordChangeNotify function to synchronize the password in the system. The syntax of this function is roughly as follows.

```c++
PSAM_PASSWORD_NOTIFICATION_ROUTINE PsamPasswordNotificationRoutine;

NTSTATUS PsamPasswordNotificationRoutine(
  [in] PUNICODE_STRING UserName,
  [in] ULONG RelativeId,
  [in] PUNICODE_STRING NewPassword
)
{...}
```

When PasswordChangeNotify is called, the username and password will be passed in in clear text. Testers can use HOOK technology to hijack the execution process of the PasswordChangeNotify function to obtain the incoming plaintext password.

The tool implements permission persistence through HOOK PasswordChangeNotify. Modified based on the original [HookPasswordChange](https://github.com/clymb3r/Misc-Windows-Hacking) to add a simple HTTP request functionality via the WinINet API. When the administrator modifies the password, the user password will be transmitted to the remote server via the HTTP POST method.

![Snipaste_2022-02-12_02-26-11](https://s2.loli.net/2022/02/12/heSGRpYBa81sq7V.png)

## Link

https://github.com/clymb3r/Misc-Windows-Hacking

