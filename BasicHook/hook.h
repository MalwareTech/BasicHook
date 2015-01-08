typedef struct 
{
	CHAR *dll;
	CHAR *name;
	LPVOID proxy;
	LPVOID original;
	DWORD length;
} HOOK_ARRAY;

typedef int (WINAPI *TdefOldMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCTSTR lpCaption, UINT uType);
typedef int (WINAPI *TdefOldMessageBoxW)(HWND hWnd, LPWSTR lpText, LPCTSTR lpCaption, UINT uType);

int WINAPI NewMessageBoxA(HWND hWnd, LPCSTR lpText, LPCTSTR lpCaption, UINT uType);
int WINAPI NewMessageBoxW(HWND hWnd, LPWSTR lpText, LPCTSTR lpCaption, UINT uType);

BOOL HookFunction(CHAR *dll, CHAR *name, LPVOID proxy, LPVOID original, PDWORD length);
BOOL UnhookFunction(CHAR *dll, CHAR *name, LPVOID original, DWORD length);