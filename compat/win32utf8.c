/*
  Win32 API UTF-8 conversion wrapper

  Author: Takuya Murakami <tmurakam@tmurakam.org>
 */

#include "../git-compat-util.h"
#include "win32utf8.h"
#include "../strbuf.h"
#include "../utf8.h"

#define	MAX_STRING	32768

static wchar_t *utf82wchar(const char *s)
{
	static wchar_t buffer[6][MAX_STRING];
	static int counter = 0;
	int n;

	if (!s) return NULL;

	counter++;
	if (counter >= ARRAY_SIZE(buffer)) {
		counter = 0;
	}

	n = MultiByteToWideChar(CP_UTF8, 0, s, -1, buffer[counter], MAX_STRING);
	if (n > 0) {
		return buffer[counter];
	}
	return NULL;
}

static char *wchar2utf8(const wchar_t *s)
{
	static char buffer[6][MAX_STRING];
	static int counter = 0;
	int n;

	if (!s) return NULL;

	counter++;
	if (counter >= ARRAY_SIZE(buffer)) {
		counter = 0;
	}

	n = WideCharToMultiByte(CP_UTF8, 0, s, -1, buffer[counter], MAX_STRING, NULL, NULL);
	if (n > 0) {
		return buffer[counter];
	}
	return NULL;
}

////////////////////////////////////////////////////////////////
// replacement of libc APIs

int _wchdir(const wchar_t *);
int _wmkdir(const wchar_t *);
int _wrmdir(const wchar_t *);
wchar_t *_wgetcwd(wchar_t *, int);

#undef open
int open(const char *filename, int flags, ...)
{
	va_list args;
	unsigned mode;

	va_start(args, flags);
	mode = va_arg(args, int);
	va_end(args);

	return _wopen(utf82wchar(filename), flags, mode);
}

#undef fopen
FILE * fopen(const char *filename, const char *mode)
{
	return _wfopen(utf82wchar(filename), utf82wchar(mode));
}

#undef freopen
FILE * freopen(const char *filename, const char *mode, FILE *stream)
{
	return _wfreopen(utf82wchar(filename), utf82wchar(mode), stream);
}

#undef access
int access(const char *pathname, int mode)
{
	return _waccess(utf82wchar(pathname), mode);
}

#undef chmod
int chmod(const char *path, int mode)
{
	return _wchmod(utf82wchar(path), mode);
}

#undef unlink
int unlink(const char *pathname)
{
	return _wunlink(utf82wchar(pathname));
}

#undef chdir
int chdir(const char *path)
{
	return _wchdir(utf82wchar(path));
}

#undef rename
int rename(const char *oldpath, const char *newpath)
{
	return _wrename(utf82wchar(oldpath), utf82wchar(newpath));
}

#undef mkdir
int mkdir(const char *pathname)
{
	return _wmkdir(utf82wchar(pathname));
}

#undef rmdir
int rmdir(const char *pathname)
{
	return _wrmdir(utf82wchar(pathname));
}

#undef getcwd
char *getcwd(char *pointer, int len)
{
	wchar_t buffer[PATH_MAX];
	wchar_t *ret = _wgetcwd(buffer, PATH_MAX);
	char *utf8;

	if (!ret) return NULL;

	utf8 = wchar2utf8(buffer);
	if (!utf8) return NULL;

	if (strlen(utf8) >= len) {
		errno = ERANGE;
		return NULL;
	}
	strcpy(pointer, utf8);
	return pointer;
}

////////////////////////////////////////////////////////////////
// Win32 APIs

WINBASEAPI BOOL WINAPI CreateProcessA(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	PVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	STARTUPINFOW si;
	STARTUPINFOA *sa = lpStartupInfo;
	BOOL ret;
	wchar_t *wenv = NULL;

	// convert environemnt variables
	if (lpEnvironment) {
		int len;
		char *p;
		wchar_t *wp;

		p = lpEnvironment;
		len = 0;
		while (*p) {
			len += utf8_strwidth(p) + 1;
			p += strlen(p) + 1;
		}
		len++;

		wenv = malloc(len * sizeof(wchar_t));

		p = lpEnvironment;
		wp = wenv;
		while (*p) {
			wchar_t *w = utf82wchar(p);
			wcscpy(wp, w);

			p += strlen(p) + 1;
			wp+= wcslen(wp) + 1;
		}
		*wp = 0;
	}

	// Convert startupinfo
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.lpDesktop = utf82wchar(sa->lpDesktop);
	si.lpTitle = utf82wchar(sa->lpTitle);
	si.dwX = sa->dwX;
	si.dwY = sa->dwY;
	si.dwXSize = sa->dwXSize;
	si.dwYSize = sa->dwYSize;
	si.dwXCountChars = sa->dwXCountChars;
	si.dwYCountChars = sa->dwYCountChars;
	si.dwFillAttribute = sa->dwFillAttribute;
	si.dwFlags = sa->dwFlags;
	si.wShowWindow = sa->wShowWindow;
	si.hStdInput = sa->hStdInput;
	si.hStdOutput = sa->hStdOutput;
	si.hStdError = sa->hStdError;

	ret = CreateProcessW(
		utf82wchar(lpApplicationName),
		utf82wchar(lpCommandLine),
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags | CREATE_UNICODE_ENVIRONMENT,
		wenv,
		utf82wchar(lpCurrentDirectory),
		&si,
		lpProcessInformation);

	free(wenv);
	return ret;
}


WINBASEAPI HANDLE WINAPI CreateFileA(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
{
	return CreateFileW(utf82wchar(lpFileName),
			  dwDesiredAccess,
			  dwShareMode,
			  lpSecurityAttributes,
			  dwCreationDisposition,
			  dwFlagsAndAttributes,
			  hTemplateFile);
}

WINBASEAPI DWORD WINAPI GetFileAttributesA(LPCSTR filename)
{
	return GetFileAttributesW(utf82wchar(filename));
}

WINBASEAPI int WINAPI GetFileAttributesExA(const char *filename, GET_FILEEX_INFO_LEVELS level, void *fileinfo)
{
	return GetFileAttributesExW(utf82wchar(filename), level, fileinfo);
}

WINBASEAPI BOOL WINAPI SetFileAttributesA(LPCSTR filename, DWORD attr)
{
	return SetFileAttributesW(utf82wchar(filename), attr);
}

WINBASEAPI BOOL WINAPI MoveFileExA(LPCSTR oldfile, LPCSTR newfile, DWORD flags)
{
	return MoveFileExW(utf82wchar(oldfile), utf82wchar(newfile), flags);
}

WINBASEAPI int WINAPI CreateHardLinkA(const char *filename, const char *existingFilename, SECURITY_ATTRIBUTES *securityAttributes)
{
	typedef BOOL (WINAPI *T)(const wchar_t*, const wchar_t*, LPSECURITY_ATTRIBUTES);
	static T createHardLinkW = NULL;

	if (!createHardLinkW) {
		createHardLinkW = (T)GetProcAddress(
			GetModuleHandle("kernel32.dll"), "CreateHardLinkW");
		if (!createHardLinkW) {
			createHardLinkW = (T)-1;
		}
	}
	if (createHardLinkW == (T)-1) {
		SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
		return 0;
	}
	return createHardLinkW(utf82wchar(filename), utf82wchar(existingFilename), securityAttributes);
}

WINBASEAPI int WINAPI CreateSymbolicLinkA(const char *filename, const char *existingFilename, DWORD flags)
{
	typedef BOOL (WINAPI *T)(const wchar_t*, const wchar_t*, DWORD);
	static T createSymbolicLinkW = NULL;

	if (!createSymbolicLinkW) {
#if 0  // does not support symbolic link!
		createSymbolicLinkW = (T)GetProcAddress(
			GetModuleHandle("kernel32.dll"), "CreateSymbolicLinkW");
#endif
		if (!createSymbolicLinkW) {
			createSymbolicLinkW = (T)-1;
		}
	}
	if (createSymbolicLinkW == (T)-1) {
		SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
		return 0;
	}
	return createSymbolicLinkW(utf82wchar(filename), utf82wchar(existingFilename), flags);
}

static inline void convertFindData(WIN32_FIND_DATAW *w, WIN32_FIND_DATAA *a)
{
	a->dwFileAttributes = w->dwFileAttributes;
	a->ftCreationTime = w->ftCreationTime;
	a->ftLastAccessTime = w->ftLastAccessTime;
	a->ftLastWriteTime = w->ftLastWriteTime;
	a->nFileSizeHigh = w->nFileSizeHigh;
	a->nFileSizeLow = w->nFileSizeLow;
	a->dwReserved0 = w->dwReserved0;
	a->dwReserved1 = w->dwReserved1;
	strcpy(a->cFileName, wchar2utf8(w->cFileName));
	strcpy(a->cAlternateFileName, wchar2utf8(w->cAlternateFileName));
}

WINBASEAPI HANDLE WINAPI FindFirstFileA(LPCSTR filename, WIN32_FIND_DATAA *data)
{
	WIN32_FIND_DATAW wdata;

	HANDLE ret = FindFirstFileW(utf82wchar(filename), &wdata);
	if (ret == INVALID_HANDLE_VALUE) {
		return ret;
	}

	convertFindData(&wdata, data);
	return ret;
}

WINBASEAPI int WINAPI FindNextFileA(HANDLE handle, WIN32_FIND_DATAA *data)
{
	WIN32_FIND_DATAW wdata;

	int ret = FindNextFileW(handle, &wdata);
	if (ret != 0) {
		convertFindData(&wdata, data);
	}
	return ret;
}

//////////////////////////////////////////////////////////////
// convert argv

#include <shellapi.h>

void convert_argv_utf8(int argc, const char **argv)
{
	int wargc;
	wchar_t **wargv;
	int i;

	wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
	if (!wargv) {
		return;
	}
	if (wargc != argc) {
		LocalFree(wargv);
		return;
	}

	for (i = 0; i < argc; i++) {
		char *arg = wchar2utf8(wargv[i]);
		if (!arg) continue;

		argv[i] = strdup(arg);
	}
	LocalFree(wargv);
}
