/*
  Win32 API UTF-8 conversion wrapper

  Author: Takuya Murakami <tmurakam@tmurakam.org>
 */

#include "../git-compat-util.h"
#include "win32utf8.h"

static wchar_t *utf82wchar(const char *s)
{
	static wchar_t buffer[10][PATH_MAX];
	static int counter = 0;
	int n;

	if (!s) return NULL;

	counter++;
	if (counter >= ARRAY_SIZE(buffer)) {
		counter = 0;
	}

	n = MultiByteToWideChar(CP_UTF8, 0, s, -1, buffer[counter], PATH_MAX);
	if (n > 0) {
		return buffer[counter];
	}
	return NULL;
}

static char *wchar2utf8(const wchar_t *s)
{
	static char buffer[10][PATH_MAX];
	static int counter = 0;
	int n;

	if (!s) return NULL;

	counter++;
	if (counter >= ARRAY_SIZE(buffer)) {
		counter = 0;
	}

	n = WideCharToMultiByte(CP_UTF8, 0, s, -1, buffer[counter], PATH_MAX, NULL, NULL);
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

#include "../strbuf.h"
#include "../utf8.h"

#if 0
void convert_argv_utf8(int argc, const char **argv)
{
	int i, n;
	wchar_t buffer[PATH_MAX];
	char utf8[PATH_MAX];
	int isUtf8;

	// try to detect encoding
	isUtf8 = 1;
	for (i = 0; i < argc; i++) {
		if (!is_utf8(argv[i])) {
			isUtf8 = 0;
			break;
		}
	}
	if (isUtf8) {
		//printf("no need to convert to UTF-8\n");
		return; // no need to convert
	}
	//printf("convert to UTF-8\n");

	// convert ansi to UTF-8
	for (i = 0; i < argc; i++) {
		n = MultiByteToWideChar(CP_ACP, 0, argv[i], -1, buffer, sizeof(buffer));
		if (n == 0) continue; // TBD

		n = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, utf8, sizeof(utf8), NULL, NULL);
		if (n == 0) continue; // TBD

		argv[i] = strdup(utf8);
	}
}
#endif

void convert_argv_utf8(int argc, const char **argv)
{
	int wargc;
	wchar_t **wargv;
	char **argv;

	wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
	if (!wargv) {
		return;
	}
	if (wargc != argc) {
		LocalFree(wargv);
		return;
	}

	for (int i = 0; i < argc; i++) {
		char *arg = wchar2utf8(wargv[i]);
		if (!arg) continue;

		argv[i] = strdup(arg);
	}
	LocalFree(wargv);
}
