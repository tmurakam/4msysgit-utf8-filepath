#ifndef __WIN32UTF8_H
#define __WIN32UTF8_H

WINBASEAPI int WINAPI CreateHardLinkA(const char *filename, const char *existingFilename, SECURITY_ATTRIBUTES *securityAttributes);
WINBASEAPI int WINAPI CreateHardLinkW(const wchar_t *filename, const wchar_t *existingFilename, SECURITY_ATTRIBUTES *securityAttributes);

WINBASEAPI int WINAPI CreateSymbolicLinkA(const char *filename, const char *existingFilename, DWORD flags);

void convert_argv_utf8(int *pargc, char ***pargv);

int utf8_fputs(const char *s, FILE *fp);

#endif

