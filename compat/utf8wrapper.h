#ifndef __UTF8WRAPPER_H
#define __UTF8WRAPPER_H

WINBASEAPI int WINAPI CreateHardLinkA(const char *filename, const char *existingFilename, SECURITY_ATTRIBUTES *securityAttributes);
WINBASEAPI int WINAPI CreateSymbolicLinkA(const char *filename, const char *existingFilename, DWORD flags);

void utf8_argv(int argc, const char **argv);

#endif

