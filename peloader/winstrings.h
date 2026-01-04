#ifndef __STRINGS_H
#define __STRINGS_H

#include "winnt_types.h"

size_t CountWideChars(const void *wcharbuf);
char * CreateAnsiFromWide(void *wcharbuf);
char *string_from_wchar(void *wcharbuf, size_t len);

#define wcscmp _win_wcscmp
#define wcsicmp _win_wcsicmp
extern INT WINCALL wcscmp(const wchar_t *s1, const wchar_t *s2);
extern INT WINCALL wcsicmp(const wchar_t *s1, const wchar_t *s2);

#endif
