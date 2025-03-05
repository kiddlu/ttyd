#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *sys_signame[NSIG] = {
    "zero", "HUP",  "INT",  "QUIT", "ILL",    "TRAP",   "ABRT",  "UNUSED", "FPE",  "KILL", "USR1",
    "SEGV", "USR2", "PIPE", "ALRM", "TERM",   "STKFLT", "CHLD",  "CONT",   "STOP", "TSTP", "TTIN",
    "TTOU", "URG",  "XCPU", "XFSZ", "VTALRM", "PROF",   "WINCH", "IO",     "PWR",  "SYS",  NULL};

void *xmalloc(size_t size)
{
    if (size == 0)
        return NULL;
    void *p = malloc(size);
    if (!p)
        abort();
    return p;
}

void *xrealloc(void *p, size_t size)
{
    if ((size == 0) && (p == NULL))
        return NULL;
    p = realloc(p, size);
    if (!p)
        abort();
    return p;
}

char *uppercase(char *s)
{
    while (*s)
    {
        *s = (char)toupper((int)*s);
        s++;
    }
    return s;
}

char *lowercase(char *s)
{
    while (*s)
    {
        *s = (char)tolower((int)*s);
        s++;
    }
    return s;
}

bool endswith(const char *str, const char *suffix)
{
    size_t str_len    = strlen(str);
    size_t suffix_len = strlen(suffix);
    return str_len > suffix_len && !strcmp(str + (str_len - suffix_len), suffix);
}

int get_sig_name(int sig, char *buf, size_t len)
{
    int n = snprintf(buf, len, "SIG%s", sig < NSIG ? sys_signame[sig] : "unknown");
    uppercase(buf);
    return n;
}

int get_sig(const char *sig_name)
{
    for (int sig = 1; sig < NSIG; sig++)
    {
        const char *name = sys_signame[sig];
        if (name != NULL &&
            (strcasecmp(name, sig_name) == 0 || strcasecmp(name, sig_name + 3) == 0))
            return sig;
    }
    return atoi(sig_name);
}

int open_uri(char *uri)
{
    // check if X server is running
    if (system("xset -q > /dev/null 2>&1"))
        return 1;
    char command[256];
    sprintf(command, "xdg-open %s > /dev/null 2>&1", uri);
    return system(command);
}
