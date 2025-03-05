#ifndef TTYD_BUF_H
#define TTYD_BUF_H

typedef struct
{
    char  *base;
    size_t len;
} buf_t;

buf_t *buf_init(char *base, size_t len);
void   buf_free(buf_t *buf);

#endif