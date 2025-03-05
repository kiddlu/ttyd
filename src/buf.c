#include <stdlib.h>
#include <string.h>

#include "buf.h"

#include "utils.h"

buf_t *buf_init(char *base, size_t len)
{
    buf_t *buf = xmalloc(sizeof(buf_t));
    buf->base  = xmalloc(len);
    memcpy(buf->base, base, len);
    buf->len = len;
    return buf;
}

void buf_free(buf_t *buf)
{
    if (buf == NULL)
        return;
    if (buf->base != NULL)
        free(buf->base);
    free(buf);
}