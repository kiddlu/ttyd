#ifndef TTYD_PTY_H
#define TTYD_PTY_H

#include <stdbool.h>
#include <stdint.h>
#include <uv.h>

#include "buf.h"

typedef struct _ptyProc_ ptyProc;
typedef void (*pty_read_cb)(ptyProc *, buf_t *, bool);
typedef void (*pty_exit_cb)(ptyProc *);

struct _ptyProc_
{
    int      pid, exit_code, exit_signal;
    uint16_t columns, rows;

    pid_t       pty;
    uv_thread_t tid;

    char **argv;
    char **envp;
    char  *cwd;

    uv_loop_t *loop;
    uv_async_t async;
    uv_pipe_t *in;
    uv_pipe_t *out;
    bool       paused;

    pty_read_cb read_cb;
    pty_exit_cb exit_cb;
    void       *ctx;
};

ptyProc *pty_init(void *ctx, uv_loop_t *loop, char *argv[], char *envp[]);
bool     pty_running(ptyProc *process);
void     pty_free(ptyProc *process);
int      pty_spawn(ptyProc *process, pty_read_cb read_cb, pty_exit_cb exit_cb);
void     pty_pause(ptyProc *process);
void     pty_resume(ptyProc *process);
int      pty_write(ptyProc *process, buf_t *buf);
bool     pty_resize(ptyProc *process);
bool     pty_kill(ptyProc *process, int sig);

#endif  // TTYD_PTY_H
