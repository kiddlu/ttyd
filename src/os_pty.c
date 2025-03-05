#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/wait.h>

#include <pty.h>

#include "os_pty.h"
#include "utils.h"

static void alloc_cb(uv_handle_t *unused, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = xmalloc(suggested_size);
    buf->len  = suggested_size;
}

static void close_cb(uv_handle_t *handle)
{
    free(handle);
}

static void async_free_cb(uv_handle_t *handle)
{
    free((uv_async_t *)handle->data);
}

pty_buf_t *pty_buf_init(char *base, size_t len)
{
    pty_buf_t *buf = xmalloc(sizeof(pty_buf_t));
    buf->base      = xmalloc(len);
    memcpy(buf->base, base, len);
    buf->len = len;
    return buf;
}

void pty_buf_free(pty_buf_t *buf)
{
    if (buf == NULL)
        return;
    if (buf->base != NULL)
        free(buf->base);
    free(buf);
}

static void read_cb(uv_stream_t *stream, ssize_t n, const uv_buf_t *buf)
{
    uv_read_stop(stream);
    pty_process *process = (pty_process *)stream->data;
    if (n <= 0)
    {
        if (n == UV_ENOBUFS || n == 0)
            return;
        process->read_cb(process, NULL, true);
        goto done;
    }
    process->read_cb(process, pty_buf_init(buf->base, (size_t)n), false);

done:
    free(buf->base);
}

static void write_cb(uv_write_t *req, int unused)
{
    pty_buf_t *buf = (pty_buf_t *)req->data;
    pty_buf_free(buf);
    free(req);
}

pty_process *process_init(void *ctx, uv_loop_t *loop, char *argv[], char *envp[])
{
    pty_process *process = xmalloc(sizeof(pty_process));
    memset(process, 0, sizeof(pty_process));
    process->ctx       = ctx;
    process->loop      = loop;
    process->argv      = argv;
    process->envp      = envp;
    process->columns   = 80;
    process->rows      = 24;
    process->exit_code = -1;
    return process;
}

bool process_running(pty_process *process)
{
    return process != NULL && process->pid > 0 && uv_kill(process->pid, 0) == 0;
}

void process_free(pty_process *process)
{
    if (process == NULL)
        return;

    close(process->pty);
    uv_thread_join(&process->tid);

    if (process->in != NULL)
        uv_close((uv_handle_t *)process->in, close_cb);
    if (process->out != NULL)
        uv_close((uv_handle_t *)process->out, close_cb);
    if (process->argv != NULL)
        free(process->argv);
    if (process->cwd != NULL)
        free(process->cwd);
    char **p = process->envp;
    for (; *p; p++)
        free(*p);
    free(process->envp);
}

void pty_pause(pty_process *process)
{
    if (process == NULL)
        return;
    if (process->paused)
        return;
    uv_read_stop((uv_stream_t *)process->out);
}

void pty_resume(pty_process *process)
{
    if (process == NULL)
        return;
    if (!process->paused)
        return;
    process->out->data = process;
    uv_read_start((uv_stream_t *)process->out, alloc_cb, read_cb);
}

int pty_write(pty_process *process, pty_buf_t *buf)
{
    if (process == NULL)
    {
        pty_buf_free(buf);
        return UV_ESRCH;
    }
    uv_buf_t    b   = uv_buf_init(buf->base, buf->len);
    uv_write_t *req = xmalloc(sizeof(uv_write_t));
    req->data       = buf;
    return uv_write(req, (uv_stream_t *)process->in, &b, 1, write_cb);
}

bool pty_resize(pty_process *process)
{
    if (process == NULL)
        return false;
    if (process->columns <= 0 || process->rows <= 0)
        return false;

    struct winsize size = {process->rows, process->columns, 0, 0};
    return ioctl(process->pty, TIOCSWINSZ, &size) == 0;
}

bool pty_kill(pty_process *process, int sig)
{
    if (process == NULL)
        return false;

    return uv_kill(-process->pid, sig) == 0;
}

static bool fd_set_cloexec(const int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return false;
    return (flags & FD_CLOEXEC) == 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != -1;
}

static bool fd_duplicate(int fd, uv_pipe_t *pipe)
{
    int fd_dup = dup(fd);
    if (fd_dup < 0)
        return false;

    if (!fd_set_cloexec(fd_dup))
        return false;

    int status = uv_pipe_open(pipe, fd_dup);
    if (status)
        close(fd_dup);
    return status == 0;
}

static void wait_cb(void *arg)
{
    pty_process *process = (pty_process *)arg;

    pid_t pid;
    int   stat;
    do
        pid = waitpid(process->pid, &stat, 0);
    while (pid != process->pid && errno == EINTR);

    if (WIFEXITED(stat))
    {
        process->exit_code = WEXITSTATUS(stat);
    }
    if (WIFSIGNALED(stat))
    {
        int sig              = WTERMSIG(stat);
        process->exit_code   = 128 + sig;
        process->exit_signal = sig;
    }

    uv_async_send(&process->async);
}

static void async_cb(uv_async_t *async)
{
    pty_process *process = (pty_process *)async->data;
    process->exit_cb(process);

    uv_close((uv_handle_t *)async, async_free_cb);
    process_free(process);
}

int pty_spawn(pty_process *process, pty_read_cb read_cb, pty_exit_cb exit_cb)
{
    int status = 0;

    uv_disable_stdio_inheritance();

    int            master, pid;
    struct winsize size = {process->rows, process->columns, 0, 0};
    pid                 = forkpty(&master, NULL, NULL, &size);
    if (pid < 0)
    {
        status = -errno;
        return status;
    }
    else if (pid == 0)
    {
        setsid();
        if (process->cwd != NULL)
            chdir(process->cwd);
        if (process->envp != NULL)
        {
            char **p = process->envp;
            for (; *p; p++)
                putenv(*p);
        }
        int ret = execvp(process->argv[0], process->argv);
        if (ret < 0)
        {
            perror("execvp failed\n");
            _exit(-errno);
        }
    }

    int flags = fcntl(master, F_GETFL);
    if (flags == -1)
    {
        status = -errno;
        goto error;
    }
    if (fcntl(master, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        status = -errno;
        goto error;
    }
    if (!fd_set_cloexec(master))
    {
        status = -errno;
        goto error;
    }

    process->in  = xmalloc(sizeof(uv_pipe_t));
    process->out = xmalloc(sizeof(uv_pipe_t));
    uv_pipe_init(process->loop, process->in, 0);
    uv_pipe_init(process->loop, process->out, 0);

    if (!fd_duplicate(master, process->in) || !fd_duplicate(master, process->out))
    {
        status = -errno;
        goto error;
    }

    process->pty        = master;
    process->pid        = pid;
    process->paused     = true;
    process->read_cb    = read_cb;
    process->exit_cb    = exit_cb;
    process->async.data = process;
    uv_async_init(process->loop, &process->async, async_cb);
    uv_thread_create(&process->tid, wait_cb, process);

    return 0;

error:
    close(master);
    uv_kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return status;
}
