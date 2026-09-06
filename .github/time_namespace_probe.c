#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

struct child_report {
    struct timespec monotonic;
    struct timespec boottime;
    int timens_rewrite_errno;
};

static void die(const char *what) {
    fprintf(stderr, "%s: %s\n", what, strerror(errno));
    exit(1);
}

static void write_exact_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) die(path);
    size_t len = strlen(text);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, text + off, len - off);
        if (n < 0) {
            int saved = errno;
            close(fd);
            errno = saved;
            die(path);
        }
        off += (size_t)n;
    }
    if (close(fd) < 0) die("close mapping/offset file");
}

static ssize_t readlink_checked(const char *path, char *buf, size_t cap) {
    ssize_t n = readlink(path, buf, cap - 1);
    if (n < 0) die(path);
    buf[n] = '\0';
    return n;
}

static int64_t ns_value(struct timespec ts) {
    return (int64_t)ts.tv_sec * INT64_C(1000000000) + ts.tv_nsec;
}

static int64_t abs64(int64_t value) {
    return value < 0 ? -value : value;
}

static void write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            _exit(90);
        }
        off += (size_t)n;
    }
}

static void read_all(int fd, void *buf, size_t len) {
    char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            die("read child report");
        }
        if (n == 0) {
            fprintf(stderr, "child report reached EOF early\n");
            exit(1);
        }
        off += (size_t)n;
    }
}

int main(void) {
    const int64_t mono_offset_ns = INT64_C(3600) * 1000000000;
    const int64_t boot_offset_ns = INT64_C(7200) * 1000000000;
    const int64_t tolerance_ns = INT64_C(2) * 1000000000;
    uid_t outer_uid = geteuid();
    gid_t outer_gid = getegid();
    struct timespec outer_mono_before, outer_boot_before;
    if (clock_gettime(CLOCK_MONOTONIC, &outer_mono_before) < 0) die("clock_gettime monotonic before");
    if (clock_gettime(CLOCK_BOOTTIME, &outer_boot_before) < 0) die("clock_gettime boottime before");

    if (unshare(CLONE_NEWUSER | CLONE_NEWTIME) < 0) die("unshare user+time namespace");

    write_exact_file("/proc/self/setgroups", "deny\n");
    char map[128];
    snprintf(map, sizeof(map), "0 %u 1\n", (unsigned)outer_uid);
    write_exact_file("/proc/self/uid_map", map);
    snprintf(map, sizeof(map), "0 %u 1\n", (unsigned)outer_gid);
    write_exact_file("/proc/self/gid_map", map);

    char self_time[128], child_time[128];
    readlink_checked("/proc/self/ns/time", self_time, sizeof(self_time));
    readlink_checked("/proc/self/ns/time_for_children", child_time, sizeof(child_time));
    if (strcmp(self_time, child_time) == 0) {
        fprintf(stderr, "time namespace for children did not diverge from bootstrap namespace: %s\n", self_time);
        return 1;
    }

    write_exact_file("/proc/self/timens_offsets", "monotonic 3600 0\n");
    write_exact_file("/proc/self/timens_offsets", "boottime 7200 0\n");

    struct timespec parent_mono_before_fork, parent_boot_before_fork;
    if (clock_gettime(CLOCK_MONOTONIC, &parent_mono_before_fork) < 0) die("parent monotonic before fork");
    if (clock_gettime(CLOCK_BOOTTIME, &parent_boot_before_fork) < 0) die("parent boottime before fork");
    if (ns_value(parent_mono_before_fork) - ns_value(outer_mono_before) > INT64_C(60) * 1000000000 ||
        ns_value(parent_boot_before_fork) - ns_value(outer_boot_before) > INT64_C(60) * 1000000000) {
        fprintf(stderr, "bootstrap clock unexpectedly inherited child time offset\n");
        return 1;
    }

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0) die("pipe2");
    pid_t child = fork();
    if (child < 0) die("fork");
    if (child == 0) {
        close(pipefd[0]);
        struct child_report report;
        memset(&report, 0, sizeof(report));
        if (clock_gettime(CLOCK_MONOTONIC, &report.monotonic) < 0) _exit(91);
        if (clock_gettime(CLOCK_BOOTTIME, &report.boottime) < 0) _exit(92);

        int fd = open("/proc/self/timens_offsets", O_WRONLY | O_CLOEXEC);
        if (fd < 0) _exit(93);
        errno = 0;
        ssize_t n = write(fd, "monotonic 3601 0\n", strlen("monotonic 3601 0\n"));
        report.timens_rewrite_errno = n < 0 ? errno : 0;
        close(fd);
        write_all(pipefd[1], &report, sizeof(report));
        _exit(0);
    }

    close(pipefd[1]);
    struct child_report report;
    read_all(pipefd[0], &report, sizeof(report));
    close(pipefd[0]);

    int status = 0;
    if (waitpid(child, &status, 0) != child) die("waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "time namespace child failed: status=%d\n", status);
        return 1;
    }

    struct timespec parent_mono_after, parent_boot_after;
    if (clock_gettime(CLOCK_MONOTONIC, &parent_mono_after) < 0) die("parent monotonic after child");
    if (clock_gettime(CLOCK_BOOTTIME, &parent_boot_after) < 0) die("parent boottime after child");

    int64_t mono_delta = ns_value(report.monotonic) - ns_value(parent_mono_after);
    int64_t boot_delta = ns_value(report.boottime) - ns_value(parent_boot_after);
    if (abs64(mono_delta - mono_offset_ns) > tolerance_ns) {
        fprintf(stderr, "child monotonic offset mismatch: got %.3f seconds\n", (double)mono_delta / 1e9);
        return 1;
    }
    if (abs64(boot_delta - boot_offset_ns) > tolerance_ns) {
        fprintf(stderr, "child boottime offset mismatch: got %.3f seconds\n", (double)boot_delta / 1e9);
        return 1;
    }
    if (report.timens_rewrite_errno != EACCES) {
        fprintf(stderr, "timens_offsets was not locked after first child: errno=%d (%s)\n",
                report.timens_rewrite_errno, strerror(report.timens_rewrite_errno));
        return 1;
    }

    printf("PASS bootstrap_time=%s child_time=%s monotonic_delta=%.3f boottime_delta=%.3f rewrite_errno=EACCES\n",
           self_time, child_time, (double)mono_delta / 1e9, (double)boot_delta / 1e9);
    return 0;
}
