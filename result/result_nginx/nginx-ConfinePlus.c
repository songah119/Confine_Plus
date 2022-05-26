#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#define ArchField offsetof(struct seccomp_data, arch)

#define Allow(syscall) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##syscall, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)


#define AllowWithArg(syscall,indx,value)\
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[indx]))),\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, 0, 1),\
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),\
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr)))	 
		 
#define Kill(syscall) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##syscall, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

struct sock_filter filter[] = {
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ArchField),
    BPF_JUMP( BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

   BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
   Allow(accept4),
	Allow(accept),
	Allow(access),
	Allow(arch_prctl),
	Allow(bind),
	Allow(brk),
	Allow(capset),
	Allow(chdir),
	Allow(chmod),
	AllowWithArg(chown,2,4294967295),
	Allow(clock_gettime),
	Allow(clock_nanosleep),
	Allow(clone3),
	AllowWithArg(clone,0,18874385),
	AllowWithArg(clone,0,4001536),
	Allow(close),
	Allow(connect),
	Allow(creat),
	Allow(dup2),
	Allow(dup),
	Allow(epoll_create),
	AllowWithArg(epoll_ctl,1,1),
	AllowWithArg(epoll_ctl,1,3),
	AllowWithArg(epoll_ctl,1,2),
	Allow(epoll_wait),
	Allow(eventfd2),
	Allow(execve),
	Allow(exit),
	Allow(exit_group),
	Allow(fadvise64),
	Allow(fcntl),
	Allow(fsconfig),
	Allow(fsmount),
	Allow(fsopen),
	Allow(fspick),
	Allow(fstat),
	Allow(ftruncate),
	Allow(futex),
	Allow(getcwd),
	Allow(getdents64),
	Allow(geteuid),
	Allow(getpid),
	Allow(getppid),
	Allow(getrandom),
	Allow(getsockname),
	AllowWithArg(getsockopt,1,1),
	AllowWithArg(getsockopt,1,1),
	AllowWithArg(getsockopt,1,0),
	AllowWithArg(getsockopt,1,41),
	AllowWithArg(getsockopt,1,6),
	AllowWithArg(getsockopt,2,4),
	AllowWithArg(getsockopt,2,3),
	AllowWithArg(getsockopt,2,21),
	AllowWithArg(getsockopt,2,20),
	AllowWithArg(getsockopt,2,14),
	AllowWithArg(getsockopt,2,24),
	AllowWithArg(getsockopt,2,3),
	AllowWithArg(getsockopt,2,8),
	AllowWithArg(getsockopt,2,7),
	AllowWithArg(getsockopt,2,15),
	AllowWithArg(getsockopt,2,23),
	AllowWithArg(getsockopt,2,9),
	AllowWithArg(getsockopt,2,4),
	AllowWithArg(getsockopt,2,11),
	Allow(gettid),
	Allow(gettimeofday),
	Allow(getuid),
	AllowWithArg(ioctl,1,35123),
	AllowWithArg(ioctl,1,35088),
	AllowWithArg(ioctl,1,21507),
	AllowWithArg(ioctl,1,21505),
	AllowWithArg(ioctl,1,21537),
	AllowWithArg(ioctl,1,21513),
	AllowWithArg(ioctl,1,21531),
	AllowWithArg(ioctl,1,21586),
	Allow(io_destroy),
	Allow(io_getevents),
	Allow(io_setup),
	Allow(io_uring_enter),
	Allow(io_uring_register),
	Allow(io_uring_setup),
	Allow(kill),
	Allow(listen),
	Allow(lseek),
	Allow(lstat),
	Allow(madvise),
	Allow(memfd_create),
	Allow(mkdir),
	Allow(mmap),
	Allow(move_mount),
	Allow(mprotect),
	Allow(munmap),
	Allow(newfstatat),
	Allow(openat),
	Allow(open),
	Allow(open_tree),
	Allow(pidfd_open),
	Allow(pidfd_send_signal),
	Allow(pkey_alloc),
	Allow(pkey_free),
	Allow(poll),
	Allow(prctl),
	Allow(pread64),
	Allow(prlimit64),
	Allow(pwrite64),
	Allow(pwritev),
	Allow(readlink),
	Allow(read),
	Allow(readv),
	Allow(recvfrom),
	Allow(recvmsg),
	Allow(rename),
	Allow(rmdir),
	Allow(rt_sigaction),
	Allow(rt_sigprocmask),
	Allow(rt_sigreturn),
	Allow(rt_sigsuspend),
	Allow(sched_getparam),
	Allow(sched_get_priority_max),
	Allow(sched_get_priority_min),
	Allow(sched_getscheduler),
	Allow(sched_setaffinity),
	Allow(sched_setscheduler),
	Allow(sched_yield),
	Allow(select),
	Allow(sendfile),
	Allow(sendmsg),
	Allow(sendto),
	Allow(setgid),
	Allow(setgroups),
	Allow(setitimer),
	AllowWithArg(setpriority,0,0),
	AllowWithArg(setpriority,1,0),
	Allow(set_robust_list),
	Allow(setsid),
	AllowWithArg(setsockopt,1,0),
	AllowWithArg(setsockopt,1,6),
	AllowWithArg(setsockopt,1,1),
	AllowWithArg(setsockopt,1,6),
	AllowWithArg(setsockopt,1,41),
	AllowWithArg(setsockopt,1,1),
	AllowWithArg(setsockopt,2,11),
	AllowWithArg(setsockopt,2,1),
	AllowWithArg(setsockopt,2,9),
	AllowWithArg(setsockopt,2,1),
	AllowWithArg(setsockopt,2,2),
	AllowWithArg(setsockopt,2,26),
	AllowWithArg(setsockopt,2,21),
	AllowWithArg(setsockopt,2,20),
	AllowWithArg(setsockopt,2,10),
	AllowWithArg(setsockopt,2,62),
	AllowWithArg(setsockopt,2,23),
	AllowWithArg(setsockopt,2,15),
	AllowWithArg(setsockopt,2,2),
	AllowWithArg(setsockopt,2,8),
	AllowWithArg(setsockopt,2,7),
	AllowWithArg(setsockopt,2,9),
	AllowWithArg(setsockopt,2,4),
	AllowWithArg(setsockopt,2,5),
	AllowWithArg(setsockopt,2,6),
	AllowWithArg(setsockopt,2,49),
	AllowWithArg(setsockopt,2,19),
	AllowWithArg(setsockopt,2,75),
	AllowWithArg(setsockopt,2,24),
	AllowWithArg(setsockopt,2,3),
	AllowWithArg(setsockopt,2,13),
	Allow(set_tid_address),
	Allow(setuid),
	AllowWithArg(shmat,2,4096),
	Allow(shmdt),
	AllowWithArg(shmget,2,0),
	AllowWithArg(shmget,2,804),
	AllowWithArg(shutdown,1,2),
	AllowWithArg(shutdown,1,1),
	AllowWithArg(socketpair,0,1),
	AllowWithArg(socketpair,1,1),
	AllowWithArg(socketpair,2,0),
	Allow(socket),
	Allow(statfs),
	Allow(stat),
	Allow(sysinfo),
	Allow(tgkill),
	Allow(time),
	AllowWithArg(umask,0,0),
	Allow(uname),
	Allow(unlink),
	Allow(uselib),
	Allow(utimes),
	Allow(vfork),
	Allow(wait4),
	Allow(writev),
	Allow(write),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
};
struct sock_fprog filterprog = {
    .len = sizeof(filter)/sizeof(filter[0]),
    .filter = filter
};

int main(int argc, char **argv) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("Could not start seccomp:");
        exit(1);
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filterprog) == -1) {
        perror("Could not start seccomp:");
        exit(1);
    }

//    char *args[] = {
    char *args[argc+1];
    for ( int i = 1; i < argc; i++ ){
        args[i] = argv[i];
    }
    args[argc] = NULL;

args[0] = "nginx.bak";
	execv("/usr/sbin/nginx.bak", args);
}
