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

#define Kill(syscall) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##syscall, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO)

struct sock_filter filter[] = {
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ArchField),
    BPF_JUMP( BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

Kill(pipe),
	Kill(mremap),
	Kill(mincore),
	Kill(shmctl),
	Kill(pause),
	Kill(nanosleep),
	Kill(getitimer),
	Kill(alarm),
	Kill(fork),
	Kill(semget),
	Kill(semop),
	Kill(semctl),
	Kill(msgget),
	Kill(msgsnd),
	Kill(msgrcv),
	Kill(msgctl),
	Kill(flock),
	Kill(getdents),
	Kill(fchdir),
	Kill(getrlimit),
	Kill(times),
	Kill(ptrace),
	Kill(syslog),
	Kill(setpgid),
	Kill(getpgrp),
	Kill(setreuid),
	Kill(setregid),
	Kill(getresuid),
	Kill(getresgid),
	Kill(getpgid),
	Kill(setfsuid),
	Kill(setfsgid),
	Kill(getsid),
	Kill(capget),
	Kill(capset),
	Kill(rt_sigpending),
	Kill(rt_sigtimedwait),
	Kill(rt_sigqueueinfo),
	Kill(rt_sigsuspend),
	Kill(sigaltstack),
	Kill(utime),
	Kill(mknod),
	Kill(personality),
	Kill(ustat),
	Kill(sysfs),
	Kill(sched_setparam),
	Kill(sched_rr_get_interval),
	Kill(munlock),
	Kill(mlockall),
	Kill(munlockall),
	Kill(vhangup),
	Kill(modify_ldt),
	Kill(pivot_root),
	Kill(adjtimex),
	Kill(setrlimit),
	Kill(chroot),
	Kill(sync),
	Kill(acct),
	Kill(settimeofday),
	Kill(mount),
	Kill(swapon),
	Kill(swapoff),
	Kill(reboot),
	Kill(sethostname),
	Kill(setdomainname),
	Kill(iopl),
	Kill(ioperm),
	Kill(init_module),
	Kill(delete_module),
	Kill(quotactl),
	Kill(readahead),
	Kill(setxattr),
	Kill(lsetxattr),
	Kill(fsetxattr),
	Kill(getxattr),
	Kill(lgetxattr),
	Kill(fgetxattr),
	Kill(listxattr),
	Kill(llistxattr),
	Kill(flistxattr),
	Kill(removexattr),
	Kill(lremovexattr),
	Kill(fremovexattr),
	Kill(tkill),
	Kill(set_thread_area),
	Kill(io_setup),
	Kill(io_destroy),
	Kill(io_getevents),
	Kill(io_submit),
	Kill(io_cancel),
	Kill(get_thread_area),
	Kill(lookup_dcookie),
	Kill(remap_file_pages),
	Kill(restart_syscall),
	Kill(semtimedop),
	Kill(timer_create),
	Kill(timer_settime),
	Kill(timer_gettime),
	Kill(timer_getoverrun),
	Kill(timer_delete),
	Kill(clock_settime),
	Kill(utimes),
	Kill(mbind),
	Kill(set_mempolicy),
	Kill(get_mempolicy),
	Kill(mq_open),
	Kill(mq_unlink),
	Kill(mq_timedsend),
	Kill(mq_timedreceive),
	Kill(mq_notify),
	Kill(mq_getsetattr),
	Kill(kexec_load),
	Kill(waitid),
	Kill(add_key),
	Kill(request_key),
	Kill(keyctl),
	Kill(ioprio_set),
	Kill(ioprio_get),
	Kill(migrate_pages),
	Kill(mkdirat),
	Kill(mknodat),
	Kill(fchownat),
	Kill(futimesat),
	Kill(unlinkat),
	Kill(renameat),
	Kill(linkat),
	Kill(symlinkat),
	Kill(readlinkat),
	Kill(faccessat),
	Kill(pselect6),
	Kill(ppoll),
	Kill(unshare),
	Kill(get_robust_list),
	Kill(splice),
	Kill(tee),
	Kill(sync_file_range),
	Kill(vmsplice),
	Kill(move_pages),
	Kill(signalfd),
	Kill(timerfd_create),
	Kill(fallocate),
	Kill(timerfd_settime),
	Kill(timerfd_gettime),
	Kill(signalfd4),
	Kill(rt_tgsigqueueinfo),
	Kill(perf_event_open),
	Kill(fanotify_init),
	Kill(fanotify_mark),
	Kill(name_to_handle_at),
	Kill(open_by_handle_at),
	Kill(clock_adjtime),
	Kill(syncfs),
	Kill(setns),
	Kill(getcpu),
	Kill(process_vm_readv),
	Kill(process_vm_writev),
	Kill(kcmp),
	Kill(finit_module),
	Kill(sched_setattr),
	Kill(sched_getattr),
	Kill(renameat2),
	Kill(seccomp),
	Kill(kexec_file_load),
	Kill(bpf),
	Kill(execveat),
	Kill(userfaultfd),
	Kill(membarrier),
	Kill(preadv2),
	Kill(pwritev2),
	Kill(pkey_mprotect),
	Kill(io_pgetevents),
	Kill(rseq),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
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


}
