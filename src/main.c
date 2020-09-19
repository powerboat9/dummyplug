#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <asm-generic/ioctl.h>
#include <linux/videodev2.h>
#include <linux/version.h>
#include <sys/mman.h>
#include <sys/uio.h>

#define DEBUG 0

#define DEBUG_LOG(msg) do {\
    if (DEBUG) {\
        printf("[DUMMY] " msg "\n");\
    }\
} while (0)

#define ASSERT_ERROR(val, msg) do {\
    if (!(val)) {\
        fputs("[DUMMY ERROR] " msg "\n", stderr);\
        exit(-1);\
    }\
} while (0)

#define TRY_ERROR(func, msg) ASSERT_ERROR((func != -1), msg)

typedef unsigned long long reg_t;

int global_priority = 2;

pid_t child_pid;
int buffer_mem_fd;

struct user_regs_struct proc_regs;

// TRACK VIDEO DEVICE OPENS

#define MAX_VID_OPEN 128

struct vid_fd_entry {
    int fd;
    int priority;
};

int vid_stream_fd = -1;
struct vid_fd_entry vid_fd_list[MAX_VID_OPEN] = {[0 ... (MAX_VID_OPEN - 1)] = {
    .fd = -1,
    .priority = 0
}};

// PTRACE STUFF

void load_regs() {
    TRY_ERROR(ptrace(PTRACE_GETREGS, child_pid, 0, &proc_regs), "failed to load regs");
}

void store_regs() {
    TRY_ERROR(ptrace(PTRACE_SETREGS, child_pid, 0, &proc_regs), "failed to set regs");
}

void wait_for_stop() {
    while (1) {
        int status;
        TRY_ERROR(waitpid(child_pid, &status, 0), "failed to wait on process");
        if (WIFEXITED(status)) {
            fputs("[DUMMY] zoom process exited\n", stdout);
            exit(0);
        }
        if (WIFSTOPPED(status)) break;
    }
}

void bring_to_syscall() {
    while (1) {
        TRY_ERROR(ptrace(PTRACE_SYSCALL, child_pid, 0, 0), "failed to resume child process");
        int status;
        TRY_ERROR(waitpid(child_pid, &status, 0), "failed to wait on process");
        if (WIFEXITED(status)) {
            fputs("[DUMMY] zoom process exited\n", stdout);
            exit(0);
        }
        if (WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80))) break;
    }
}

int load_mem(long *addr, long *out) {
    *out = ptrace(PTRACE_PEEKTEXT, child_pid, addr, 0);
    if (errno != 0) {
        return -1;
    }
    return 0;
}

int load_mem_buffer(void *addr, void *buff, size_t size) {
    long *addr_l = addr;
    long *buff_l = buff;
    size_t size_l = size / sizeof(long);
    for (size_t i = 0; i < size_l; i++) {
        if (load_mem(addr_l + i, buff_l + i) == -1) {
            return -1;
        }
    }
    int extra_size = size % sizeof(long);
    if (extra_size != 0) {
        long *e_addr = addr_l + size_l;
        char *e_buff = (char *) (buff_l + size_l);
        long n;
        if (load_mem(e_addr, &n) == -1) {
            return -1;
        }
        for (int i = 0; i < extra_size; i++) {
            e_buff[i] = ((char *) &n)[i];
        }
    }
    return 0;
}

int store_mem(long *addr, long val) {
    return ptrace(PTRACE_POKETEXT, child_pid, addr, val);
}

int store_mem_buffer(void *addr, const void *buff, size_t size) {
    long *addr_l = addr;
    const long *buff_l = buff;
    size_t size_l = size / sizeof(long);
    for (size_t i = 0; i < size_l; i++) {
        if (store_mem(addr_l + i, buff_l[i]) == -1) {
            return -1;
        }
    }
    int extra_size = size % sizeof(long);
    if (extra_size != 0) {
        long *e_addr = addr_l + size_l;
        char *e_buff = (char *) (buff_l + size_l);
        long n;
        if (load_mem(e_addr, &n) == -1) return -1;
        for (int i = 0; i < extra_size; i++) {
            ((char *) &n)[i] = e_buff[i];
        }
        if (store_mem(e_addr, n) == -1) return -1;
    }
    return 0;
}

int pull_str(long *addr, char *buff, size_t max_len) {
    if (max_len == 0) return -1;
    long out;
    while (1) {
        if (load_mem(addr, &out) == -1) return -1;
        for (int i = 0; i < sizeof(long); i++) {
            char c = ((char *) &out)[i];
            *(buff++) = c;
            if (c == 0) return 0;
            if ((--max_len) == 0) return -1;
        }
        addr += 1;
    }
}

// may add extra null bytes
void insert_str_raw(char *src, char *dst_addr) {
    while (1) {
        long out = 0;
        for (int i = 0; i < sizeof(long); i++) {
            if (src[i] == 0) {
                store_mem((long *) dst_addr, out);
                return;
            }
            ((char *) &out)[i] = src[i];
        }
        store_mem((long *) dst_addr, out);
        src += sizeof(long);
        dst_addr += sizeof(long);
    }
}

char *insert_str(char *src) {
    char *insert_pos = (char *) proc_regs.rsp;
    insert_pos -= 128 + sizeof(long) - 1; // redzone, small buffer for extra nulls
    insert_pos -= strlen(src) + 1;    // string size, null terminated
    insert_str_raw(src, insert_pos);
    return insert_pos;
}

#define VIDEO_WIDTH 1920
#define VIDEO_HEIGHT 1080
#define VIDEO_FMT V4L2_PIX_FMT_RGB24
#define VIDEO_FMT_NAME "24 bit RGB"
#define VIDEO_FMT_PIXEL_SIZE 3

#define VIDEO_BUFF_SIZE (VIDEO_WIDTH * VIDEO_FMT_PIXEL_SIZE * VIDEO_HEIGHT)

#define VIDEO_BUFF_CNT 2

#define VIDEO_BUFF_TOTAL_SIZE (VIDEO_BUFF_SIZE * VIDEO_BUFF_CNT)

void *vid_buffer;

#define MEM_STATE_OPEN 0
#define MEM_STATE_USERPTR 1
#define MEM_STATE_MMAP 2

int mem_state = MEM_STATE_OPEN;

struct v4l2_buffer video_buffers[VIDEO_BUFF_CNT] = {
    {
        .index = 0,
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .bytesused = VIDEO_BUFF_SIZE,
        .flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC,
        .field = V4L2_FIELD_NONE,
        .memory = V4L2_MEMORY_MMAP,
        .m = {
            .offset = 0
        },
        .length = VIDEO_BUFF_SIZE
    },
    {
        .index = 1,
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .bytesused = VIDEO_BUFF_SIZE,
        .flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC,
        .field = V4L2_FIELD_NONE,
        .memory = V4L2_MEMORY_MMAP,
        .m = {
            .offset = VIDEO_BUFF_SIZE
        },
        .length = VIDEO_BUFF_SIZE
    }
};

void start_mmap() {
    mem_state = MEM_STATE_MMAP;
    TRY_ERROR(ftruncate(buffer_mem_fd, VIDEO_BUFF_TOTAL_SIZE), "failed to expand vid buffer");
    vid_buffer = mmap(NULL, VIDEO_BUFF_TOTAL_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, buffer_mem_fd, 0);
    TRY_ERROR((size_t) vid_buffer, "failed to map vid buffer");
}

void end_mmap() {
    mem_state = MEM_STATE_OPEN;
    TRY_ERROR(munmap(vid_buffer, VIDEO_BUFF_TOTAL_SIZE), "failed to unmap vid buffer");
    TRY_ERROR(ftruncate(buffer_mem_fd, 0), "failed to shrink vid buffer");
}

void start_userptr() {
    mem_state = MEM_STATE_USERPTR;
}

void end_userptr() {
    mem_state = MEM_STATE_OPEN;
}

void close_vidbuffs() {
    switch (mem_state) {
        case MEM_STATE_MMAP:
            end_mmap();
            return;
        case MEM_STATE_USERPTR:
            end_userptr();
            return;
    }
}

#define SYSCALL_SYS (proc_regs.orig_rax)
#define SYSCALL_RET (proc_regs.rax)
#define SYSCALL_P1 (proc_regs.rdi)
#define SYSCALL_P2 (proc_regs.rsi)
#define SYSCALL_P3 (proc_regs.rdx)
#define SYSCALL_P4 (proc_regs.r10)
#define SYSCALL_P5 (proc_regs.r8)
#define SYSCALL_P6 (proc_regs.r9)

#define CANCEL_SYS(out) do {\
    SYSCALL_SYS = -1;\
    store_regs();\
    bring_to_syscall();\
    load_regs();\
    SYSCALL_RET = (out);\
    store_regs();\
    return;\
} while (0)

#define LD_STRUCT(s_ptr) do {\
    if (load_mem_buffer(addr, (s_ptr), sizeof(*(s_ptr))) == -1) {\
        printf("MEM FAULT\n");\
        return -EFAULT;\
    }\
} while (0)

#define ST_STRUCT(s_ptr) do {\
    if (store_mem_buffer(addr, (s_ptr), sizeof(*(s_ptr))) == -1) {\
        printf("MEM FAULT\n");\
        return -EFAULT;\
    }\
} while (0)

void print_buffer(void *ptr, size_t len) {
    printf("##:");
    char *ptr_c = ptr;
    for (size_t i = 0; i < len; i++) {
        printf(" %02x", ptr_c[i]);
    }
    printf("\n");
}

int video_ioctl(reg_t cmd, void *addr, struct vid_fd_entry *ent) {
    switch (cmd) {
        case VIDIOC_QUERYCAP:
            DEBUG_LOG("querycap");
            const int dev_caps = V4L2_CAP_VIDEO_CAPTURE |
                                 V4L2_CAP_STREAMING |
                                 V4L2_CAP_EXT_PIX_FORMAT;
            const struct v4l2_capability video_caps = {
                .driver = "dummyplug",
                .card = "Dummy Plug",
                .bus_info = "platform:psyche_chip",
                .version = LINUX_VERSION_CODE,
                .capabilities = dev_caps | V4L2_CAP_DEVICE_CAPS,
                .device_caps = dev_caps
            };
            ST_STRUCT(&video_caps);
            return 0;
        case VIDIOC_ENUM_FMT:;
            DEBUG_LOG("enum_fmt");
            struct v4l2_fmtdesc fmt_desc;
            LD_STRUCT(&fmt_desc);
            if ((fmt_desc.index == 0) && (fmt_desc.type == V4L2_BUF_TYPE_VIDEO_CAPTURE)) {
                memset(&fmt_desc, 0, sizeof(fmt_desc));
                fmt_desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
                fmt_desc.flags = 0;
                strcpy(fmt_desc.description, VIDEO_FMT_NAME);
                fmt_desc.pixelformat = VIDEO_FMT;
                ST_STRUCT(&fmt_desc);
                return 0;
            } else {
                return -EINVAL;
            }
        case VIDIOC_G_FMT:
        case VIDIOC_S_FMT:
        case VIDIOC_TRY_FMT:;
            DEBUG_LOG("g/s/try_fmt");
            const struct v4l2_format video_only_format = {
                .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
                .fmt = {
                    .pix = {
                        .width = VIDEO_WIDTH,
                        .height = VIDEO_HEIGHT,
                        .pixelformat = VIDEO_FMT,
                        .field = V4L2_FIELD_NONE,
                        .bytesperline = VIDEO_WIDTH * VIDEO_FMT_PIXEL_SIZE,
                        .sizeimage = VIDEO_BUFF_SIZE,
                        .colorspace = V4L2_COLORSPACE_SRGB,
                        .priv = V4L2_PIX_FMT_PRIV_MAGIC,
                        .flags = 0
                    }
                }
            };
            struct v4l2_format fmt;
            LD_STRUCT(&fmt);
            if (fmt.type == video_only_format.type) {
                ST_STRUCT(&video_only_format);
                return 0;
            } else {
                return -EINVAL;
            }
        case VIDIOC_G_PARM:;
            DEBUG_LOG("g_param");
            struct v4l2_streamparm parm;
            LD_STRUCT(&parm);
            if (parm.type == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
                memset(&parm, 0, sizeof(parm));
                parm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
                ST_STRUCT(&parm);
                return 0;
            } else {
                return -EINVAL;
            }
        case VIDIOC_REQBUFS:;
            DEBUG_LOG("reqbufs");
            struct v4l2_requestbuffers rbuffs;
            LD_STRUCT(&rbuffs);
            struct v4l2_requestbuffers rbuffsout = {
                .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
                .memory = V4L2_MEMORY_MMAP,
                .capabilities = V4L2_BUF_CAP_SUPPORTS_MMAP,
                .reserved[0] = 0
            };
            if (rbuffs.type == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
                if (rbuffs.memory != V4L2_MEMORY_MMAP) {
                    rbuffsout.count = 0;
                    ST_STRUCT(&rbuffsout);
                    return -EINVAL;
                } else if ((vid_stream_fd != -1) && (vid_stream_fd != ent->fd)) {
                    rbuffsout.count = VIDEO_BUFF_CNT;
                    ST_STRUCT(&rbuffsout);
                    return -EBUSY;
                } else if (rbuffs.count == 0) {
                    vid_stream_fd = -1;
                    global_priority = 2;
                    rbuffsout.count = 0;
                    ST_STRUCT(&rbuffsout);
                    return 0;
                } else {
                    vid_stream_fd = ent->fd;
                    global_priority = 3;
                    rbuffsout.count = VIDEO_BUFF_CNT;
                    ST_STRUCT(&rbuffsout);
                    return 0;
                }
            }
            rbuffsout.count = 0;
            ST_STRUCT(&rbuffsout);
            return -EINVAL;
        case VIDIOC_QUERYBUF:;
            DEBUG_LOG("querybuf");
            struct v4l2_buffer qbuffs;
            LD_STRUCT(&qbuffs);
            if ((qbuffs.index < VIDEO_BUFF_CNT) && (qbuffs.type == V4L2_BUF_TYPE_VIDEO_CAPTURE)) {
                video_buffers[qbuffs.index].flags |= V4L2_BUF_FLAG_MAPPED;
                ST_STRUCT(video_buffers + qbuffs.index);
                return 0;
            } else {
                return -EINVAL;
            }
        case VIDIOC_G_INPUT:;
            DEBUG_LOG("g_input");
            const int input_g = 0;
            ST_STRUCT(&input_g);
            return 0;
        case VIDIOC_S_INPUT:;
            DEBUG_LOG("s_input");
            int input_s;
            LD_STRUCT(&input_s);
            return (input_s == 0) ? 0 : (-EINVAL);
        case VIDIOC_ENUMINPUT:;
            DEBUG_LOG("enuminput");
            struct v4l2_input enum_input_data;
            LD_STRUCT(&enum_input_data);
            if (enum_input_data.index == 0) {
                struct v4l2_input ret = {
                    .index = 0,
                    .name = "Single Input",
                    .type = V4L2_INPUT_TYPE_CAMERA,
                    .audioset = 0,
                    .std = 0,
                    .status = 0,
                    .capabilities = 0
                };
                ST_STRUCT(&ret);
                return 0;
            } else {
                return -EINVAL;
            }
        case VIDIOC_G_PRIORITY:;
            DEBUG_LOG("g_priority");
            ST_STRUCT(&global_priority);
            return 0;
        case VIDIOC_S_PRIORITY:;
            DEBUG_LOG("s_priority");
            int s_pri;
            LD_STRUCT(&s_pri);
            switch (s_pri) {
                case 1:
                    if (vid_stream_fd == ent->fd) {
                        vid_stream_fd = -1;
                    }
                    global_priority = 1;
                    return 0;
                case 2:
                    if (global_priority == 3) {
                        if (vid_stream_fd == ent->fd) {
                            vid_stream_fd = -1;
                            global_priority = 2;
                            return 0;
                        } else {
                            return -EINVAL;
                        }
                    } else {
                        global_priority = 2;
                        return 0;
                    }
                case 3:
                    if ((vid_stream_fd != -1) && (vid_stream_fd != ent->fd)) {
                        return -EBUSY;
                    } else {
                        global_priority = 3;
                        vid_stream_fd = ent->fd;
                        return 0;
                    }
                default:
                    return -EINVAL;
            }
        default:
            if (DEBUG) {
                fprintf(stderr, "[DUMMY WARN] ioctl unimplemented:\n");
                fprintf(stderr, "             DIR: %u\n", (unsigned int) _IOC_DIR(cmd));
                fprintf(stderr, "             TYPE: %c\n", (char) _IOC_TYPE(cmd));
                fprintf(stderr, "             ID: %u\n", (unsigned int) _IOC_NR(cmd));
                //TRY_ERROR(-1, "shut it down");
            }
            return -ENOTTY;
    }
}

void tick_syscall() {
    bring_to_syscall();
    load_regs();
    switch (SYSCALL_SYS) {
        case SYS_read:
            if (SYSCALL_P1 != -1) {
                for (int i = 0; i < MAX_VID_OPEN; i++) {
                    ASSERT_ERROR(vid_fd_list[i].fd != SYSCALL_P1, "vid read not implemented");
                }
            }
            bring_to_syscall();
            return;
        case SYS_write:
            if (SYSCALL_P1 != -1) {
                for (int i = 0; i < MAX_VID_OPEN; i++) {
                    ASSERT_ERROR(vid_fd_list[i].fd != SYSCALL_P1, "vid write not implemented");
                }
            }
            bring_to_syscall();
            return;
        case SYS_close:
            if (SYSCALL_P1 != -1) {
                for (int i = 0; i < MAX_VID_OPEN; i++) {
                    if (vid_fd_list[i].fd == SYSCALL_P1) {
                        vid_fd_list[i].fd = -1;
                        if (vid_stream_fd == SYSCALL_P1) {
                            vid_stream_fd = -1;
                        }
                    }
                }
            }
            bring_to_syscall();
            return;
        case SYS_openat:;
            // redirect attempts to access /dev/videoX and /dev/videoXX
            char name_buff[13];
            if (pull_str((long *) SYSCALL_P2, name_buff, sizeof(name_buff)) == -1) {
                bring_to_syscall();
                return;
            }
            for (int i = 0; i < 10; i++) if (("/dev/video")[i] != name_buff[i]) {
                bring_to_syscall();
                return;
            }
            if ((name_buff[10] == '0') && (name_buff[11] == 0)) {
                for (int i = 0; i < MAX_VID_OPEN; i++) {
                    if (vid_fd_list[i].fd == -1) {
                        reg_t old_filename = SYSCALL_P2;
                        SYSCALL_P2 = (reg_t) insert_str("/dev/null");
                        store_regs();
                        bring_to_syscall();
                        load_regs();
                        SYSCALL_P2 = old_filename;
                        store_regs();
                        vid_fd_list[i].fd = SYSCALL_RET;
                        vid_fd_list[i].priority = 2;
                        return;
                    }
                }
                CANCEL_SYS(-EBUSY);
            } else {
                CANCEL_SYS(-ENOENT);
            }
        case SYS_ioctl:
            if (SYSCALL_P1 != -1) {
                for (int i = 0; i < MAX_VID_OPEN; i++) {
                    if (vid_fd_list[i].fd == SYSCALL_P1) {
                        CANCEL_SYS(video_ioctl(SYSCALL_P2, (void *) SYSCALL_P3, &vid_fd_list[i]));
                    }
                }
            }
            bring_to_syscall();
            return;
        case SYS_mmap:
            if ((vid_stream_fd != -1) && (SYSCALL_P5 == vid_stream_fd)) {
                DEBUG_LOG("mmap");
                int mmap_old_fd = SYSCALL_P5;
                SYSCALL_P5 = buffer_mem_fd;
                store_regs();
                bring_to_syscall();
                load_regs();
                SYSCALL_P5 = mmap_old_fd;
                store_regs();
                return;
            } else {
                bring_to_syscall();
                return;
            }
        default:
            bring_to_syscall();
            return;
    }
}

void parent_process() {
    // start ptracing child
    wait_for_stop();
    TRY_ERROR(ptrace(
                         PTRACE_SETOPTIONS,
                         child_pid,
                         0,
                         PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD
                    ),
                    "failed to set ptrace options");
    // main loop
    while (1) {
        tick_syscall();
    }
}

void child_process() {
    TRY_ERROR(ptrace(PTRACE_TRACEME, 0, 0, 0), "failed to accept ptrace");
    kill(getpid(), SIGSTOP); // cannot fail
    //TRY_ERROR(execlp("zoom", "zoom", NULL), "failed to start program");
    TRY_ERROR(execlp("v4l2-compliance", "v4l2-compliance", NULL), "failed to start program");
    //TRY_ERROR(execlp("v4l2-ctl", "v4l2-ctl", "--all", NULL), "failed to start program");
}

int main(int argc, char **argv) {
    TRY_ERROR((buffer_mem_fd = syscall(SYS_memfd_create, "vid_mem", 0)), "failed to create video buffer fd");
    child_pid = fork();
    switch (child_pid) {
        case -1: TRY_ERROR(-1, "failed to fork"); break;
        case 0: child_process(); break;
        default: parent_process();
    }
}
