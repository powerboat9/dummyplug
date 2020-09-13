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

#define TRY_ERROR(func, msg) do {\
    if ((func) == -1) {\
        fputs("[DUMMY ERROR] " msg "\n", stderr);\
        exit(-1);\
    }\
} while (0)

#define IS_SYS_INT (WIFSTOPPED(last_status) && (WSTOPSIG(last_status) == (SIGTRAP | 0x80)))
#define HANDLE_EXIT do {\
    if (WIFEXITED(last_status)) {\
        fputs("[DUMMY] zoom process exited\n", stdout);\
        exit(0);\
    }\
} while (0)

int child_pid;
int last_status;
struct user_regs_struct last_regs;
int special_vid_fd = -1;

void wait_for_stop() {
    TRY_ERROR(waitpid(child_pid, &last_status, 0), "failed to wait on process");
}

void bring_to_syscall() {
    while (1) {
        TRY_ERROR(ptrace(PTRACE_SYSCALL, child_pid, 0, 0), "failed to resume child process");
        wait_for_stop();
        HANDLE_EXIT;
        if (IS_SYS_INT) break;
    }
}

long load_mem(long *addr) {
    long ret = ptrace(PTRACE_PEEKTEXT, child_pid, addr, 0);
    if (errno != 0) {
        TRY_ERROR(-1, "failed to load process data");
    }
    return ret;
}

void load_mem_buffer(void *addr, void *buff, size_t size) {
    long *addr_l = addr;
    long *buff_l = buff;
    size_t size_l = size / sizeof(long);
    for (size_t i = 0; i < size_l; i++) {
        buff_l[i] = load_mem(addr_l + i);
    }
    int extra_size = size % sizeof(long);
    if (extra_size != 0) {
        long *e_addr = addr_l + size_l;
        char *e_buff = (char *) (buff_l + size_l);
        long n = load_mem(e_addr);
        for (int i = 0; i < extra_size; i++) {
            e_buff[i] = ((char *) &n)[i];
        }
    }
}

void store_mem(long *addr, long val) {
    TRY_ERROR(ptrace(PTRACE_POKETEXT, child_pid, addr, val), "failed to store process data");
}

void store_mem_buffer(void *addr, const void *buff, size_t size) {
    long *addr_l = addr;
    const long *buff_l = buff;
    size_t size_l = size / sizeof(long);
    for (size_t i = 0; i < size_l; i++) {
        store_mem(addr_l + i, buff_l[i]);
    }
    int extra_size = size % sizeof(long);
    if (extra_size != 0) {
        long *e_addr = addr_l + size_l;
        char *e_buff = (char *) (buff_l + size_l);
        long n = load_mem(e_addr);
        for (int i = 0; i < extra_size; i++) {
            ((char *) &n)[i] = e_buff[i];
        }
        store_mem(e_addr, n);
    }
}

int pull_str(long *addr, char *buff, size_t max_len) {
    if (max_len == 0) return -1;
    long out;
    while (1) {
        out = load_mem(addr);
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
    char *insert_pos = (char *) last_regs.rsp;
    insert_pos -= 128 + sizeof(long) - 1; // redzone, small buffer for extra nulls
    insert_pos -= strlen(src) + 1;    // string size, null terminated
    insert_str_raw(src, insert_pos);
    return insert_pos;
}

void load_regs() {
    TRY_ERROR(ptrace(PTRACE_GETREGS, child_pid, 0, &last_regs), "failed to load regs");
}

void store_regs() {
    TRY_ERROR(ptrace(PTRACE_SETREGS, child_pid, 0, &last_regs), "failed to set regs");
}

#define RESULT_PASS 0
#define RESULT_VID 1
#define RESULT_BLOCK 2

int check_file_request() {
    char name_buff[13];
    if (pull_str((long *) last_regs.rsi, name_buff, 13) == -1) return RESULT_PASS;
    for (int i = 0; i < 10; i++) {
        if (("/dev/video")[i] != name_buff[i]) return RESULT_PASS;
    }
    if ((name_buff[10] == '0') && (name_buff[11] == 0)) return RESULT_VID;
    return RESULT_BLOCK;
}

void replace_syscall(unsigned long long ret) {
    last_regs.orig_rax = -1;
    store_regs();
    bring_to_syscall();
    last_regs.rax = ret;
    store_regs();
}

#define VIDEO_WIDTH 1920
#define VIDEO_HEIGHT 1080
#define VIDEO_FMT V4L2_PIX_FMT_RGB24
#define VIDEO_FMT_NAME "24 bit RGB"
#define VIDEO_FMT_PIXEL_SIZE 3

#define VIDEO_BUFF_SIZE (VIDEO_WIDTH * VIDEO_FMT_PIXEL_SIZE * VIDEO_HEIGHT)

struct v4l2_capability video_caps = {
    .driver = "dummyplug",
    .card = "Dummy Plug",
    .bus_info = "platform:psyche_chip",
    .version = LINUX_VERSION_CODE,
    .capabilities = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING | V4L2_CAP_EXT_PIX_FORMAT | V4L2_CAP_DEVICE_CAPS,
    .device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING | V4L2_CAP_EXT_PIX_FORMAT
};

const struct v4l2_format video_only_format = {
    .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
    .fmt = {
        .pix = {
            .width = VIDEO_WIDTH,
            .height = VIDEO_HEIGHT,
            .pixelformat = VIDEO_FMT,
            .field = V4L2_FIELD_NONE,
            .bytesperline = VIDEO_WIDTH * VIDEO_FMT_PIXEL_SIZE,
            .sizeimage = VIDEO_WIDTH * VIDEO_FMT_PIXEL_SIZE * VIDEO_HEIGHT,
            .colorspace = V4L2_COLORSPACE_SRGB,
            .priv = V4L2_PIX_FMT_PRIV_MAGIC,
            .flags = 0
        }
    }
};

#define VIDEO_BUFFER_CNT 2

struct v4l2_buffer video_buffers[VIDEO_BUFFER_CNT] = {
    {
        .index = 0,
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .bytesused = video_only_format.fmt.pix.sizeimage,
        .flags = V4L2_BUF_FLAG_PREPARED,
        .field = V4L2_FIELD_NONE,
        .memory = V4L2_MEMORY_MMAP,
        .m = {
            .offset = 0
        },
        .length = video_only_format.fmt.pix.sizeimage
    },
    {
        .index = 1,
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .bytesused = video_only_format.fmt.pix.sizeimage,
        .flags = V4L2_BUF_FLAG_PREPARED,
        .field = V4L2_FIELD_NONE,
        .memory = V4L2_MEMORY_MMAP,
        .m = {
            .offset = 1
        },
        .length = video_only_format.fmt.pix.sizeimage
    }
};

void *actual_video_buffers[VIDEO_BUFFER_CNT];

#define DEBUG 0

#define DEBUG_LOG(msg) do {\
    if (DEBUG) {\
        printf("[DUMMY] " msg "\n");\
    }\
} while (0)

int loop_syscalls() {
    bring_to_syscall();
    load_regs();
    switch (last_regs.orig_rax) {
        case SYS_openat:
            switch (check_file_request()) {
                case RESULT_VID:
                    if (special_vid_fd != -1) {
                        replace_syscall(-EBUSY);
                    } else {
                        unsigned long long old_rsi = last_regs.rsi;
                        last_regs.rsi = (unsigned long long) insert_str("/dev/null");
                        store_regs();
                        bring_to_syscall();
                        load_regs();
                        special_vid_fd = (int) last_regs.rax;
                        last_regs.rsi = old_rsi;
                        store_regs();
                    }
                    break;
                case RESULT_BLOCK:
                    replace_syscall(-ENOENT);
                    break;
                default:
                    TRY_ERROR(-1, "check file request fail");
                    break;
                case RESULT_PASS:
                    bring_to_syscall();
            }
            break;
        case SYS_close:
            if (last_regs.rdi == special_vid_fd) {
                special_vid_fd = -1;
            }
            bring_to_syscall();
            break;
        case SYS_ioctl:;
            unsigned int cmd = (unsigned int) last_regs.rsi;
            void *ioctl_arg = (void *) last_regs.rdx;
            if (last_regs.rdi == special_vid_fd) {
                switch (cmd) {
                    case VIDIOC_QUERYCAP:
                        DEBUG_LOG("querycap");
                        store_mem_buffer(ioctl_arg, &video_caps, sizeof(video_caps));
                        replace_syscall(0);
                        break;
                    case VIDIOC_ENUM_FMT:;
                        DEBUG_LOG("enum_fmt");
                        struct v4l2_fmtdesc fmt_desc;
                        load_mem_buffer(ioctl_arg, &fmt_desc, sizeof(fmt_desc));
                        if ((fmt_desc.index == 0) && (fmt_desc.type == V4L2_BUF_TYPE_VIDEO_CAPTURE)) {
                            memset(&fmt_desc, 0, sizeof(fmt_desc));
                            fmt_desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
                            fmt_desc.flags = 0;
                            strcpy(fmt_desc.description, VIDEO_FMT_NAME);
                            fmt_desc.pixelformat = VIDEO_FMT;
                            store_mem_buffer(ioctl_arg, &fmt_desc, sizeof(fmt_desc));
                            replace_syscall(0);
                        } else {
                            replace_syscall(-EINVAL);
                        }
                        break;
                    case VIDIOC_G_FMT:
                    case VIDIOC_S_FMT:
                    case VIDIOC_TRY_FMT:;
                        DEBUG_LOG("g/s/try_fmt");
                        struct v4l2_format fmt;
                        load_mem_buffer(ioctl_arg, &fmt, sizeof(fmt));
                        if (fmt.type == video_only_format.type) {
                            store_mem_buffer(ioctl_arg, &video_only_format, sizeof(video_only_format));
                            replace_syscall(0);
                        } else {
                            replace_syscall(-EINVAL);
                        }
                        break;
                    case VIDIOC_G_PARM:;
                        DEBUG_LOG("g_param");
                        struct v4l2_streamparm parm;
                        load_mem_buffer(ioctl_arg, &parm, sizeof(parm));
                        if (parm.type == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
                            memset(&parm, 0, sizeof(parm));
                            parm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
                            store_mem_buffer(ioctl_arg, &parm, sizeof(parm));
                            replace_syscall(0);
                        } else {
                            replace_syscall(-EINVAL);
                        }
                        break;
                    case VIDIOC_REQBUFS:;
                        DEBUG_LOG("reqbufs");
                        struct v4l2_requestbuffers rbuffs;
                        load_mem_buffer(ioctl_arg, &rbuffs, sizeof(rbuffs));
                        if ((rbuffs.type == V4L2_BUF_TYPE_VIDEO_CAPTURE) && (rbuffs.memory == V4L2_MEMORY_MMAP)) {
                            rbuffs.count = VIDEO_BUFFER_CNT;
                            rbuffs.reserved[0] = 0;
                            rbuffs.reserved[1] = 0;
                            store_mem_buffer(ioctl_arg, &rbuffs, sizeof(rbuffs));
                            replace_syscall(0);
                        } else {
                            fprintf(stderr, "[DUMMY WARN] reqbufs fail, requesting (mem = %d)\n", rbuffs.memory);
                            replace_syscall(-EINVAL);
                        }
                        break;
                    case VIDIOC_QUERYBUF:;
                        DEBUG_LOG("querybuf");
                        struct v4l2_buffer qbuffs;
                        load_mem_buffer(ioctl_arg, &qbuffs, sizeof(qbuffs));
                        if ((qbuffs.index < VIDEO_BUFFER_CNT) && (qbuffs.type == V4L2_BUF_TYPE_VIDEO_CAPTURE)) {
                            video_buffers[qbuffs.index].flags |= V4L2_BUF_FLAG_MAPPED;
                            store_mem_buffer(ioctl_arg, video_buffers + qbuffs.index, sizeof(struct v4l2_buffer));
                            replace_syscall(0);
                        } else {
                            fprintf(stderr, "[DUMMY WARN] querybuf fail\n");
                            replace_syscall(-EINVAL);
                        }
                        break;
                    case VIDIOC_G_INPUT:;
                        const int input_g = 0;
                        store_mem_buffer(ioctl_arg, &input_g, sizeof(int));
                        replace_syscall(0);
                        break;
                    case VIDIOC_S_INPUT:;
                        int input_s;
                        load_mem_buffer(ioctl_arg, &input_s, sizeof(int));
                        if (input_s == 0) {
                            replace_syscall(0);
                        } else {
                            replace_syscall(-EINVAL);
                        }
                        break;
                    case VIDIOC_ENUMINPUT:;
                        struct v4l2_input enum_input_data;
                        load_mem_buffer(ioctl_arg, &enum_input_data, sizeof(enum_input_data));
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
                            store_mem_buffer(ioctl_arg, &ret, sizeof(ret));
                            replace_syscall(0);
                        } else {
                            replace_syscall(-EINVAL);
                        }
                        break;
                    default:
                        if (DEBUG) {
                            fprintf(stderr, "[DUMMY WARN] ioctl unimplemented:\n");
                            fprintf(stderr, "             DIR: %u\n", _IOC_DIR(cmd));
                            fprintf(stderr, "             TYPE: %c\n", (char) _IOC_TYPE(cmd));
                            fprintf(stderr, "             ID: %u\n", _IOC_NR(cmd));
                            //TRY_ERROR(-1, "shut it down");
                        }
                        replace_syscall(-ENOTTY);
                }
            } else {
                bring_to_syscall();
            }
            break;
        case SYS_read:
            if (last_regs.rdi == special_vid_fd) {
                fprintf(stderr, "[DUMMY WARN] read video unimplemented\n");
                TRY_ERROR(-1, "shut it down");
            }
            bring_to_syscall();
            break;
        case SYS_write:
            if (last_regs.rdi == special_vid_fd) {
                fprintf(stderr, "[DUMMY WARN] write video unimplemented\n");
                TRY_ERROR(-1, "shut it down");
            }
            bring_to_syscall();
            break;
        case SYS_mmap:
            if (last_regs.r8 == special_vid_fd) {
                unsigned long off = last_regs.r9;
                if (off >= VIDEO_BUFFER_CNT) {
                    replace_syscall(-EINVAL);
                } else {
                    printf("[DUMMY] modifying mmap with %llu\n", (unsigned long long) actual_video_buffers[off]);
                    replace_syscall((unsigned long long) actual_video_buffers[off]);
                }
            } else {
                bring_to_syscall();
            }
            break;
        case SYS_munmap:;
            int cancel = 0;
            for (int i = 0; i < VIDEO_BUFFER_CNT; i++) {
                if (actual_video_buffers[i] == ((void *) last_regs.rdi)) {
                    cancel = 1;
                    break;
                }
            }
            if (cancel) {
                printf("[DUMMY] someone wants to drop a mmap buffer\n");
                replace_syscall(0);
            } else {
                bring_to_syscall();
            }
            break;
        default:
            bring_to_syscall();
    }
    return 1;
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
    while (loop_syscalls(child_pid)) {}
}

void test_child_process() {
    int f_fd = openat(AT_FDCWD, "/dev/video0", O_RDONLY);
    close(f_fd);
    int fd = openat(AT_FDCWD, "/dev/video0", O_RDONLY);
    char buff[2048];
    int r;
    while ((r = read(fd, buff, 2048)) != 0) {
        TRY_ERROR(r, "failed to read");
        printf("%.*s", r, buff);
    }
    close(fd);
}

void child_process() {
    TRY_ERROR(ptrace(PTRACE_TRACEME, 0, 0, 0), "failed to accept ptrace");
    kill(getpid(), SIGSTOP); // cannot fail
    //TRY_ERROR(execlp("zoom", "zoom", NULL), "failed to start program");
    TRY_ERROR(execlp("v4l2-compliance", "v4l2-compliance", NULL), "failed to start program");
    //TRY_ERROR(execlp("v4l2-ctl", "v4l2-ctl", "--all", NULL), "failed to start program");
}

int main(int argc, char **argv) {
    for (int i = 0; i < VIDEO_BUFFER_CNT; i++) {
        actual_video_buffers[i] = mmap(
            NULL,
            VIDEO_BUFF_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_SHARED,
            -1,
            0
        );
        TRY_ERROR((ssize_t) actual_video_buffers[i], "failed to allocate buffers");
    }
    child_pid = fork();
    switch (child_pid) {
        case -1: TRY_ERROR(-1, "failed to fork"); break;
        case 0: child_process(); break;
        default: parent_process();
    }
}
