#define _GNU_SOURCE

#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <bits/types.h>
#include <sys/mman.h>
#include <linux/videodev2.h>
#include <linux/version.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <poll.h>

#define DEBUG 1

#define DEBUG_LOG(msg) do {\
    if (DEBUG) {\
        printf("[DUMMY] " msg "\n");\
    }\
} while (0)

#define ERROR_IF(val, msg) do {\
    if (val) {\
        fputs("[DUMMY ERROR] " msg "\n", stderr);\
        exit(-1);\
    }\
} while (0)

#define TRY_ERROR(func, msg) ERROR_IF((func) == -1, msg)

int (*_old_ioctl)(int, unsigned long, void *);
int (*_old_open)(const char *, int, __mode_t);
int (*_old_close)(int);
void *(*_old_mmap)(void *, size_t, int, int, int, off_t);
int (*_old_poll)(struct pollfd *, nfds_t, int);
int start_pid;

__attribute__((constructor))
void _init_dummyplug() {
    _old_ioctl = dlsym(RTLD_NEXT, "ioctl");
    _old_open = dlsym(RTLD_NEXT, "open");
    _old_close = dlsym(RTLD_NEXT, "close");
    _old_mmap = dlsym(RTLD_NEXT, "mmap");
    _old_poll = dlsym(RTLD_NEXT, "poll");
    start_pid = getpid();
}

#define VIDEO_WIDTH 1920
#define VIDEO_HEIGHT 1080
#define VIDEO_FMT V4L2_PIX_FMT_RGB24
#define VIDEO_FMT_NAME "24 bit RGB"
#define VIDEO_FMT_PIXEL_SIZE 3

#define VIDEO_BUFF_SIZE_USED (VIDEO_WIDTH * VIDEO_FMT_PIXEL_SIZE * VIDEO_HEIGHT)

// TODO: not this
#define GUESS_PAGE_SIZE 4096

#define VIDEO_BUFF_SIZE ((VIDEO_BUFF_SIZE_USED + GUESS_PAGE_SIZE - 1) & ~(GUESS_PAGE_SIZE - 1))

#define VIDEO_BUFF_CNT 2

#define VIDEO_BUFF_TOTAL_SIZE (VIDEO_BUFF_SIZE * VIDEO_BUFF_CNT)

struct v4l2_buffer video_buffers[VIDEO_BUFF_CNT] = {
    {
        .index = 0,
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .bytesused = VIDEO_BUFF_SIZE_USED,
        .flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC | V4L2_BUF_FLAG_TSTAMP_SRC_SOE,
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
        .bytesused = VIDEO_BUFF_SIZE_USED,
        .flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC | V4L2_BUF_FLAG_TSTAMP_SRC_SOE,
        .field = V4L2_FIELD_NONE,
        .memory = V4L2_MEMORY_MMAP,
        .m = {
            .offset = VIDEO_BUFF_SIZE
        },
        .length = VIDEO_BUFF_SIZE
    }
};
unsigned int seq_cnt;

int vid_fd = -1;
char *vid_map;

void print_data(void *d, size_t len) {
    unsigned int *d_i = d;
    size_t len_i = len / 4;
    for (size_t i = 0; i < len_i; i++) {
        unsigned int int_store = d_i[i];
        char out[4];
        *((unsigned int *) out) = d_i[i];
        printf("%02hhx %02hhx %02hhx %02hhx | ", out[0], out[1], out[2], out[3]);
        for (int j = 0; j < 4; j++) {
            if (!isgraph(out[j])) out[j] = '.';
        }
        printf("%c%c%c%c | %u\n", out[0], out[1], out[2], out[3], int_store);
    }
}

void record_timestamp(struct timeval *tstamp) {
    struct timespec tmp;
    TRY_ERROR(clock_gettime(CLOCK_MONOTONIC, &tmp), "failed to get time");
    tstamp->tv_sec = tmp.tv_sec;
    tstamp->tv_usec = tmp.tv_nsec / 1000;
}

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
            .priv = 0
        }
    }
};

void fill_buffers() {
    for (int i = 0; i < VIDEO_BUFF_CNT; i++) {
        if (video_buffers[i].flags & V4L2_BUF_FLAG_QUEUED) {
            for (int j = 0; j < (VIDEO_WIDTH * VIDEO_HEIGHT); j++) {
                vid_map[VIDEO_BUFF_SIZE * i + VIDEO_FMT_PIXEL_SIZE * j + 0] = 0xff;
                vid_map[VIDEO_BUFF_SIZE * i + VIDEO_FMT_PIXEL_SIZE * j + 1] = 0;
                vid_map[VIDEO_BUFF_SIZE * i + VIDEO_FMT_PIXEL_SIZE * j + 2] = 0;
            }
            video_buffers[i].flags ^= V4L2_BUF_FLAG_QUEUED | V4L2_BUF_FLAG_DONE;
        }
    }
}

int video_ioctl(int fd, unsigned long request, void *ioctl_ptr) {
    int cpid = getpid();
    if (cpid != start_pid) {
        printf("$$$ - (   %d != %d   ) - $$$", start_pid, cpid);
        __builtin_trap();
    }
    switch (request) {
        case VIDIOC_QUERYCAP:
            do {
                DEBUG_LOG("querycap");
                const int dev_caps = V4L2_CAP_VIDEO_CAPTURE |
                                     V4L2_CAP_STREAMING |
                                     /*V4L2_CAP_EXT_PIX_FORMAT*/0;
                struct v4l2_capability *cap_ptr = ioctl_ptr;
                const char driver[16] = "dummyplug";
                const char card[32] = "Dummy Plug";
                const char bus_info[32] = "platform:psyche_chip";
                memcpy(&cap_ptr->driver, driver, 16);
                memcpy(&cap_ptr->card, card, 32);
                memcpy(&cap_ptr->bus_info, bus_info, 32);
                cap_ptr->version = LINUX_VERSION_CODE;
                cap_ptr->capabilities = dev_caps | V4L2_CAP_DEVICE_CAPS;
                cap_ptr->device_caps = dev_caps;
                memset(&cap_ptr->reserved, 0, sizeof(cap_ptr->reserved));
                return 0;
            } while (0);
            __builtin_trap();
        case VIDIOC_ENUM_FMT:
            do {
                DEBUG_LOG("enum_fmt");
                struct v4l2_fmtdesc *fmt_ptr = ioctl_ptr;
                if ((fmt_ptr->index == 0) && (fmt_ptr->type == V4L2_BUF_TYPE_VIDEO_CAPTURE)) {
                    fmt_ptr->flags = 0;
                    const char description[32] = VIDEO_FMT_NAME;
                    memcpy(&fmt_ptr->description, description, 32);
                    fmt_ptr->pixelformat = VIDEO_FMT;
                    memset(&fmt_ptr->reserved, 0, sizeof(fmt_ptr->reserved));
                    return 0;
                } else {
                    errno = EINVAL;
                    return -1;
                }
            } while (0);
            __builtin_trap();
        case VIDIOC_S_FMT:
            printf("NOTE: S_FMT\n");
        case VIDIOC_G_FMT:
        case VIDIOC_TRY_FMT:
            do {
                DEBUG_LOG("g/s/try_fmt");
                struct v4l2_format *fmt_ptr = ioctl_ptr;
                if (fmt_ptr->type == video_only_format.type) {
                    int exp_fmt = fmt_ptr->fmt.pix.pixelformat;
                    memcpy(fmt_ptr, &video_only_format, sizeof(struct v4l2_format));
                    return 0;
                } else {
                    errno = EINVAL;
                    return -1;
                }
            } while (0);
            __builtin_trap();
        case VIDIOC_G_PARM:
            do {
                DEBUG_LOG("g_param");
                struct v4l2_streamparm *parm_ptr = ioctl_ptr;
                if (parm_ptr->type == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
                    memset(parm_ptr, 0, sizeof(struct v4l2_streamparm));
                    parm_ptr->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
                    return 0;
                } else {
                    errno = EINVAL;
                    return -1;
                }
            } while (0);
            __builtin_trap();
        case VIDIOC_REQBUFS:
            do {
                DEBUG_LOG("reqbufs");
                seq_cnt = 0;
                struct v4l2_requestbuffers *rbuffs_ptr = ioctl_ptr;
                if (rbuffs_ptr->type == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
                    if (rbuffs_ptr->memory != V4L2_MEMORY_MMAP) {
                        rbuffs_ptr->count = 0;
                        rbuffs_ptr->capabilities = V4L2_BUF_CAP_SUPPORTS_MMAP;
                        rbuffs_ptr->reserved[0] = 0;
                        errno = EINVAL;
                        return -1;
                    } else {
                        rbuffs_ptr->count = VIDEO_BUFF_CNT;
                        rbuffs_ptr->capabilities = V4L2_BUF_CAP_SUPPORTS_MMAP;
                        rbuffs_ptr->reserved[0] = 0;
                        for (int i = 0; i < VIDEO_BUFF_CNT; i++) {
                            video_buffers[i].flags |= 0;
                        }
                        return 0;
                    }
                } else {
                    rbuffs_ptr->count = 0;
                    rbuffs_ptr->capabilities = V4L2_BUF_CAP_SUPPORTS_MMAP;
                    rbuffs_ptr->reserved[0] = 0;
                    errno = EINVAL;
                    return -1;
                }
            } while (0);
            __builtin_trap();
        case VIDIOC_QUERYBUF:
            do {
                DEBUG_LOG("querybuf");
                struct v4l2_buffer *qbuffs_ptr = ioctl_ptr;
                if ((qbuffs_ptr->index < VIDEO_BUFF_CNT) && (qbuffs_ptr->type == V4L2_BUF_TYPE_VIDEO_CAPTURE)) {
                    memcpy(qbuffs_ptr, video_buffers + qbuffs_ptr->index, sizeof(struct v4l2_buffer));
                    return 0;
                } else {
                    errno = EINVAL;
                    return -1;
                }
            } while (0);
            __builtin_trap();
        case VIDIOC_QBUF:
            do {
                DEBUG_LOG("qbuf");
                struct v4l2_buffer *qbuffs_ptr = ioctl_ptr;
                if ((qbuffs_ptr->index < VIDEO_BUFF_CNT) && (qbuffs_ptr->type == V4L2_BUF_TYPE_VIDEO_CAPTURE)) {
                    video_buffers[qbuffs_ptr->index].flags |= V4L2_BUF_FLAG_MAPPED | V4L2_BUF_FLAG_QUEUED;
                    memcpy(qbuffs_ptr, video_buffers + qbuffs_ptr->index, sizeof(struct v4l2_buffer));
                    return 0;
                } else {
                    errno = EINVAL;
                    return -1;
                }
            } while (0);
            __builtin_trap();
        case VIDIOC_STREAMON:
            return 0;
        case VIDIOC_DQBUF:
            do {
                DEBUG_LOG("dqbuf");
                fill_buffers();
                struct v4l2_buffer *qbuffs_ptr = ioctl_ptr;
                int idx = -1;
                for (int i = 0; i < VIDEO_BUFF_CNT; i++) {
                    if (video_buffers[i].flags & V4L2_BUF_FLAG_DONE) {
                        video_buffers[i].flags &= ~V4L2_BUF_FLAG_DONE;
                        idx = i;
                        break;
                    }
                }
                TRY_ERROR(idx, "no buffers to queue");
                if (qbuffs_ptr->type == V4L2_BUF_TYPE_VIDEO_CAPTURE) {
                    video_buffers[idx].flags &= ~V4L2_BUF_FLAG_QUEUED;
                    video_buffers[idx].sequence = ++seq_cnt;
                    record_timestamp(&video_buffers[idx].timestamp);
                    memcpy(qbuffs_ptr, video_buffers + idx, sizeof(struct v4l2_buffer));
                    return 0;
                } else {
                    errno = EINVAL;
                    return -1;
                }
            } while (0);
            __builtin_trap();
        case VIDIOC_G_INPUT:
            DEBUG_LOG("g_input");
            *((int *) ioctl_ptr) = 0;
            return 0;
            __builtin_trap();
        case VIDIOC_S_INPUT:
            DEBUG_LOG("s_input");
            if (*((int *) ioctl_ptr) == 0) {
                return 0;
            } else {
                errno = EINVAL;
                return -1;
            }
            __builtin_trap();
        case VIDIOC_ENUMINPUT:
            do {
                DEBUG_LOG("enuminput");
                struct v4l2_input *ein_ptr = ioctl_ptr;
                if (ein_ptr->index == 0) {
                    const struct v4l2_input ret = {
                        .index = 0,
                        .name = "Single Input",
                        .type = V4L2_INPUT_TYPE_CAMERA,
                        .audioset = 0,
                        .std = 0,
                        .status = 0,
                        .capabilities = 0
                    };
                    memcpy(ein_ptr, &ret, sizeof(struct v4l2_input));
                    return 0;
                } else {
                    return -EINVAL;
                }
            } while (0);
            __builtin_trap();
        /*
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
        case VIDIOC_STREAMON:;
            int st_mode_on;
            LD_STRUCT(&st_mode_on);
            if ((st_mode_on == V4L2_BUF_TYPE_VIDEO_CAPTURE) && !is_mapped) {
                return 0;
            } else {
                return -EINVAL;
            }
            */
        case VIDIOC_EXPBUF:
            errno = EINVAL;
            return -1;
        case VIDIOC_G_CTRL:
        case VIDIOC_S_CTRL:
            errno = EINVAL;
            return -1;
        case VIDIOC_STREAMOFF:;
            return 0;
        case VIDIOC_CREATE_BUFS:
            do {
                struct v4l2_create_buffers *cbuffs_ptr = ioctl_ptr;
                if ((cbuffs_ptr->memory != V4L2_MEMORY_MMAP) || (memcmp(&cbuffs_ptr->format, &video_only_format, sizeof(struct v4l2_format)))) {
                    errno = EINVAL;
                    printf("FAIL FAIL FAIL\n");
                    return -1;
                } else {
                    if (cbuffs_ptr->count == 0) {
                        cbuffs_ptr->index = 2;
                        return 0;
                    } else {
                        cbuffs_ptr->index = 0;
                        cbuffs_ptr->count = 2;
                        return 0;
                    }
                }
            } while (0);
            __builtin_trap();
        case VIDIOC_ENUMSTD:
            errno = EINVAL;
            return -1;
        case VIDIOC_ENUM_FRAMESIZES:
            do {
                struct v4l2_frmsizeenum *efrm = ioctl_ptr;
                if ((efrm->index != 0) || (efrm->pixel_format != VIDEO_FMT)) {
                    errno = EINVAL;
                    return -1;
                } else {
                    efrm->type = V4L2_FRMSIZE_TYPE_DISCRETE;
                    efrm->discrete.width = VIDEO_WIDTH;
                    efrm->discrete.height = VIDEO_HEIGHT;
                    return 0;
                }
            } while (0);
            __builtin_trap();
        case VIDIOC_QUERYCTRL:
            errno = EINVAL;
            return -1;
        case VIDIOC_CROPCAP:
            errno = ENODATA;
            return -1;
        case VIDIOC_ENUM_FRAMEINTERVALS:
            do {
                struct v4l2_frmivalenum *eval = ioctl_ptr;
                if ((eval->index != 0) || (eval->pixel_format != VIDEO_FMT) || (eval->width != VIDEO_WIDTH) || (eval->height != VIDEO_HEIGHT)) {
                    errno = EINVAL;
                    return -1;
                } else {
                    eval->type = V4L2_FRMIVAL_TYPE_DISCRETE;
                    eval->discrete.numerator = 1;
                    eval->discrete.denominator = 30;
                    return 0;
                }
            } while (0);
            __builtin_trap();
        default:
            if (DEBUG || 1) {
                fprintf(stderr, "[DUMMY WARN] ioctl unimplemented:\n");
                fprintf(stderr, "             DIR: %u\n", (unsigned int) _IOC_DIR(request));
                fprintf(stderr, "             TYPE: %c\n", (char) _IOC_TYPE(request));
                fprintf(stderr, "             ID: %u\n", (unsigned int) _IOC_NR(request));
                fprintf(stderr, "             SIZE: %u\n", (unsigned int) _IOC_SIZE(request));
                fprintf(stderr, "             $$: %lx\n", request);
                //TRY_ERROR(-1, "shut it down");
            }
            errno = ENOTTY;
            return -1;
    }
}

void log_vid_ioctl_start(int fd, unsigned int request, void *ptr) {
    if (_IOC_TYPE(request) == 'V') {
        printf("DETECT IOCTL ON %d:\n", fd);
        printf("NR: %d\n", (int) _IOC_NR(request));
        printf("###\n");
        if (request & IOC_IN) {
            printf("INPUT DATA:\n");
            print_data(ptr, _IOC_SIZE(request));
        }
        printf("---\n");
    }
}

void log_vid_ioctl_end(int fd, unsigned int request, void *ptr) {
    if (_IOC_TYPE(request) == 'V') {
        if (request & IOC_OUT) {
            printf("OUTPUT DATA:\n");
            print_data(ptr, _IOC_SIZE(request));
        }
        printf("###\n");
    }
}

volatile pthread_spinlock_t fake_sys_lock;
__attribute__((constructor)) void _init_fake_sys_lock() {
    pthread_spin_init(&fake_sys_lock, PTHREAD_PROCESS_SHARED);
}

__attribute__((destructor)) void _free_fake_sys_lock() {
    pthread_spin_destroy(&fake_sys_lock);
}

#define SYS_LOCK do {\
    /*printf("LOCKING: %d\n", __LINE__);\
    pthread_spin_lock(&fake_sys_lock);*/\
} while (0);

#define SYS_UNLOCK do {\
    /*printf("UNLOCKING: %d\n", __LINE__);\
    pthread_spin_unlock(&fake_sys_lock);*/\
} while (0);

int ioctl(int fd, unsigned int request, void *ptr) {
    SYS_LOCK;
    if ((vid_fd != -1) && (fd == vid_fd)) {
        log_vid_ioctl_start(fd, request, ptr);
        //printf("[=DUMMY=] ioctl from %p\n", __builtin_extract_return_addr(__builtin_frame_address(0)));
        int ret = video_ioctl(fd, request, ptr);
        //printf("[=DUMMY=] %d\n", ret);
        log_vid_ioctl_end(fd, request, ptr);
        SYS_UNLOCK;
        return ret;
    } else {
        int ret = _old_ioctl(fd, request, ptr);
        SYS_UNLOCK;
        return ret;
    }
}

int open(const char *file, int flags, __mode_t c_mode) {
    const char vidprefix[] = "/dev/video";
    for (int i = 0; i < 10; i++) {
        if (("/dev/video")[i] != file[i]) {
            return _old_open(file, flags, c_mode);
        }
    }
    if ((file[10] == '0') && (file[11] == 0)) {
        SYS_LOCK;
        if (vid_fd == -1) {
            vid_fd = memfd_create("/dev/video0", 0);
            TRY_ERROR(vid_fd, "failed to create memfd");
            TRY_ERROR(ftruncate(vid_fd, VIDEO_BUFF_TOTAL_SIZE), "failed to expand memfd");
            vid_map = mmap(NULL, VIDEO_BUFF_TOTAL_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, vid_fd, 0);
            TRY_ERROR((long long) vid_fd, "failed to map memfd");
            SYS_UNLOCK;
            return vid_fd;
        } else {
            SYS_UNLOCK;
            fprintf(stderr, "[DUMMY] multiple opens not supported\n");
            TRY_ERROR(-1, "stop");
            errno = EBUSY;
            return -1;
        }
    } else {
        errno = ENOENT;
        return -1;
    }
}

int close(int fd) {
    SYS_LOCK;
    if ((vid_fd != -1) && (vid_fd == fd)) {
        munmap(vid_map, VIDEO_BUFF_TOTAL_SIZE);
        vid_map = NULL;
        vid_fd = -1;
    }
    int ret = _old_close(fd);
    SYS_UNLOCK;
    return ret;
}

void *mmap(void *addr, size_t len, int prot, int flags,
           int fd, off_t off) {
    SYS_LOCK;
    if ((vid_fd != -1) && (fd == vid_fd)) {
        flags |= MAP_SHARED;
    }
    void *ret = _old_mmap(addr, len, prot, flags, fd, off);
    SYS_UNLOCK;
    return ret;
}

int poll(struct pollfd *fds, nfds_t fd_cnt, int timeout) {
    nfds_t rep_index = -1;
    SYS_LOCK;
    if (vid_fd != -1) {
        for (nfds_t i = 0; i < fd_cnt; i++) {
            if (fds[i].fd == vid_fd) {
                printf("POLL\n");
                fds[i].fd = -fds[i].fd;
                if (timeout < 0) timeout = 5;
                int ret = _old_poll(fds, fd_cnt, 5) + 1;
                fds[i].fd = -fds[i].fd;
                fds[i].revents |= fds[i].events & POLLIN;
                SYS_UNLOCK;
                return ret;
            }
        }
    }
    SYS_UNLOCK;
    return _old_poll(fds, fd_cnt, timeout);
}
