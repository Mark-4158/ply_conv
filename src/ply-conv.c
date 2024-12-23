/*
    Plymouth-based, PAM conversation function
    Copyright (C) 2024  Mark A. Williams, Jr.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software Foundation,
    Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "ply-pam-conv.h"

#include <plymouth-1/ply-boot-client/ply-boot-protocol.h>
#include <plymouth-1/ply/ply-utils.h>

#include <security/pam_appl.h>

#include <sys/mman.h>
#include <malloc.h>
#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


static ssize_t conv_write(const int sockfd,
                          const struct pam_message *const msg) {
    static const char (*const hdrv)[2] =
        (void *) PLY_BOOT_PROTOCOL_REQUEST_TYPE_PING "\x2"
                 PLY_BOOT_PROTOCOL_REQUEST_TYPE_PASSWORD "\x2"
                 PLY_BOOT_PROTOCOL_REQUEST_TYPE_QUESTION "\x2"
                 PLY_BOOT_PROTOCOL_REQUEST_TYPE_ERROR "\x2"
                 PLY_BOOT_PROTOCOL_REQUEST_TYPE_SHOW_MESSAGE "\x2";
    static const uint8_t *const lenv = (void *)"\x2\x2\x2\x4\x2";

    if ((unsigned)msg->msg_style < 5) {
        if (ply_write(sockfd, hdrv[msg->msg_style], lenv[msg->msg_style])) {
            const uint8_t len = strnlen(msg->msg, UINT8_MAX);

            if (ply_write(sockfd, &len, sizeof len) &&
                ply_write(sockfd, msg->msg, len)) {
                return len;
            }
        }
        warn("conv_write()");
    } else {
        warnx("conv_write(): unsupported PAM message type requested");
    }

    return -1;
}

static ssize_t conv_read(const int sockfd, struct pam_response *const resp) {
    resp->resp_retcode = PAM_SUCCESS;
    for (;;) {
        uint8_t resp_type;

        if (ply_read(sockfd, &resp_type, 1)) {
            if (resp_type == '\x2' || resp_type == '\t') {
                union {
                    uint32_t u32;
                    size_t n;
                } len;

                if (ply_read_uint32(sockfd, &len.u32)) {
                    char *const s = malloc((len.n = len.u32) + 1);

                    if (s) {
                        mlock(s, len.n);
                        if (ply_read(sockfd, s, len.n)) {
                            resp->resp = s;
                            return MIN(len.n, SSIZE_MAX);
                        }
                        munlock(s, len.n);
                        free(s);
                        resp->resp_retcode = PAM_CONV_ERR;
                    } else {
                        resp->resp_retcode = PAM_BUF_ERR;
                    }
                }
            } else if (resp_type == '\x5' || resp_type == '\x6') {
                resp->resp = NULL;
                return 0;
            } else {
                continue;
            }
        }

        warn("conv_read()");
        break;
    }

    return -1;
}

int ply_conv(const int num_msg, const struct pam_message **const msgv,
             struct pam_response **const prespv, void *) {
    int ret = PAM_SUCCESS;

    mallopt(M_PERTURB, 0xFF);
    do {
        struct pam_response *const respv = malloc(num_msg * sizeof **prespv);

        if (respv) {
            const int sockfd = ply_connect_init();

            if (sockfd == -1) {
                ret = PAM_CONV_ERR;
            } else {
                for (unsigned i = 0;;) {
                    if ((unsigned)num_msg == i) {
                        *prespv = respv;
                        break;
                    }

                    struct pam_response *resp = respv + i;

                    if (conv_write(sockfd, msgv[i++]) == -1) {
                        ret = PAM_CONV_ERR;
                    } else {
                        conv_read(sockfd, resp);
                        if (resp->resp_retcode == PAM_CONV_ERR) {
                            ret = PAM_CONV_ERR;
                        } else {
                            if (resp->resp_retcode == PAM_BUF_ERR) {
                                ret = PAM_BUF_ERR;
                            }
                            continue;
                        }
                    }

                    do {
                        free(resp->resp);
                    } while (resp-- != respv);
                    free(respv);

                    break;
                }

                if (!close(sockfd)) {
                    break;
                }
            }
        } else {
            ret = PAM_BUF_ERR;
        }

        warn("ply_conv()");
    } while (0);
    mallopt(M_PERTURB, 0);

    return ret;
}
