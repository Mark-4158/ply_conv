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
#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


static ssize_t conv_write(const int sockfd,
                          const struct pam_message *const msg) {
    ssize_t len = strnlen(msg->msg, UINT8_MAX - 1);
    uint8_t query[UINT8_MAX + 3] = "M\x2";

    do {
        switch (msg->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            *query = '*';
            break;

        case PAM_PROMPT_ECHO_ON:
            *query = 'W';
            break;

        case PAM_ERROR_MSG:
            ply_write(sockfd,
                      PLY_BOOT_PROTOCOL_REQUEST_TYPE_ERROR,
                      sizeof PLY_BOOT_PROTOCOL_REQUEST_TYPE_ERROR);
            [[fallthrough]];
        default:
            continue;
        }

        for (; len; --len) {
            register const int ch = (msg->msg + len)[-1];

            if (ch > '\x7F' || isalnum(ch)) {
                break;
            }
        }
    } while (false);

    query[2] = len + 1;
    memcpy(query + 3, msg->msg, len);

    if (!ply_write(sockfd, query, len + 4)) {
        warn("conv_write()");
        len = -1;
    }
    explicit_bzero(query, sizeof query);

    return len;
}

static ssize_t conv_read(const int sockfd, struct pam_response *const resp) {
    for (uint8_t resp_type;
         resp->resp_retcode = ply_read(sockfd, &resp_type, sizeof resp_type),
         resp->resp_retcode--;) {
        switch (resp_type) {
        case '\x2':
        case '\t':
            union {
                uint32_t u32;
                size_t n;
            } len;

            if (resp->resp_retcode = ply_read_uint32(sockfd, &len.u32),
                resp->resp_retcode--) {
                register char *const s = calloc((len.n = len.u32) + 1, 1);

                if (s) {
                    mlock(s, len.n);
                    if (resp->resp_retcode = ply_read(sockfd, s, len.n),
                        resp->resp_retcode--) {
                        resp->resp = s;
                        resp->resp_retcode = MIN(len.n, INT_MAX);

                        return len.n;
                    }

                    explicit_bzero(s, len.n);
                    munlock(s, len.n);
                    free(s);
                }
            }
            break;

        case '\x5':
        case '\x6':
            return resp->resp = NULL, 0;

        default:
            continue;
        }
        break;
    }
    warn("conv_read()");

    return -1;
}

int ply_conv(const int num_msg, const struct pam_message **const msgv,
             struct pam_response **const respv, void *) {
    int ret = PAM_BUF_ERR;
    struct pam_response *const retv = calloc(num_msg, sizeof **respv);

    switch ((bool)retv) {
    default:
        const int sockfd = ply_connect_init();

        if (sockfd == -1) {
            ret = PAM_CONV_ERR;
        } else {
            for (ssize_t i = 0;;) {
                if (i == num_msg) {
                    *respv = retv;
                    ret = PAM_SUCCESS;

                    break;
                }

                register struct pam_response *resp = retv + i;

                if (conv_write(sockfd, msgv[i++]) == -1 ||
                    conv_read(sockfd, resp) == -1) {
                    if (resp->resp_retcode)
                        ret = PAM_CONV_ERR;

                    while (resp-- != retv) {
                        if (resp->resp) {
                            explicit_bzero(resp->resp, resp->resp_retcode);
                            free(resp->resp);
                        }
                    }
                    explicit_bzero(retv, i * sizeof *retv);
                    free(retv);

                    break;
                }
            }

            if (!close(sockfd)) {
                break;
            }
        }
        [[fallthrough]];
    case false:
        warn("ply_conv()");
    }

    return ret;
}
