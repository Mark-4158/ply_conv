/*
    <one line to give the program's name and a brief idea of what it does.>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define u(arg) (static const union { char s[sizeof (uint16_t)]; uint16_t x; }){ arg }.x
#define U(arg) (static const union { char s[sizeof (uint32_t)]; uint32_t x; }){ arg }.x


static ssize_t conv_write(const int sockfd,
                          const struct pam_message *const msg) {
    uint8_t query[strnlen(msg->msg, UINT8_MAX - 1) + 4] = { };

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
        *query = 'M';
        break;
    }

    query[1] = '\002';
    query[2] = (sizeof query - 3)
             - (*(uint16_t *)(msg->msg + (sizeof query - 6)) == u(": ")) * 2;
    memcpy(query + 3, msg->msg, query[2] - 1);

    *query = ply_write(sockfd, query, sizeof query);
    explicit_bzero(query + 1, sizeof query - 2);
#ifdef DEBUG
    dprintf(STDERR_FILENO, "conv_write(): %s\n", msg->msg);
#endif // DEBUG

    return *query ? (ssize_t)sizeof query : (perror("conv_write()"), -1);
}


static ssize_t conv_read(const int sockfd, struct pam_response *const resp) {
    for (uint8_t resp_type;
         resp->resp_retcode = ply_read(sockfd, &resp_type, sizeof resp_type),
         resp->resp_retcode--;) {
#ifdef DEBUG
        dprintf(STDERR_FILENO, "conv_read(): %x\n", resp_type);
#endif // DEBUG
        switch (resp_type) {
        case '\x2':
        case '\t':
            union {
                uint32_t val;
                size_t n;
            } len;

            if (resp->resp_retcode = ply_read_uint32(sockfd, &len.val),
                resp->resp_retcode--) {
                char *const s = malloc((len.n = len.val) + 1);

                if (s) {
                    if ((resp->resp_retcode = ply_read(sockfd, s, len.n),
                         resp->resp_retcode--)) {
                        (resp->resp = s)[resp->resp_retcode = len.n] = '\0';

                        return resp->resp_retcode;
                    }

                    explicit_bzero(s, len.n);
                    free(s);
                }
            }
            break;

        case '\x5':
        case '\x6':
            return resp->resp = nullptr, 0;

        default:
            continue;
        }
        break;
    }
    perror("conv_read()");

    return -1;
}

int ply_conv(const int num_msg, const struct pam_message **const msgv,
             struct pam_response **const respv, void *) {
    int ret = PAM_BUF_ERR;
    struct pam_response *const retv = calloc(num_msg, sizeof **respv);

    switch ((bool)retv) {
    default:
        const int sockfd = ply_connect_init();

        if (sockfd == -1)
            ret = PAM_CONV_ERR;
        else {
            for (int i = { };;) {
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
                    explicit_bzero(retv, (size_t)i * sizeof *retv);
                    free(retv);

                    break;
                }
#ifdef DEBUG
                dprintf(STDERR_FILENO, "ply_conv(): %s\n", resp->resp);
#endif // DEBUG
            }

            if (!close(sockfd))
                break;
        }
        [[fallthrough]];
    case false:
        perror("ply_conv()");
    }

    return ret;
}
