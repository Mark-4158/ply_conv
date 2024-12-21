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

#include <assert.h>
#include <err.h>

#define ARRLEN(v) (sizeof v / sizeof *v)

enum PLY_TYPE {
    PLY_TYPE_ABSTRACT = 0,
    PLY_TYPE_TRIMMED_ABSTRACT,
    PLY_TYPE_N,
};


static inline int connect_to_unix_socket(enum PLY_TYPE type) {
    static const char *const PLY_BOOT_PROTOCOL_SOCKET_PATHS[] = {
        PLY_BOOT_PROTOCOL_OLD_ABSTRACT_SOCKET_PATH,
        PLY_BOOT_PROTOCOL_TRIMMED_ABSTRACT_SOCKET_PATH,
    };
    static const int PLY_UNIX_SOCKET_TYPES[] = {
        PLY_UNIX_SOCKET_TYPE_ABSTRACT,
        PLY_UNIX_SOCKET_TYPE_TRIMMED_ABSTRACT,
    };

    static_assert (ARRLEN(PLY_BOOT_PROTOCOL_SOCKET_PATHS) == PLY_TYPE_N);
    static_assert (ARRLEN(PLY_UNIX_SOCKET_TYPES) == PLY_TYPE_N);

    return ply_connect_to_unix_socket(PLY_BOOT_PROTOCOL_SOCKET_PATHS[type],
                                      PLY_UNIX_SOCKET_TYPES[type]);
}

inline int ply_connect_init() {
    int sockfd;

    for (int i = PLY_TYPE_N; (sockfd = connect_to_unix_socket(--i)) == -1;) {
        if (!i) {
            warn("ply_connect_init()");

            break;
        }
    }

    return sockfd;
}
