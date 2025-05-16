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

#include <err.h>

static const char *const SOCKET_PATHV[] = {
    PLY_BOOT_PROTOCOL_OLD_ABSTRACT_SOCKET_PATH,
    PLY_BOOT_PROTOCOL_TRIMMED_ABSTRACT_SOCKET_PATH,
};
static const int SOCKET_TYPEV[] = {
    PLY_UNIX_SOCKET_TYPE_ABSTRACT,
    PLY_UNIX_SOCKET_TYPE_TRIMMED_ABSTRACT,
};


inline int ply_connect_init() {
    int i = ARRLEN(SOCKET_TYPEV) - 1;

    do {
        const int sockfd =
            ply_connect_to_unix_socket(SOCKET_PATHV[i], SOCKET_TYPEV[i]);

	if (sockfd != -1)
            return sockfd;
    } while (i--);

    warn("ply_connect_init()");
    return -1;
}
