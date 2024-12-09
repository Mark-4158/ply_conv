LIBNAME=libpam_ply.so
LIBVER=0.1.0

build: libpam_ply plyin

clean:
	rm -f plyin ${LIBNAME} ${LIBNAME}.${LIBVER}

libpam_ply:
	cc -std=gnu23 -O2 -Wpedantic -Wall -Wextra -Wno-multichar -shared -fPIC\
		 -lply -o ${LIBNAME}.${LIBVER} src/ply-pam-conv.c src/ply-conv.c
	ln -sf ${LIBNAME}.${LIBVER} ${LIBNAME}.0
	ln -sf ${LIBNAME}.0 ${LIBNAME}

plyin:
	patchelf --add-needed libpam_ply.so.0 --rename-dynamic-symbols\
		rename.map --output plyin /bin/login
