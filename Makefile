LIBNAME=libpam_ply.so.0.1.0

build: libpam_ply plyin

clean:
	rm plyin ${LIBNAME}

libpam_ply:
	cc -std=gnu23 -O2 -Wpedantic -Wall -Wextra -Wno-multichar -shared -fPIC\
		 -lply -o ${LIBNAME} ply-pam-conv.c ply_conv.c

plyin:
	patchelf --add-needed libpam_ply.so.0 --rename-dynamic-symbols\
		rename.map --output plyin /bin/login
