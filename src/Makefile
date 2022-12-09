CFLAGS= -Wall -Wno-format-security -I/usr/local/include
LDFLAGS= -L/usr/local/lib
LIBS= -lspf2 -lpthread
BINDIR= ./bin
BINFILE= postfix-spfpd

OBJFILES= ${BINDIR}/ps_main.o ${BINDIR}/ps_white.o \
	${BINDIR}/ps_read_request.o ${BINDIR}/ps_other.o \
	${BINDIR}/ps_white_test.o ${BINDIR}/ps_white_write.o \
	${BINDIR}/ps_white_read.o ${BINDIR}/ps_getopt.o

all: ${BINDIR} ${BINDIR}/${BINFILE}

${BINDIR}:
	mkdir ${BINDIR}

clean:
	rm -f ${OBJFILES} ${BINDIR}/${BINFILE}
	( [ -d ${BINDIR} ] && rmdir ${BINDIR} ) || true

install: ${BINDIR}/${BINFILE} ${DESTROOT}/libexec
	cp ${BINDIR}/${BINFILE} ${DESTROOT}/libexec/${BINFILE}

${BINDIR}/${BINFILE}: ${OBJFILES}
	${CC} ${LDFLAGS} ${LIBS} -o ${BINDIR}/${BINFILE} ${OBJFILES}

${BINDIR}/ps_main.o: ps_main.c
	${CC} ${CFLAGS} -c -o ${BINDIR}/ps_main.o ps_main.c

${BINDIR}/ps_white.o: ps_white.c
	${CC} ${CFLAGS} -c -o ${BINDIR}/ps_white.o ps_white.c

${BINDIR}/ps_getopt.o: ps_getopt.c
	${CC} ${CFLAGS} -c -o ${BINDIR}/ps_getopt.o ps_getopt.c

${BINDIR}/ps_white_test.o: ps_white_test.c
	${CC} ${CFLAGS} -c -o ${BINDIR}/ps_white_test.o ps_white_test.c

${BINDIR}/ps_read_request.o: ps_read_request.c
	${CC} ${CFLAGS} -c -o ${BINDIR}/ps_read_request.o ps_read_request.c

${BINDIR}/ps_other.o: ps_other.c
	${CC} ${CFLAGS} -c -o ${BINDIR}/ps_other.o ps_other.c

${BINDIR}/ps_white_write.o: ps_white_write.c
	${CC} ${CFLAGS} -c -o ${BINDIR}/ps_white_write.o ps_white_write.c

${BINDIR}/ps_white_read.o: ps_white_read.c
	${CC} ${CFLAGS} -c -o ${BINDIR}/ps_white_read.o ps_white_read.c
