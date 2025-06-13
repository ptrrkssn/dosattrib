/*
 * dosattrib.c
 *
 * Copyright (c) 2025 Peter Eriksson <pen@lysator.liu.se>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "config.h"

#define _XOPEN_SOURCE 800

#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ftw.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#if defined(HAVE_SYS_EXTATTR_H) /* FreeBSD */
#  include <sys/extattr.h>
#  define DOSATTRIBNAME "DOSATTRIB"
#elif defined(HAVE_SYS_XATTR_H) /* Linux & MacOS */
#  include <sys/xattr.h>
#  define DOSATTRIBNAME "user.DOSATTRIB"
#elif define(HAVE_ATTROPEN)     /* Solaris */
#  define DOSATTRIBNAME "user.DOSATTRIB"
#endif

int f_update = 1;
int f_verbose = 0;
int f_recurse = 0;

uint16_t f_andattribs = 0xFFFF;
uint16_t f_orattribs = 0;
uint16_t f_searchattribs = 0;

char *argv0;


#define FILE_ATTRIBUTE_INVALID 		0x0000L
#define FILE_ATTRIBUTE_READONLY		0x0001L
#define FILE_ATTRIBUTE_HIDDEN		0x0002L
#define FILE_ATTRIBUTE_SYSTEM		0x0004L

#define FILE_ATTRIBUTE_VOLUME		0x0008L
#define FILE_ATTRIBUTE_DIRECTORY	0x0010L

#define FILE_ATTRIBUTE_ARCHIVE		0x0020L
#define FILE_ATTRIBUTE_DEVICE		0x0040L
#define FILE_ATTRIBUTE_NORMAL		0x0080L
#define FILE_ATTRIBUTE_TEMPORARY	0x0100L
#define FILE_ATTRIBUTE_SPARSE		0x0200L
#define FILE_ATTRIBUTE_REPARSE_POINT	0x0400L
#define FILE_ATTRIBUTE_COMPRESSED	0x0800L
#define FILE_ATTRIBUTE_OFFLINE		0x1000L
#define FILE_ATTRIBUTE_NONINDEXED	0x2000L
#define FILE_ATTRIBUTE_ENCRYPTED	0x4000L
#define FILE_ATTRIBUTE_INTEGRITY	0x8000L
#define FILE_ATTRIBUTE_ALL_MASK 	0x7FFFL

struct attr {
    uint16_t a;
    char c;
} attribs[] = {
    { FILE_ATTRIBUTE_READONLY,      'R' },
    { FILE_ATTRIBUTE_HIDDEN,        'H' },
    { FILE_ATTRIBUTE_SYSTEM,        'S' },
    { FILE_ATTRIBUTE_VOLUME,        'v' },
    { FILE_ATTRIBUTE_DIRECTORY,     'D' },
    { FILE_ATTRIBUTE_ARCHIVE,       'A' },
    { FILE_ATTRIBUTE_DEVICE,        'd' },
    { FILE_ATTRIBUTE_NORMAL,        'N' },
    { FILE_ATTRIBUTE_TEMPORARY,     'T' },
    { FILE_ATTRIBUTE_SPARSE,        's' },
    { FILE_ATTRIBUTE_REPARSE_POINT, 'L' },
    { FILE_ATTRIBUTE_COMPRESSED,    'C' },
    { FILE_ATTRIBUTE_OFFLINE,       'O' },
    { FILE_ATTRIBUTE_NONINDEXED,    'I' },
    { FILE_ATTRIBUTE_ENCRYPTED,     'E' },
    { FILE_ATTRIBUTE_INTEGRITY,     'V' },
    { 0, 0 },
};

int
str2attrib(uint16_t *ap,
	   char *s) {
    uint16_t a = 0;
    int i;
    
    if (!s || !*s)
	return 0;
    
    for (; *s; ++s) {
	for (i = 0; attribs[i].a && attribs[i].c != *s; i++)
	    ;
	if (!attribs[i].a)
	    return -1;
	a |= attribs[i].a;
    }
    
    *ap = a;
    return 1;
}

char *
attrib2str(uint16_t a) {
    static char buf[64], *bp;
    int i;
	
    bp = buf;
    for (i = 0; attribs[i].a; i++)
	if (attribs[i].a & a)
	    *bp++ = attribs[i].c;
    
    return buf;
}

typedef union {
    struct {
	uint16_t version;
	uint32_t attrib;
	uint32_t ea_size;
	uint64_t size;
	uint64_t alloc_size;
	uint64_t create_time;
	uint64_t change_time;
    } dosinfo_1; /* 40 bytes */
    struct {
	uint16_t version;
	uint32_t flags;
	uint32_t attrib;
	uint32_t ea_size;
	uint64_t size;
	uint64_t alloc_size;
	uint64_t create_time;
	uint64_t change_time;
	uint64_t write_time;
    } dosinfo_2; /* 50 bytes */
    struct {
	uint16_t version;
	uint32_t valid_flags;
	uint32_t attrib;
	uint32_t ea_size;
	uint64_t size;
	uint64_t alloc_size;
	uint64_t create_time;
	uint64_t change_time;
    } dosinfo_3; /* 44 bytes */
    struct {
	uint16_t version;
	uint32_t valid_flags;
	uint32_t attrib;
	uint64_t itime;
	uint64_t create_time;
    } dosinfo_4; /* 26 bytes */
    struct {
	uint16_t version;
	uint32_t valid_flags;
	uint32_t attrib;
	uint64_t create_time;
    } dosinfo_5; /* 18 bytes */
} DOSATTRIB;

/*
  # Fails:
  # Documents    [32] 00 00 04 00 04 00 00 00 51 00 00 00 11 00 00 00 9e 55 d7 72 85 12 d8 01 9e 55 d7 72 85 12 d8 01
  #  
  # Works:
  # ThisOneWorks [24] 00 00 05 00 05 00 00 00 11 00 00 00 10 00 00 00 da a0 fc 93 fc ce db 01
  # Desktop      [24] 00 00 05 00 05 00 00 00 11 00 00 00 30 00 00 00 c0 b7 36 87 73 1d d3 01
*/

void
spin(void) {
    static time_t last;
    time_t now;
    char dials[] = "|/-\\";
    static int p = 0;

    time(&now);
    if (now != last) {
	fputc(dials[p++%4], stderr);
	fputc('\b', stderr);
	last = now;
    }
}

int
get_uint16(uint16_t *vp,
	   unsigned char **bp,
	   ssize_t *bs) {
    int i;
  
    if (*bs < 2)
	return -1;
    if (!*bs)
	return 0;

    *vp = 0;
    for (i = 0; i < 2; i++) {
	*vp <<= 8;
	*vp |= (*bp)[0];
	++(*bp);
	--(*bs);
    }
    return 1;
}

int
get_uint32(uint32_t *vp,
	   unsigned char **bp,
	   ssize_t *bs) {
    int i;
  
    if (*bs < 4)
	return -1;
    if (!*bs)
	return 0;
    *vp = 0;
    for (i = 0; i < 4; i++) {
	*vp <<= 8;
	*vp |= (*bp)[0];
	++(*bp);
	--(*bs);
    }
    return 1;
}

int
get_uint64(uint64_t *vp,
	   unsigned char **bp,
	   ssize_t *bs) {
    int i;
  
    if (*bs < 8)
	return -1;
    if (!*bs)
	return 0;
    *vp = 0;
    for (i = 0; i < 8; i++) {
	*vp <<= 8;
	*vp |= (*bp)[0];
	++(*bp);
	--(*bs);
    }
    return 1;
}

int
put_uint16(uint16_t v,
	   unsigned char **bp,
	   size_t *bs) {
    int i;
  
    if (*bs < 2)
	return -1;

    for (i = 1; i >= 0; i--) {
	(*bp)[i] = v&0xFF;
	v >>= 8;
    }
    (*bp) += 2;
    (*bs) -= 2;
    return 0;
}

int
put_uint32(uint32_t v,
	   unsigned char **bp,
	   size_t *bs) {
    int i;
  
    if (*bs < 4)
	return -1;

    for (i = 3; i >= 0; i--) {
	(*bp)[i] = v&0xFF;
	v >>= 8;
    }
    (*bp) += 4;
    (*bs) -= 4;
    return 0;
}

int
put_uint64(uint64_t v,
	   unsigned char **bp,
	   size_t *bs) {
    int i;
  
    if (*bs < 8)
	return -1;

    for (i = 7; i >= 0; i--) {
	(*bp)[i] = v&0xFF;
	v >>= 8;
    }
    (*bp) += 8;
    (*bs) -= 8;
    return 0;
}



int
parse_dosattrib(DOSATTRIB *da,
		unsigned char *bp,
		ssize_t bs,
		size_t *rlen) {
    uint16_t version = 0;

    if (bs > 2 && bp[0] == '0' && bp[1] == 'x' && isxdigit(bp[2])) {
	bp += 2;
	bs -= 2;
	if (sscanf((char *) bp, "%x", &da->dosinfo_2.attrib) != 1)
	    return -1;
	while (bs > 0 && isxdigit(*bp)) {
	    ++bp;
	    --bs;
	}
    }
  
    if (bs > 0 && bp[0] == '\0') {
	++bp;
	--bs;
    }
    if (!bs)
	return 0;
  
    if (bs < 2)
	return -2;

    get_uint16(&version, &bp, &bs);
  
    switch (version) {
    case 1:
	get_uint16(&da->dosinfo_1.version, &bp, &bs);
	get_uint32(&da->dosinfo_1.attrib, &bp, &bs);
	get_uint32(&da->dosinfo_1.ea_size, &bp, &bs);
	get_uint64(&da->dosinfo_1.size, &bp, &bs);
	get_uint64(&da->dosinfo_1.alloc_size, &bp, &bs);
	get_uint64(&da->dosinfo_1.create_time, &bp, &bs);
	get_uint64(&da->dosinfo_1.change_time, &bp, &bs);
	break;
    case 2:
	get_uint16(&da->dosinfo_2.version, &bp, &bs);
	get_uint32(&da->dosinfo_2.flags, &bp, &bs);
	get_uint32(&da->dosinfo_2.attrib, &bp, &bs);
	get_uint32(&da->dosinfo_2.ea_size, &bp, &bs);
	get_uint64(&da->dosinfo_2.size, &bp, &bs);
	get_uint64(&da->dosinfo_2.alloc_size, &bp, &bs);
	get_uint64(&da->dosinfo_2.create_time, &bp, &bs);
	get_uint64(&da->dosinfo_2.change_time, &bp, &bs);
	get_uint64(&da->dosinfo_2.write_time, &bp, &bs);
	break;
    case 3:
	get_uint16(&da->dosinfo_3.version, &bp, &bs);
	get_uint32(&da->dosinfo_3.valid_flags, &bp, &bs);
	get_uint32(&da->dosinfo_3.attrib, &bp, &bs);
	get_uint32(&da->dosinfo_3.ea_size, &bp, &bs);
	get_uint64(&da->dosinfo_3.size, &bp, &bs);
	get_uint64(&da->dosinfo_3.alloc_size, &bp, &bs);
	get_uint64(&da->dosinfo_3.create_time, &bp, &bs);
	get_uint64(&da->dosinfo_3.change_time, &bp, &bs);
	break;
    case 4:
	get_uint16(&da->dosinfo_4.version, &bp, &bs);
	get_uint32(&da->dosinfo_4.valid_flags, &bp, &bs);
	get_uint32(&da->dosinfo_4.attrib, &bp, &bs);
	get_uint64(&da->dosinfo_4.itime, &bp, &bs);
	get_uint64(&da->dosinfo_4.create_time, &bp, &bs);
	break;
    case 5:
	get_uint16(&da->dosinfo_5.version, &bp, &bs);
	get_uint32(&da->dosinfo_5.valid_flags, &bp, &bs);
	get_uint32(&da->dosinfo_5.attrib, &bp, &bs);
	get_uint64(&da->dosinfo_5.create_time, &bp, &bs);
	break;
    default:
	return -3;
    }

    *rlen = bs;
    return version;
}

int
put_hex(unsigned char **bp,
	size_t *bs,
	uint64_t v,
	size_t vs) {
    int i;
    
    if (*bs < 5)
	return -1;

    *(*bp)++ = '0';
    *(*bp)++ = 'x';

    for (i = vs-1; i >= 0; i--) {
	unsigned char c = (v&0xF);
	
	(*bp)[i] = (c > 0xA ? c-0xA+'A' : c+'0');
    }
    (*bp) += vs;
    *(*bp) = '\0';
    *bs -= 3+vs;
    
    return 0;
}

ssize_t
create_dosattrib(DOSATTRIB *da,
		 int version,
		 unsigned char *buf,
		 size_t bs) {
    unsigned char *bp = buf;
    
    switch (version) {
    case 2:
	put_hex(&bp, &bs, da->dosinfo_2.attrib, sizeof(da->dosinfo_2.attrib));
	break;
    case 3:
	put_hex(&bp, &bs, da->dosinfo_3.attrib, sizeof(da->dosinfo_3.attrib));
	break;
    }
    
    if (bs < 1)
	return -1;
    
    *bp++ = '\0';
    bs--;
    
    put_uint16(version, &bp, &bs);
  
    switch (version) {
    case 1:
	put_uint16(da->dosinfo_1.version, &bp, &bs);
	put_uint32(da->dosinfo_1.attrib, &bp, &bs);
	put_uint32(da->dosinfo_1.ea_size, &bp, &bs);
	put_uint64(da->dosinfo_1.size, &bp, &bs);
	put_uint64(da->dosinfo_1.alloc_size, &bp, &bs);
	put_uint64(da->dosinfo_1.create_time, &bp, &bs);
	put_uint64(da->dosinfo_1.change_time, &bp, &bs);
	break;
    case 2:
	put_uint16(da->dosinfo_2.version, &bp, &bs);
	put_uint32(da->dosinfo_2.flags, &bp, &bs);
	put_uint32(da->dosinfo_2.attrib, &bp, &bs);
	put_uint32(da->dosinfo_2.ea_size, &bp, &bs);
	put_uint64(da->dosinfo_2.size, &bp, &bs);
	put_uint64(da->dosinfo_2.alloc_size, &bp, &bs);
	put_uint64(da->dosinfo_2.create_time, &bp, &bs);
	put_uint64(da->dosinfo_2.change_time, &bp, &bs);
	put_uint64(da->dosinfo_2.write_time, &bp, &bs);
	break;
    case 3:
	put_uint16(da->dosinfo_3.version, &bp, &bs);
	put_uint32(da->dosinfo_3.valid_flags, &bp, &bs);
	put_uint32(da->dosinfo_3.attrib, &bp, &bs);
	put_uint32(da->dosinfo_3.ea_size, &bp, &bs);
	put_uint64(da->dosinfo_3.size, &bp, &bs);
	put_uint64(da->dosinfo_3.alloc_size, &bp, &bs);
	put_uint64(da->dosinfo_3.create_time, &bp, &bs);
	put_uint64(da->dosinfo_3.change_time, &bp, &bs);
	break;
    case 4:
	put_uint16(da->dosinfo_4.version, &bp, &bs);
	put_uint32(da->dosinfo_4.valid_flags, &bp, &bs);
	put_uint32(da->dosinfo_4.attrib, &bp, &bs);
	put_uint64(da->dosinfo_4.itime, &bp, &bs);
	put_uint64(da->dosinfo_4.create_time, &bp, &bs);
	break;
    case 5:
	put_uint16(da->dosinfo_5.version, &bp, &bs);
	put_uint32(da->dosinfo_5.valid_flags, &bp, &bs);
	put_uint32(da->dosinfo_5.attrib, &bp, &bs);
	put_uint64(da->dosinfo_5.create_time, &bp, &bs);
	break;
    default:
	return -1;
    }

    while (bs&3) {
	*bp++ = '\0';
	bs--;
    }
    return bp-buf;
}


int
walker(const char *path,
       const struct stat *sp,
       int type,
       struct FTW *fp) {
    ssize_t len, nlen;
    size_t rlen;
    DOSATTRIB da;
    unsigned char oblob[64], nblob[64];
    int version;
    uint16_t oa, na;
#if defined(HAVE_ATTROPEN)
    int fd;
#endif
    

    switch (type) {
    case FTW_DNR:
    case FTW_NS:
	fprintf(stderr, "%s: Error: %s: Unable to access\n",
		argv0, path);
	return -1;
    }
    
    spin();

    memset(oblob, 0, sizeof(oblob));
    
    memset(&da, 0, sizeof(da));
#if defined(HAVE_EXTATTR_GET_LINK)
    /* FreeBSD */
    len = extattr_get_link(path, EXTATTR_NAMESPACE_USER, DOSATTRIBNAME,
			   oblob, sizeof(oblob));
#elif defined(HAVE_LGETXATTR)
    /* Linux */
    len = lgetxattr(path, DOSATTRIBNAME, oblob, sizeof(oblob));
#elif defined(HAVE_GETXATTR)
    /* MacOS */
    len = getxattr(path, DOSATTRIBNAME, oblob, sizeof(oblob), 0, XATTR_NOFOLLOW);
#elif defined(HAVE_ATTROPEN)
    /* Solaris */
    fd = attropen(path, DOSATTRIBNAME, O_RDONLY);
    if (fd < 0)
	return -1;
    len = read(fd, oblob, sizeof(oblob));
    close(fd);
#else
    errno = ENOSYS;
    return -1;
#endif
    if (len < 0)
	return 0;

    rlen = 0;
    version = parse_dosattrib(&da, oblob, len, &rlen);
    
    switch (version) {
    case 1:
	oa = da.dosinfo_1.attrib;
	break;
    case 2:
	oa = da.dosinfo_2.attrib;
	break;
    case 3:
	oa = da.dosinfo_3.attrib;
	break;
    case 4:
	oa = da.dosinfo_4.attrib;
	break;
    case 5:
	oa = da.dosinfo_5.attrib;
	break;
    default:
	errno = EINVAL;
	return -1;
    }

    na = oa;
    if (f_orattribs != 0)
	na |= f_orattribs;
    if (f_andattribs != 0xFFFF)
	na &= f_andattribs;
    
    /* Sanity check real type vs attribute type */
    if ((type == FTW_D || type == FTW_DP) &&
	(na & FILE_ATTRIBUTE_DIRECTORY) == 0) {
	na |= FILE_ATTRIBUTE_DIRECTORY;
    } else if (type == FTW_F &&
	       (na & FILE_ATTRIBUTE_DIRECTORY) != 0) {
	na &= ~FILE_ATTRIBUTE_DIRECTORY;
    }
    
    if (f_verbose || na != oa || (f_searchattribs & oa) != 0) {
	printf("%s: %s", path, attrib2str(oa));
    
	if (f_verbose > 1)
	    printf(" (0x%02x)", oa);
	if (f_verbose > 2) {
	    int i;
	    
	    putchar(':');
	    for (i = 0; i < len; i++)
		printf(" %02x", oblob[i]);
	}
	
	
	if (na != oa) {
	    printf(" -> %s", attrib2str(na));
	    if (f_verbose > 1)
		printf(" (0x%02x)", na);

	    switch (version) {
	    case 1:
		da.dosinfo_1.attrib = na;
		break;
	    case 2:
		da.dosinfo_2.attrib = na;
		break;
	    case 3:
		da.dosinfo_3.attrib = na;
		break;
	    case 4:
		da.dosinfo_4.attrib = na;
		break;
	    case 5:
		da.dosinfo_5.attrib = na;
		break;
	    }

	    nlen = create_dosattrib(&da, version, nblob, sizeof(nblob));
	    if (f_verbose > 2) {
		int i;
		
		for (i = 0; i < nlen; i++)
		    printf(" %02x", nblob[i]);
	    }
	    
	    if (f_update) {
#if defined(HAVE_EXTATTR_SET_LINK) /* FreeBSD */
		len = extattr_set_link(path, EXTATTR_NAMESPACE_USER, DOSATTRIBNAME, nblob, nlen);
#elif defined(HAVE_LGETXATTR) /* Linux */
		len = lsetxattr(path, DOSATTRIBNAME, oblob, sizeof(oblob), 0);
#elif defined(HAVE_GETXATTR) /* MacOS */
		len = setxattr(path, DOSATTRIBNAME, oblob, sizeof(oblob), 0, XATTR_NOFOLLOW);
#elif defined(HAVE_ATTROPEN) /* Solaris */
		fd = attropen(path, DOSATTRIBNAME, O_WRONLY);
		if (fd < 0)
		    return -1;
		len = write(fd, nblob, nlen);
		close(fd);
#else
		errno = ENOSYS;
		wlen = -1;
#endif
		if (len == nlen)
		    printf(": Updated");
		else
		    printf(": Update Failed: %s", strerror(errno));
	    } else {
		printf(": (NOT) Updated");
	    }
	}
	
	putchar('\n');
    }
    return 0;
}

int
main(int argc,
     char *argv[]) {
    int i, j, rc = 0;
    char *ap = NULL;
    uint16_t a;

    argv0 = argv[0];
    
    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
	for (j = 1; argv[i][j]; j++)
	    switch (argv[i][j]) {
	    case 'h':
		printf("Usage:\n\t%s [-hvrn] [-A<attribs>] [-U<attribs>] <path-1> [.. <path-N>]\n",
		       argv[0]);
		exit(0);
	    case 'v':
		f_verbose++;
		break;
	    case 'r':
		f_recurse++;
		break;
	    case 'n':
		f_update = 0;
		break;
		
	    case 'S':
		if (argv[i][j+1])
		    rc = str2attrib(&a, ap = argv[i]+j+1);
		else if (i+1 < argc)
		    rc = str2attrib(&a, ap = argv[++i]);
		else
		    rc = 0;
		if (rc == 0) {
		    fprintf(stderr, "%s: Error: -S: Missing argument\n",
			    argv[0]);
		    exit (1);
		} else if (rc < 0) {
		    fprintf(stderr, "%s: Error: %s: Invalid argument for -S\n",
			    argv[0], ap);
		    exit (1);
		}
		f_searchattribs |= a;
		goto NextArg;
		
	    case 'A':
		if (argv[i][j+1])
		    rc = str2attrib(&a, ap = argv[i]+j+1);
		else if (i+1 < argc)
		    rc = str2attrib(&a, ap = argv[++i]);
		else
		    rc = 0;
		if (rc == 0) {
		    fprintf(stderr, "%s: Error: -A: Missing argument\n",
			    argv[0]);
		    exit (1);
		} else if (rc < 0) {
		    fprintf(stderr, "%s: Error: %s: Invalid argument for -A\n",
			    argv[0], ap);
		    exit (1);
		}
		f_orattribs |= a;
		goto NextArg;
		
	    case 'U':
		if (argv[i][j+1])
		    rc = str2attrib(&a, ap = argv[i]+j+1);
		else if (i+1 < argc)
		    rc = str2attrib(&a, ap = argv[++i]);
		else
		    rc = 0;
		if (rc == 0) {
		    fprintf(stderr, "%s: Error: -U: Missing argument\n",
			    argv[0]);
		    exit (1);
		} else if (rc < 0) {
		    fprintf(stderr, "%s: Error: %s: Invalid argument for -U\n",
			    argv[0], ap);
		    exit (1);
		}
		f_andattribs &= ~a;
		goto NextArg;

	    case '-':
		++i;
		goto EndArg;
		
	    default:
		fprintf(stderr, "%s: Error: -%c: Invalid switch\n",
			argv[0], argv[i][j]);
		exit(1);
	    }
    NextArg:;
    }
 EndArg:;
    
    for (; i < argc; i++)
	if (f_recurse) {
	    rc = nftw(argv[i], walker, 9999, FTW_PHYS);
	    if (rc < 0)
		goto Fail;
	} else {
	    struct stat sb;
	    struct FTW ftw;
	    
	    rc = lstat(argv[i], &sb);
	    if (rc < 0)
		goto Fail;

	    ftw.base = 0;
	    ftw.level = 0;
	    rc = walker(argv[i], &sb, S_ISDIR(sb.st_mode) ? FTW_D : FTW_F, &ftw);
	    if (rc != 0)
		goto Fail;
	}

 Fail:
    return (rc == 0 ? 0 : 1);
}
