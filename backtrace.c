#define _GNU_SOURCE 

#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <execinfo.h>
#include <string.h>

#include "list_head.h"

#define MAX_FRAME 8

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#endif

struct malloc_hdr {
        void *frame[MAX_FRAME];
	list_t malloc_list;
        int frame_cnt;
        int len;
	int in_list;
        char buf[0];
};

pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t malloc_mutex = PTHREAD_MUTEX_INITIALIZER;

__thread int malloc_status;
int initializing = 0; 

list_t malloc_header;

char tmpbuf[1024];
unsigned long tmppos = 0;
unsigned long tmpallocs = 0;

static void* temp_malloc(size_t size);
static void* temp_calloc(size_t nmemb, size_t size);

static void* (*real_malloc)(size_t size);
static void* (*real_calloc)(size_t nmemb, size_t size);
static void* (*real_realloc)(void *ptr, size_t size);
static void  (*real_free)(void *ptr);

__attribute__((constructor)) static void init(void)
{
	pthread_mutex_lock(&init_mutex);
	if (!initializing) {
		initializing = 1;
		pthread_mutex_unlock(&init_mutex);

		INIT_LIST_HEAD(&malloc_header);
		malloc_status = FALSE;
		
		real_malloc     = dlsym(RTLD_NEXT, "malloc");
		real_calloc	= dlsym(RTLD_NEXT, "calloc");
		real_realloc    = dlsym(RTLD_NEXT, "realloc");
		real_free       = dlsym(RTLD_NEXT, "free");
		
		if (!real_malloc || !real_calloc || !real_realloc || !real_free) {
			exit(1);
		}
		
		pthread_mutex_lock(&init_mutex);
		initializing = 0;
	}
	pthread_mutex_unlock(&init_mutex);

	return;
}

void* temp_malloc(size_t size)
{
	if (tmppos + size >= sizeof(tmpbuf))
		exit(1);
	void *retptr = tmpbuf + tmppos;
	tmppos += size;
	++tmpallocs;
	return retptr;
}

void* temp_calloc(size_t nmemb, size_t size)
{
	void *ptr = temp_malloc(nmemb * size);
	unsigned int i = 0;
	for (; i < nmemb * size; ++i)
		*((char*)(ptr + i)) = '\0';
	return ptr;
}

void* malloc(size_t size)
{
	struct malloc_hdr * hdr = NULL;
	void *p = NULL;
	int recursive_flag;

	if(likely(real_malloc)) {
		hdr = real_malloc(sizeof(struct malloc_hdr) + size);
		if (hdr == NULL)
			return NULL;

		hdr->len = size;
		hdr->in_list = FALSE;
		if(malloc_status == FALSE) {
			malloc_status = TRUE;

			hdr->frame_cnt = __backtrace(hdr->frame, MAX_FRAME);
			hdr->in_list = TRUE;

			pthread_mutex_lock(&list_mutex);
			list_add(&hdr->malloc_list, &malloc_header);
			pthread_mutex_unlock(&list_mutex);

			malloc_status = FALSE;
		}
		p = hdr->buf;
	} else {
		init();
		p = temp_malloc(size);
	}
	return p;
}		

void* calloc(size_t nmemb, size_t size)
{
	struct malloc_hdr * hdr = NULL;
	void *p = NULL;

	if(likely(real_malloc)) {
		hdr = real_malloc(sizeof(struct malloc_hdr) + nmemb * size);
		if (hdr == NULL)
			return NULL;

		hdr->len = size;
		hdr->in_list = FALSE;

		if(malloc_status == FALSE) {
			malloc_status = TRUE;

			hdr->frame_cnt = __backtrace(hdr->frame, MAX_FRAME);
			hdr->in_list = TRUE;

			pthread_mutex_lock(&list_mutex);
			list_add(&hdr->malloc_list, &malloc_header);
			pthread_mutex_unlock(&list_mutex);

			malloc_status = FALSE;
		}
		p = hdr->buf;
	} else {
		init();
		p = temp_calloc(nmemb, size);
	}
	memset(p, 0x0, (size_t)size);
	return p;
}

void* realloc(void *ptr, size_t size)
{
	void *p = NULL;

	if(likely(real_realloc))
		p = real_realloc(ptr, size);
	return p;
}

void free(void *ptr)
{
	if (real_free) {
		if (ptr)
			ptr = container_of(ptr, struct malloc_hdr, buf);
		else 
			return;
		
		if (((struct malloc_hdr *)ptr)->in_list == TRUE) {
			pthread_mutex_lock(&list_mutex);
			list_del(&((struct malloc_hdr *)ptr)->malloc_list);
			pthread_mutex_unlock(&list_mutex);
		}

		real_free(ptr);
	}
        return;
}

void print_list(void)
{
	struct malloc_hdr *pos;
	int fd = 0;

	fd = open("/var/log/glusterfs/memory.log");

	pthread_mutex_lock(&list_mutex);
	list_for_each_entry(pos, &malloc_header, malloc_list)
		__backtrace_symbols_fd(pos->frame, pos->frame_cnt, fd);
	pthread_mutex_unlock(&list_mutex);
	
	close(fd);
	return;
}

__attribute__((destructor)) static void fini(void)
{
	struct malloc_hdr *pos;
	char str[32];
	int cnt = 0;

	pthread_mutex_lock(&list_mutex);
	while(!list_empty(&malloc_header)) {
		pos = list_first_entry(&malloc_header, struct malloc_hdr, malloc_list);
		list_del(&pos->malloc_list);
		pthread_mutex_unlock(&list_mutex);

		//cnt = snprintf(str, 32, "malloc addr %p, len %d\n", pos->buf, pos->len);
		//if (cnt < 0)
		//	goto out;
		//write(stdout, str, cnt);
		__backtrace_symbols_fd(pos->frame, pos->frame_cnt, 1);
		//write(1, '\n', 1);

		//if(likely(real_free))
		//	real_free(pos);
			
		pthread_mutex_lock(&list_mutex);
	}
out:
	pthread_mutex_unlock(&list_mutex);
	return;
}

