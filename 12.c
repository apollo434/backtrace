#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

static int * fun()
{
	int *w = NULL;	
	w = malloc(sizeof(int));
	return w;
}

static void *thread(void)
{
	int *h = NULL;
	h = fun();
	pthread_exit(NULL);
}

int main()
{
	int *l = NULL;
	int *p = NULL;
	pthread_t pd;
	int ret = 0;

	p = malloc(sizeof(int));

	l = fun();
	ret = pthread_create(&pd, NULL, thread, NULL);

	pthread_join(pd, NULL);

	return 0;
}
