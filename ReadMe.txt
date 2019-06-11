gcc -shared -ldl -lpthread -fPIC backtrace.c -o backtrace.so
gcc -o test -lpthread  12.c
LD_PRELOAD=./backtrace.so ./test
