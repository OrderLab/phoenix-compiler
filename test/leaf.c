// Simple file with basic call-relationship and CFG

#include <stdlib.h>
#include <stdio.h>

int global;

struct arg {
    int t;
};
struct arg aaa = { 101 };
/* struct arg aaa = { 1 }; */

void phx_handler(int sig);

#define crash() (*(int*)NULL = 33989)

__attribute__((noinline))
struct arg *modify(struct arg *a) {
    int x = 10;
    // range start here
    a->t = 100;
    x += 5;
    a->t++;
    crash();
    // range stop here
    x += 3;
    return a;
}

__attribute__((noinline))
int caller(struct arg *a) {
    int x = -10;
    // range start here
    struct arg *y = modify(a);
    /* crash(); */
    x -= 5;
    y->t += 77;
    // range stop here
    x -= 3;
    return 10;
}

__attribute__((noinline))
struct arg *flow(struct arg *a) {
    int x = 10;

    if (a->t > 100) {
        while (a->t > 100) {
            --a->t;
        }
        /* crash(); */
    } else {
        while (a->t < 20) {
            ++a;
            if (a->t < 10) {
                /* crash(); */
                a->t = 0;
                return a;
            }
        }
    }

    return a;
}

// TODO change to thread-local malloced self-growing array
#define __phx_storage_len 128
volatile unsigned char *__phx_func_state_storage[__phx_storage_len];
volatile unsigned char *volatile *__phx_func_state_array_ptr = __phx_func_state_storage;
size_t __phx_func_state_top = 0, __phx_func_state_max = __phx_storage_len;

void phx_handler(int sig) {
    fprintf(stderr, "__phx_func_state_top = %lu\n", __phx_func_state_top);

    for (size_t i = 0; i < __phx_func_state_top; ++i) {
        fprintf(stderr, "__phx_func_state_array_ptr[%lu] = { ", i);
        for (size_t j = 0; j < 1; ++j)
            fprintf(stderr, "%hhx, ", __phx_func_state_array_ptr[i][j]);
        fprintf(stderr, "}\n");
    }
    exit(1);
}

int main() {
    signal(SIGSEGV, phx_handler);
    flow(&aaa);
    caller(&aaa);
    printf("exit successfully %lu\n", __phx_func_state_top);
}
