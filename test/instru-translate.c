// Source code file used to translate instrumentation code into IR, for
// Instrumenter reference

#include <stdlib.h>
#include <stdio.h>

int global;

volatile unsigned char *volatile *global_array;
size_t array_offset = 77;

struct arg {
    int t;
};

struct arg aaa;

struct arg *modify(struct arg *a);

__attribute__((noinline))
int caller(struct arg *a) {
    unsigned char state[13] = {};
    size_t old_offset = array_offset;
    global_array[old_offset] = state;
    array_offset = old_offset + 1;

    int x = -10;
    // range start here
    struct arg *y = modify(a);
    x -= 5;
    y->t += 77;
    // range stop here
    x -= 3;

    printf("%lu\n", array_offset);
    array_offset--;
    array_offset = old_offset;
    return 10;
}

__attribute__((noinline))
struct arg *modify(struct arg *a) {
    unsigned char state[7] = {};
    size_t old_offset = array_offset;
    global_array[old_offset] = state;
    array_offset = old_offset + 1;

    int x = 10;
    // range start here
    a->t = 100;
    x += 5;
    a->t++;
    // range stop here
    x += 3;

    printf("%lu\n", array_offset);
    array_offset = old_offset;
    return a;
}

__attribute__((noinline))
void simple() {
    volatile unsigned char state[77] = { 0 };
    size_t old_offset = array_offset;
    global_array[old_offset] = state;
    array_offset = old_offset + 1;

    state[9] |= 00002;

    caller(&aaa);

    state[9] &= ~00002;

    printf("%lu\n", array_offset);
    array_offset = old_offset;
}

void init_global_array() {
    global_array = (volatile unsigned char* volatile*)malloc(100 * sizeof(unsigned char*));
}

int main() {
    init_global_array();
    simple();
    printf("%lu\n", array_offset);
}
