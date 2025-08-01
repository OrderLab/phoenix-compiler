// Simple file with basic call-relationship and CFG

#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(INLINE_RUNTIME) && INLINE_RUNTIME == 1
#define IN_PHX_RUNTIME
#endif // INLINE_RUNTIME

#include "../include/phx_instrument.h"

int global;

struct arg {
    int t;
    int *ptr;
};
struct arg aaa = { 101, &global };
/* struct arg aaa = { 1 }; */

void phx_handler(int sig);

int *faultptr = NULL;
#define crash() (*faultptr = 33989)


/* Simple straight control flow with only one pointer.
 * Argument effect: [0: <ReturnTaint::POINTER, ModifyType::MAY_MODIFY>]
 */
__attribute__((noinline))
struct arg *modify(struct arg *a) {
    // PROLOGUE
    // local = { flcallee_done = false, { UNMODIFIED } }
    // oldtop = load phxtop
    // newtop = oldtop + 1;
    // store *newtop = &local
    // store phxtop = newtop;

    int x = 10;
    // range start here
    // local[0] = MODIFYING
    // NOTE: this translates to:
    //     %at = getelementptr inbounds %struct.arg, %struct.arg* %a, i32 0, i32 0
    //   unsafe range should start here!
    //     store i32 100, i32* %at
    a->t = 100;
    x += 5;
    a->t++;
    // range end here
    // local[0] = MODIFY_END

    /* crash(); */
    x += 3;

    // EPILOGUE:
    // (*oldtop)->flcallee_done = true
    // store phxtop = oldtop
    return a;
}

__attribute__((noinline))
struct arg *modify_rebind_struct(struct arg *a) {
    struct localstore {
        int *x;
    } b;

    b.x = &a->t;

    // unsafe should start here
    *b.x = 100;
    // unsafe should end here

    return a;
}

__attribute__((noinline))
struct arg *modify_rebind_var(struct arg *a) {
    int *x;

    x = &a->t;

    // unsafe should start here
    *x = 100;
    // unsafe should end here

    return a;
}

/* Example case that
 * Argument effect: [0: <ReturnTaint::PURE, ModifyType::MAY_MODIFY>]
 */
__attribute__((noinline))
int caller(struct arg *a) {
    // PROLOGUE
    // local = { flcallee_done = false, { UNMODIFIED } }
    // oldtop = load phxtop
    // newtop = oldtop + 1;
    // store *newtop = &local
    // store phxtop = newtop;

    int x = -10;

    // range start here
    // local.flcallee_done = false
    // local[0] = FCALL
    struct arg *y = modify(a);
    // local[0] = MODIFYING

    /* crash(); */
    x -= 5;
    y->t += 77;
    // range end here
    // local[0] = MODIFY_END

    x -= 3;

    // EPILOGUE:
    // (*oldtop)->flcallee_done = true
    // store phxtop = oldtop
    return 10;
}

__attribute__((noinline))
int caller_loop(struct arg *a) {
    int x = -10;

    struct arg *y;

    for (int i = 0; i < 10; ++i) {
        y = modify(a);
    }

    x -= 5;
    y->t += 77;
    // range end here
    // local[0] = MODIFY_END

    x -= 3;

    // EPILOGUE:
    // (*oldtop)->flcallee_done = true
    // store phxtop = oldtop
    return 10;
}

// TODO: cannot handle pass struct, because llvm declares arg as "[2 x i64] %0",
// while GEP is on "%struct.arg".
void passvalue(struct arg a) {
    *a.ptr = 0xdeadbeaf;
}

void nested(struct arg *a) {
    while (a->t < 100) {
        for (int i = 0; i < 10; ++i)
            ;

        while (a->t < 100) {
            a->t++;
        }
    }
}

/* Example case with complex control flow.
 *
 * Should return POINTER
 */
__attribute__((noinline))
struct arg *flow(struct arg *a) {
    // PROLOGUE:
    // local = { flcallee_done = false, { UNMODIFIED } }
    // oldtop = load phxtop
    // newtop = oldtop + 1;
    // store *newtop = &local
    // store phxtop = newtop;

    int x = 10;

    /* Limitaiton: if a->t is in [20,100], there is a path of no modification,
     * we still consider the whole function as modify! Drawback is that unsafe
     * points are always static and can't be dynamic.
     */

    if (a->t > 100) {
        while (a->t > 100) {
            // range start here
            // local[0] = MODIFYING
            --a->t;
        }
        // range end here
        // local[0] = MODIFY_END

        /* crash(); */
    } else {
        while (a->t < 20) {
            ++a;    // not here!
            if (a->t < 10) {
                // range start here
                // local[0] = MODIFYING

                /* crash(); */
                a->t = 0;

                // range end here
                // local[0] = MODIFY_END
                // NOTE: In LLVM, this is turned into a jump to the single sink
                // goto sink
                return a;
            }
        }
    }
    // sink:
    // EPILOGUE:
    // (*oldtop)->flcallee_done = true
    // store phxtop = oldtop
    return a;
}

void phx_handler(int sig) {
    (void)sig;
    fprintf(stderr, "Entering phx_handler...\n");
    phx_debug_unsafe_range();
    if (!phx_has_auto_unsafe()) {
        fprintf(stderr, "phx_handler: phx auto unsafe region not supported, fallback to regular restart.\n");
        exit(3);
    }
    if (phx_auto_is_unsafe()) {
        fprintf(stderr, "phx_handler: seems in unsafe region\n");
        exit(2);
    }
    fprintf(stderr, "phx_handler: seems safe\n");
    exit(1);
}

int main() {
    // called automatically:
    // phx_instrument_init_main();

    signal(SIGSEGV, phx_handler);

    pthread_t t;
    pthread_create(&t, NULL, (void *(*)(void *))flow, &aaa);
    usleep(10);

    flow(&aaa);
    caller(&aaa);
    passvalue(aaa);
    nested(&aaa);
    caller_loop(&aaa);
    modify_rebind_struct(&aaa);
    modify_rebind_var(&aaa);

    pthread_join(t, NULL);

    printf("main: exit successfully\n");
    phx_debug_unsafe_range();
    return 0;
}

#if defined(INLINE_RUNTIME) && INLINE_RUNTIME == 1
#include "phxruntime.c"
#endif // INLINE_RUNTIME
