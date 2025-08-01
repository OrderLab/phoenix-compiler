#ifndef __PHX_INSTRUMENT_H__
#define __PHX_INSTRUMENT_H__

#ifdef __cplusplus
#include <cstdbool>
#else
#include <stdbool.h>
#endif

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

extern bool phx_has_auto_unsafe(void);
extern bool phx_auto_is_unsafe(void);
extern void phx_debug_unsafe_range(void);
extern int phx_pthread_create_wrapper(pthread_t *thread, const pthread_attr_t *attr,
    void *(*start_routine)(void *), void *arg);
extern void __phx_instrument_init_thread(void);

#define phx_instrument_init_main __phx_instrument_init_thread

#ifdef __cplusplus
}
#endif

#endif /* __PHX_INSTRUMENT_H__ */
