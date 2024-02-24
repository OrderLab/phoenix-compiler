#include "ThreadPool.h"
#if __cpp_exceptions == 199711
#include <iostream>
#endif

namespace phoenix {

#if 0
#define dprintf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define dprintf(fmt, ...) do {} while (0)
#endif

// Destructor to stop the thread pool
ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        stop_ = true;
    }

    cv_.notify_all();

    for (auto& thread : threads_) {
        thread.join();
    }
}

// Enqueue task for execution by the thread pool
void ThreadPool::enqueue(std::function<void()> &&task) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        tasks_.push(task);
        if (threads_.size() < max_threads && running_ + tasks_.size() > threads_.size())
            threads_.emplace_back([this] { workerFunc(); });
    }
    cv_.notify_one();
}

void ThreadPool::waitBatch() {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    batch_finish_.wait(lock, [this] {
        dprintf("Wait wake: %d\n", stop_ || (running_ == 0 && tasks_.empty()));
        return stop_ || (running_ == 0 && tasks_.empty());
    });
}

void ThreadPool::workerFunc() {
    while (true) {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            cv_.wait(lock, [this] {
                dprintf("Worker wake: stop=%d running=%lu tasks=%lu\n", stop_, running_, tasks_.size());
                return !tasks_.empty() || stop_;
            });
            if (stop_) {
                batch_finish_.notify_all();
                return;
            }
            task = std::move(tasks_.front());
            tasks_.pop();
            ++running_;
        }

        dprintf("task %p started\n", pthread_self());
#if __cpp_exceptions == 199711
        try {
            task();
        } catch (const std::exception& ex) {
            std::cerr << "Phoenix ThreadPool worker saw an exception: " << ex.what() << '\n';
        } catch (...) {
            std::cerr << "Phoenix ThreadPool worker saw an unknown type exception\n";
        }
#else
        task();
#endif
        dprintf("task %p finished\n", pthread_self());

        std::unique_lock<std::mutex> lock(queue_mutex_);
        dprintf("loop tail: stop=%d running=%lu tasks=%lu\n", stop_, running_, tasks_.size());
        --running_;
        if (stop_ || (running_ == 0 && tasks_.empty()))
            batch_finish_.notify_all();
    }
}

} // namespace phoenix

#ifdef PHX_TEST
#include <iostream>

// tests
namespace phoenix_test {

int threadpool_test() {
    using namespace std::chrono;

    phoenix::ThreadPool pool;

    // Enqueue tasks for execution
    for (int i = 0; i < 5; ++i) {
        pool.enqueue([i] {
            fprintf(stderr, "Task %d is running on thread %p\n", i, pthread_self());;
            std::this_thread::sleep_for(100ms);
        });
    }

    fprintf(stderr, "Wait begin\n");
    pool.waitBatch();
    fprintf(stderr, "Wait finished\n");

    return 0;
}

} // namespace phoenix_test
#endif
