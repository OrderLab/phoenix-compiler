/* Thread Pool
 * Derived from https://www.geeksforgeeks.org/thread-pool-in-cpp/
 * and https://github.com/Manoharan-Ajay-Anand/coros/blob/6cf7617677c2ea1926352d5575b9e91606735392/src/coros/async/thread_pool.cpp
 */

#ifndef __THREADPOOL_H__
#define __THREADPOOL_H__

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>

namespace phoenix {

class ThreadPool {
public:
    ThreadPool(size_t max_threads = std::thread::hardware_concurrency())
        : max_threads(max_threads) {}
    ThreadPool(const ThreadPool &other) = delete;
    ThreadPool(ThreadPool &&other) = delete;
    ~ThreadPool();
    ThreadPool &operator=(const ThreadPool &other) = delete;
    ThreadPool &operator=(ThreadPool &&other) = delete;

    void enqueue(std::function<void()> &&task);
    // wait for one batch to finish: either pool exit, or no task is executing and queue empty
    void waitBatch();

private:
    void workerFunc();

private:
    size_t max_threads;
    std::vector<std::thread> threads_;
    std::queue<std::function<void()>> tasks_;

    std::mutex queue_mutex_;

    // Condition variable to signal changes in the state of the tasks queue
    std::condition_variable cv_;

    // Variables to wait for one batch of tasks
    size_t running_ = 0;
    std::condition_variable batch_finish_;

    // Flag to indicate whether the thread pool should stop or not
    bool stop_ = false;
};

} // namespace phoenix

#endif /* __THREADPOOL_H__ */
