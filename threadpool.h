#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>
#include <queue>

class ThreadPool 
{
public:
    typedef void *(*function)(void *);  // 函数指针
    // 定义一个认为Task，包含一个函数指针和参数
    struct ThreadTask 
    {
        function task;  // 函数指针
        void *arg;      // 参数
        ThreadTask(function task, void *arg) : task(task), arg(arg) {}
        ThreadTask() : task(nullptr), arg(nullptr){};
    };

	// 线程个数限制参数
    explicit ThreadPool(int threadsLimit = 20);
    ~ThreadPool();

	// 实际的工作线程，因为pthread_create()函数不能调用类成员函数，所以这里搞成友元函数
    friend void *workerThread(void *arg);

	// 往池子里面添加任务
    void addTask(function task, void *arg);

  private:
    pthread_mutex_t _mutex;
    pthread_cond_t _cond; // 信号弹
    pthread_attr_t _attr;

    std::queue<ThreadTask> _tasks;
    int _count;  // 当前工作线程个数
    int _idle;   // 当前空闲的线程个数
    int _threadsLimit;
    int _quit;  // 退出标识
    bool _valid; // 初始化成功标识
};

#endif  // THREAD_POOL_H
