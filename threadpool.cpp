#include "ThreadPool.h"
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <iostream>
#include "log_lib_cplus.h"
#include "sock5proxy.h"
#include <sys/time.h>
using namespace std;
extern CLog workerThreadlog;
void *workerThread(void *arg);

ThreadPool::ThreadPool(int threadsLimit) : _valid(true), _count(0), _idle(0), _quit(0), _threadsLimit(threadsLimit)
{
    _valid = true;
	// 接下来初始化一系列变量，失败就false
    if (pthread_mutex_init(&_mutex, nullptr) != 0) 
    {
        perror("pthread_mutex_init");
        _valid = false;
    }

    if (pthread_cond_init(&_cond, nullptr) != 0) 
    {
        perror("pthread_cond_init");
        _valid = false;
    }

    if (pthread_attr_init(&_attr) != 0) 
    {
        perror("pthread_attr_init");
        _valid = false;
    }

    if (pthread_attr_setdetachstate(&_attr, PTHREAD_CREATE_DETACHED) != 0) 
    {
        perror("pthread_attr_setdetachstate");
        _valid = false;
    }

    pthread_t tid;
    for (int i=0; i<_threadsLimit; i++)
    {
         pthread_create(&tid, &_attr, workerThread, this); 
    }
}

ThreadPool::~ThreadPool()
{
    if (_quit)
        return;

    pthread_mutex_lock(&_mutex);
    _quit = 1;

    if (_count > 0) 
    {
        if (_idle > 0) 
        {
            printf("idle[%d] count[%d]\n", _idle, _count);

            // 唤醒休眠的线程
            pthread_cond_broadcast(&_cond);
        }

        while (_count) 
        {
            printf("count[%d] idle[%d]\n", _count, _idle);

            // 最后一个线程退出的时候会发送信号
            pthread_cond_wait(&_cond, &_mutex);
        }
    }

    pthread_mutex_unlock(&_mutex);

    if ((pthread_mutex_destroy(&_mutex)) != 0) 
    {
        perror("pthread_mutex_destroy");
    }

    if ((pthread_cond_destroy(&_cond)) != 0) 
    {
        perror("pthread_cond_destroy");
    }

    if ((pthread_attr_destroy(&_attr)) != 0) 
    {
        perror("pthread_cond_destroy");
    }
}

// 工作线程
void *workerThread(void *arg)
{
   
    ThreadPool *pool = (ThreadPool *)arg;
   logDebug(workerThreadlog, "workerThread func function\n");
    for (;;) 
    {
        pthread_mutex_lock(&pool->_mutex);
        while (pool->_tasks.empty()) 
        {
            pthread_cond_wait(&pool->_cond, &pool->_mutex);
        }

        ThreadPool::ThreadTask task = pool->_tasks.front();
        pool->_tasks.pop();
         pthread_mutex_unlock(&pool->_mutex);

        struct timeval start;
        struct timeval end;
        float time_use=0;

        gettimeofday(&start,NULL); //gettimeofday(&start,&tz);结果一样
        StSockInfo *info = (StSockInfo *)task.arg;
        int seq = info->seq;
        task.task(task.arg);
        gettimeofday(&end,NULL); //gettimeofday(&start,&tz);结果一样
        time_use=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;//微秒
        logDebug(workerThreadlog, "workerThread function need  %.6f ms seq=%d\n",time_use, seq);
    }

    return nullptr;
}

void ThreadPool::addTask(function task, void *arg)
{
    if (!_valid || task == nullptr)
        return;
    pthread_mutex_lock(&_mutex);
    ThreadTask t(task, arg);
    _tasks.emplace(t);
    pthread_mutex_unlock(&_mutex);
    pthread_cond_signal(&_cond);
}
