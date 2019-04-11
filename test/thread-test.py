#!/usr/bin/python3
# -*- coding: utf-8 -*-


from threading import Thread
from queue import Queue

class Twork(Thread):
    def __init__(self, name, task_list):
        super().__init__(name=name, daemon=True) # daemon
        self.task_list = task_list

    def get_task(self):
        task = self.task_list.get()
        self.task_list.task_done()
        return task

    def run(self):
        print("Start " + self.getName())
        while True:
            task =  self.get_task()
            print("IN " + self.getName())
            task.func(*task.args, **task.kwargs)

class Task:
    def __init__(self, func, args=(), kwargs={}):
        self.func = func
        self.args = args
        self.kwargs = kwargs

class TaskManager:
    def __init__(self, pool_size):
        self.pool_size = pool_size
        self.task_list = Queue()
        for i in range(self.pool_size):
            Twork("thread"+str(i), self.task_list).start()

    def add_task(self, task):
        self.task_list.put(task)

    def run(self):
        self.task_list.join()

if __name__ == '__main__':
    task = Task(print, "test")
    task_manager = TaskManager(3)
    task_manager.add_task(task)

    task_manager.run()






