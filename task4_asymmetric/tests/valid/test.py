import os
import queue
from threading import Thread

debug = False
worker_queue = queue.Queue()


# streamProject = os.popen('make')
# print(streamProject.read())

def worker():
    while True:
        item = worker_queue.get()
        i = item
        num_of_errors = 0
        for j in range(1):  # number of iterations for the same number of bits
            stream_project = os.popen("./hash {}".format(i))
            stream_project_output = stream_project.read().split()

            stream_test = os.popen('echo -n "{}" | xxd -r -ps | openssl sha384'.format(stream_project_output[0]))
            stream_test_output = stream_test.read().split()

            if stream_project_output[1] != stream_test_output[1]:
                num_of_errors += 1
                if debug:
                    print("ERROR")
                    print("0-bits: {}".format(i))
                    print("iteration: {}".format(j))
                    print("Project output: {}".format(stream_project_output))
                    print("Test output: {}".format(stream_test_output))
            else:
                if debug:
                    print("OK")
                    print("0bits: {}".format(i))
                    print("Input: {}".format(stream_project_output[0]))
                    print("Output: {}".format(stream_project_output[1]))
        if num_of_errors:
            print("{} 0-bits: {} errors".format(i, num_of_errors))
        else:
            print("{} 0-bits: OK".format(i, num_of_errors))

        worker_queue.task_done()


if __name__ == "__main__":
    for j in range(384):
        worker_queue.put(j)

    workers = []
    for _ in range(8):
        workers += [Thread(target=worker)]

    for w in workers:
        w.start()

    for w in workers:
        w.join()
# for i in range(0, 384):
# #for i in range(0, 23):  # number of 0 leading bits
#     numOfErrors = 0
#     for j in range(1):  # number of iterations for the same number of bits
#         streamProject = os.popen("./hash {}".format(i))
#         streamProjectOutput = streamProject.read().split()
#
#         streamTest = os.popen('echo -n "{}" | xxd -r -ps | openssl sha384'.format(streamProjectOutput[0]))
#         streamTestOutput = streamTest.read().split()
#
#         if streamProjectOutput[1] != streamTestOutput[1]:
#             numOfErrors += 1
#             if debug:
#                 print("ERROR")
#                 print("0-bits: {}".format(i))
#                 print("iteration: {}".format(j))
#                 print("Project output: {}".format(streamProjectOutput))
#                 print("Test output: {}".format(streamTestOutput))
#         else:
#             if debug:
#                 print("OK")
#                 print("0bits: {}".format(i))
#                 print("Input: {}".format(streamProjectOutput[0]))
#                 print("Output: {}".format(streamProjectOutput[1]))
#     if numOfErrors:
#         print("{} 0-bits: {} errors".format(i, numOfErrors))
#     else:
#         print("{} 0-bits: OK".format(i, numOfErrors))
