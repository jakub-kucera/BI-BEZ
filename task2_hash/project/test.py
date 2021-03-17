import os

debug = False

# streamProject = os.popen('make')
# print(streamProject.read())

# for i in range(0, 384):
for i in range(0, 23):  # number of 0 leading bits
    numOfErrors = 0
    for j in range(1):  # number of iterations for the same number of bits
        streamProject = os.popen("./hash {}".format(i))
        streamProjectOutput = streamProject.read().split()

        streamTest = os.popen('echo -n "{}" | xxd -r -ps | openssl sha384'.format(streamProjectOutput[0]))
        streamTestOutput = streamTest.read().split()

        if streamProjectOutput[1] != streamTestOutput[1]:
            numOfErrors += 1
            if debug:
                print("ERROR")
                print("0-bits: {}".format(i))
                print("iteration: {}".format(j))
                print("Project output: {}".format(streamProjectOutput))
                print("Test output: {}".format(streamTestOutput))
        else:
            if debug:
                print("OK")
                print("0bits: {}".format(i))
                print("Input: {}".format(streamProjectOutput[0]))
                print("Output: {}".format(streamProjectOutput[1]))
    if numOfErrors:
        print("{} 0-bits: {} errors".format(i, numOfErrors))
    else:
        print("{} 0-bits: OK".format(i, numOfErrors))
