import sys

def task1():
    if len(sys.argv) > 1:
        # run the
        # sys.argv[1] # first command line arg
        print("we have cmd args")    
    else:
        print("no command arguments provided")


if __name__ == "__main__":
    task1()
