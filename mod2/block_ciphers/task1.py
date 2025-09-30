import sys

# from cbc import [your function here]
# from ebc import [your function here]

def task1():
    if len(sys.argv) == 1:
        plaintext_file = sys.argv[1]
    else:
        print("no command arguments provided")


if __name__ == "__main__":
    task1()
