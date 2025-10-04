import matplotlib.pyplot as plt
import numpy as np


if __name__ == '__main__':
    folder = './report/plts/'

    # block size vs. throughput for the various AES key sizes
    aes_x_pts = np.array([1, 8, 9, 0, 6, 0])
    aes_y_pts = np.array([3, 12, 13 , 1, 3, 9])

    plt.plot(aes_x_pts, aes_y_pts, 'o')
    plt.title('AES Throughput')
    plt.xlabel('Block Size (TODO)')
    plt.ylabel('Throughput (TODO)')
    plt.savefig(folder + 'aes.png')
    # plt.show()

    plt.clf()

    # RSA block size vs. throughput for the four RSA functions 
    rsa_x_pts = np.array([1, 1, 1, 1, 1])
    rsa_y_pts = np.array([1, 2, 4, 1, 2])

    plt.plot(rsa_x_pts, rsa_y_pts, 'o')
    plt.title('RSA')
    plt.xlabel('Block Size (TODO)')
    plt.ylabel('Throughput (TODO)')
    plt.savefig(folder + 'rsa.png')
    # plt.show()
    




