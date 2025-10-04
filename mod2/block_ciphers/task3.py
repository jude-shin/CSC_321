import matplotlib.pyplot as plt
import numpy as np

def throughput_conversion(block_size_array, fn_per_sec_array):
    # Convert to bytes (divide by 8)
    bytes_array = [x//8 for x in block_size_array]
    # Mulitply that by the x/second
    return [x*y for x, y in zip(bytes_array, fn_per_sec_array)]

if __name__ == '__main__':
    # TODO: torrey I need you to check this I have no idea if I did this correctly
    img_folder = './report/plts/'

    ###########
    ### AES ###
    ###########

    # AES block size vs. throughput for the various AES key sizes
    # The 'numbers' are in 1000s of bytes per second processed.
    # type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
    # aes-128-cbc     907976.50k  1371144.26k  1450141.88k  1453933.91k  1460622.64k  1458176.00k
    # aes-192-cbc     801784.54k  1115350.47k  1184813.14k  1214624.62k  1214158.51k  1209035.43k
    # aes-256-cbc     755476.00k   974607.32k  1025784.89k  1043042.30k  1050611.67k  1052685.70k
    aes_x_pts = np.array([16, 64, 256, 1024, 8192, 16384])

    aes_y_128_pts = np.array([907976.50, 1371144.26, 1450141.88, 1453933.91, 1460622.64, 1458176.00])
    aes_y_192_pts = np.array([801784.54, 1115350.47, 1184813.14, 1214624.62, 1214158.51, 1209035.43])
    aes_y_256_pts = np.array([755476.00, 974607.32, 1025784.89, 1043042.30, 1050611.67, 1052685.70])

    plt.plot(aes_x_pts, aes_y_128_pts, label='aes-128-cbc')
    plt.plot(aes_x_pts, aes_y_192_pts, label='aes-192-cbc')
    plt.plot(aes_x_pts, aes_y_256_pts, label='aes-256-cbc')

    plt.title('AES Throughput')
    plt.xlabel('Block Size (bytes)')
    plt.ylabel('Throughput (bytes/sec)')
    plt.legend()
    plt.savefig(img_folder+ 'aes.png')
    plt.show()


    ###########
    ### RSA ###
    ###########

    # RSA block size vs. throughput for the four RSA functions 
    #                     sign    verify   encrypt   decrypt   sign/s verify/s encr./s   decr./s
    # rsa   512 bits 0.000042s 0.000003s 0.000003s 0.000054s  23860.1 386845.4 292813.3  18568.3
    # rsa  1024 bits 0.000094s 0.000006s 0.000007s 0.000106s  10661.9 161903.0 138038.5   9442.1
    # rsa  2048 bits 0.000643s 0.000019s 0.000021s 0.000659s   1556.4  52342.1  48483.4   1518.2
    # rsa  3072 bits 0.001998s 0.000039s 0.000041s 0.001947s    500.4  25682.0  24484.7    513.7
    # rsa  4096 bits 0.004292s 0.000067s 0.000069s 0.004328s    233.0  14965.3  14458.9    231.1
    # rsa  7680 bits 0.039331s 0.000224s 0.000229s 0.039291s     25.4   4457.8   4375.3     25.5
    # rsa 15360 bits 0.204694s 0.000860s 0.000869s 0.205102s      4.9   1162.4   1150.7      4.9
    
    rsa_x_pts = np.array([512, 1024, 2048, 3072, 4096, 7680, 15360])

    rsa_y_sign_pts = np.array([23860.1, 10661.9, 1556.4, 500.4, 233.0, 25.4, 4.9])
    rsa_y_verify_pts = np.array([386845.4, 161903.0, 52342.1, 25682.0, 14965.3, 4457.8, 1162.4])
    rsa_y_encr_pts = np.array([292813.3, 138038.5, 48483.4, 24484.7, 14458.9, 4375.3, 1150.7])
    rsa_y_decr_pts = np.array([18568.3, 9442.1, 1518.2, 513.7, 231.1, 25.5, 4.9])
    
    # convert the throughput from operation/sec to bytes/sec
    rsa_y_sign_pts = throughput_conversion(rsa_x_pts, rsa_y_sign_pts) 
    rsa_y_verify_pts = throughput_conversion(rsa_x_pts, rsa_y_verify_pts)
    rsa_y_encr_pts = throughput_conversion(rsa_x_pts, rsa_y_encr_pts)
    rsa_y_decr_pts = throughput_conversion(rsa_x_pts, rsa_y_decr_pts)

    plt.plot(rsa_x_pts, rsa_y_sign_pts, label='sign')
    plt.plot(rsa_x_pts, rsa_y_verify_pts, label='verify')
    plt.plot(rsa_x_pts, rsa_y_encr_pts, label='encr.')
    plt.plot(rsa_x_pts, rsa_y_decr_pts, label='decr.')

    plt.title('RSA')
    plt.xlabel('Block Size (bytes)')
    plt.ylabel('Throughput (bytes/sec)')
    plt.legend()
    plt.savefig(img_folder + 'rsa.png')
    plt.show()
   
    
