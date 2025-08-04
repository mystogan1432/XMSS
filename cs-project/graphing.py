import matplotlib.pyplot as plt
import numpy as np
import time
import misc

"""
# sha256
sha_depth_1 = [0.8159, 0.8195, 0.8241, 0.9983, 0.7822, 0.7798]
sha_depth_1_avg = sum(sha_depth_1)/len(sha_depth_1)
sha_depth_2 = [1.2743, 0.9768, 1.0849, 1.7828, 1.2672, 1.5802]
sha_depth_2_avg = sum(sha_depth_2)/len(sha_depth_2)
sha_depth_3 = [318.1164, 82.3635, 149.4395, 190.8509, 218.3559]
sha_depth_3_avg = sum(sha_depth_3)/len(sha_depth_3)
sha_depth_4 = [15275.1343, 8370.1203, 4629.9080]
sha_depth_4_avg = sum(sha_depth_4)/len(sha_depth_4)
sha_depth = np.array([1, 2, 3])
sha_time_points = np.array([sha_depth_1_avg, sha_depth_2_avg, sha_depth_3_avg])

# shake256
shake_depth_1 = [0.599219, 0.60831, 0.597382, 0.632338, 0.602425, 0.59802]
shake_depth_1_avg = sum(shake_depth_1)/len(shake_depth_1)
shake_depth_2 = [1.113404, 1.062541, 0.978665, 1.511001, 0.8331778, 1.43793]
shake_depth_2_avg = sum(shake_depth_2)/len(shake_depth_2)
shake_depth_3 = [5.31384, 19.802962, 95.824824, 24.852153, 349.673201, 805.04124]
shake_depth_3_avg = sum(shake_depth_3)/len(shake_depth_3)
shake_depth_4 = [17344.900126, 18343.82563, 9401.36836]
shake_depth_4_avg = sum(shake_depth_4)/len(shake_depth_4)
shake_depth = np.array([1, 2, 3, 4])
shake_time_points = np.array([shake_depth_1_avg, shake_depth_2_avg, shake_depth_3_avg, shake_depth_4_avg])
"""

print("#####Hash function timings#####")
standard_timings = np.array([])
samples = 1000000
for i in range(samples):
    start = time.time()
    # time.sleep(0.05)
    standard_hash = misc.sha256_hash("hello")
    end = time.time()
    # standard_timings.append((end - start))  # - 0.05)
    standard_timings = np.append(standard_timings, end - start)
tampered_timing = np.array([])
for i in range(samples):
    start = time.time()
    # time.sleep(0.05)
    tampered_hash = misc.mySHA256("hello", "hi", "hi")
    end = time.time()
    # tampered_timing.append((end - start))  # - 0.05)
    tampered_timing = np.append(tampered_timing, end - start)

print(f"number of samples = {samples}")
# print(f"standard timings: {standard_timings}")
print(f"standard timings avg: {sum(standard_timings) / len(standard_timings)}")
# print(f"tampered timings: {tampered_timing}")
print(f"tampered timings avg: {sum(tampered_timing) / len(tampered_timing)} ")

# plt.title("Depth vs. Time")
# plt.xlabel("Byte Depth")
# plt.ylabel("Average Time(s)")
# plt.plot(sha_depth, sha_time_points, label="sha")
# plt.plot(shake_depth, shake_time_points, "-.", label="shake")
plt.title("Hash function")
plt.xlabel("samples")
plt.ylabel("time (s)")
plt.plot(standard_timings, label="standard hash")
plt.plot(tampered_timing, label="tampered hash")
plt.legend()
plt.show()


