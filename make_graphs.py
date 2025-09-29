import matplotlib.pyplot as plt

# AES Performance
aes_keys = [128, 192, 256]
aes_mbps = [1552, 1279, 1106]

plt.figure(figsize=(10, 5))
plt.subplot(1, 2, 1)
plt.plot(aes_keys, aes_mbps, marker='o', linewidth=2)
plt.xlabel('AES Key Size (bits)')
plt.ylabel('Throughput (MB/s)')
plt.title('AES Performance')
plt.grid(True)

# RSA Performance
rsa_keys = [1024, 2048, 4096]
rsa_sign = [11055.6, 1348.3, 215.9]
rsa_verify = [208792.6, 53924.5, 15080.4]

plt.subplot(1, 2, 2)
plt.plot(rsa_keys, rsa_sign, marker='o', label='Sign', linewidth=2)
plt.plot(rsa_keys, rsa_verify, marker='s', label='Verify', linewidth=2)
plt.xlabel('RSA Key Size (bits)')
plt.ylabel('Operations per Second')
plt.title('RSA Performance')
plt.legend()
plt.grid(True)
plt.yscale('log')

plt.tight_layout()
plt.savefig('images/performance_comparison.png', dpi=150)
print('Saved images/performance_comparison.png')