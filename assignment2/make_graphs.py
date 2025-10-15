import matplotlib.pyplot as plt

block_sizes = [16, 64, 256, 1024, 8192, 16384] 
aes128_throughput = [621.96, 1410.85, 1539.89, 1558.25, 1572.95, 1566.05]  
aes192_throughput = [589.42, 1211.59, 1287.91, 1297.93, 1310.13, 1312.60]  

aes256_throughput = [843.86, 1057.19, 1108.94, 1124.06, 1136.32, 1130.82] 

plt.figure(figsize=(12, 5))

plt.subplot(1, 2, 1)
plt.plot(block_sizes, aes128_throughput, marker='o', label='AES-128', linewidth=2, markersize=8)
plt.plot(block_sizes, aes192_throughput, marker='s', label='AES-192', linewidth=2, markersize=8)
plt.plot(block_sizes, aes256_throughput, marker='^', label='AES-256', linewidth=2, markersize=8)
plt.xlabel('Block Size (bytes)', fontsize=11)
plt.ylabel('Throughput (MB/s)', fontsize=11)
plt.title('AES Performance: Block Size vs Throughput', fontsize=12, fontweight='bold')
plt.legend(fontsize=10)
plt.grid(True, alpha=0.3)
plt.xscale('log')

rsa_keys = [1024, 2048, 4096]
rsa_sign = [11055.6, 1348.3, 215.9]
rsa_verify = [208792.6, 53924.5, 15080.4]

plt.subplot(1, 2, 2)
plt.plot(rsa_keys, rsa_sign, marker='o', label='Sign', linewidth=2, markersize=8)
plt.plot(rsa_keys, rsa_verify, marker='s', label='Verify', linewidth=2, markersize=8)
plt.xlabel('RSA Key Size (bits)', fontsize=11)
plt.ylabel('Operations per Second', fontsize=11)
plt.title('RSA Performance', fontsize=12, fontweight='bold')
plt.legend(fontsize=10)
plt.grid(True, alpha=0.3)
plt.yscale('log')

plt.tight_layout()
plt.savefig('images/performance_comparison.png', dpi=150)
print('Saved images/performance_comparison.png')
