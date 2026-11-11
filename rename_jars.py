import os
out_dir = 'D:/ARM/local-repo/classes'
count = 0
for f in os.listdir(out_dir):
    if f.endswith('.aar'):
        old_path = os.path.join(out_dir, f)
        new_path = os.path.join(out_dir, f[:-4] + '.jar')
        os.rename(old_path, new_path)
        count += 1
print(f'Renamed {count} files from .aar to .jar')
print(f'Total .jar files: {len([f for f in os.listdir(out_dir) if f.endswith(".jar")])}')