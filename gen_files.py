import os
out_dir = 'D:/ARM/local-repo/classes'
jars = sorted([f for f in os.listdir(out_dir) if f.endswith('.jar')])
for j in jars:
    path = f'D:/ARM/local-repo/classes/{j}'
    print(f'implementation(files("{path}"))')