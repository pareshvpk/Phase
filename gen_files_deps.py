import os
out_dir = 'D:/ARM/local-repo/classes'
jars = sorted([f for f in os.listdir(out_dir) if f.endswith('.jar')])
lines = []
for j in jars:
    path = f'D:/ARM/local-repo/classes/{j}'
    lines.append(f'    implementation(files("{path}"))')
print('\n'.join(lines))