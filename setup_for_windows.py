import os
import gc
from subprocess import Popen, PIPE
pipe = Popen('Scripts\pip3.exe install pycryptodome', stdout = PIPE, stderr = PIPE)
out, err = pipe.communicate(input = b'y')
pipe.wait()
buf = str(out)
if (buf.find('Requirement already satisfied: pycryptodome') != -1) or (buf.find('Successfully installed pycryptodome') != -1):
    print('OK.\n')
    print(out.decode('utf-8'))
else:
    print('Fail.\n')
    print(out.decode('utf-8'))
    print(err.decode('utf-8'))

i = input("Press enter for exit.")
del out
del err
del pipe
del buf
del i
gc.collect()
os._exit(0)
