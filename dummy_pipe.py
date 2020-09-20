#!/usr/bin/env python3

import sys
import threading
import win32pipe
import win32file
import pywintypes

'''
This script is called by the main program using powershell to hide the windows (-WindowStyle Hidden)
The pipe names are received as arguments and will be created by the function start_listen()

This dummy pipe server does nothing else.
'''

# At least one pipe name is expected
if len(sys.argv) < 2:
    exit("Arguments invalid")

# Creates a pipe and listen to it
def start_listen(pipe_name):
    pipe = win32pipe.CreateNamedPipe(
        pipe_name,
        win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
        1, 65536, 65536, 0, None)

    # Waiting for client
    win32pipe.ConnectNamedPipe(pipe, None)
    win32pipe.SetNamedPipeHandleState(
        pipe, win32pipe.PIPE_READMODE_MESSAGE, None, None)

    while True:
        # Got client
        try:
            # Trying to read the message received in the pipe
            get_command = win32file.ReadFile(pipe, 6)
            decoded_message = str(get_command[1].decode())

            # If the message is *STOP*, we break from the loop
            if decoded_message == "*STOP*":
                break
        except pywintypes.error as e:
            pass

        if pipe is not None:
            win32pipe.DisconnectNamedPipe(pipe)
            win32pipe.ConnectNamedPipe(pipe, None)

    win32file.CloseHandle(pipe)
    return

for pipe_name in sys.argv[1:]:
    if "\\\\.\\pipe\\" in pipe_name:
        # Each pipe hangs the script (while listening), so we need to start each
        # of them in their individual thread
        threading.Thread(target=start_listen, args=(pipe_name,)).start()
