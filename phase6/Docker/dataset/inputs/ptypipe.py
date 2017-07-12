import sys
import os
import pty
import tty
import select
import subprocess
import json
import signal
STDIN_FILENO = 0
STDOUT_FILENO = 1
STDERR_FILENO = 2

def _writen(fd, data):
    while data:
        # print ("hello", data)
        n = os.write(fd, data)
        data = data[n:]
def represents_int(s):
    try:
        return True, int(s)
    except ValueError:
        return False, -1
def main_loop(master_fd, commands):
    fds = [master_fd, STDIN_FILENO]

    wait_counter = 0
    command = ""
    while len(commands)>0:
        rfds, _, _ = select.select(fds, [], [])
        if len(commands) >0 and wait_counter==0:
            if command != "":
                # print ("writing", command)
                _writen(master_fd,command.encode('utf-8'))
            wait_counter,command = commands.pop(0)
        if master_fd in rfds:
            data = os.read(master_fd, 1024)
            if not data:
                fds.remove(master_fd)
            else:
                os.write(STDOUT_FILENO, data)
                if wait_counter >0:
                    wait_counter -=1
                    # print ("counter",wait_counter)
        if STDIN_FILENO in rfds:
            data = os.read(STDIN_FILENO, 1024)
            if wait_counter ==0:
                if not data:
                    fds.remove(STDIN_FILENO)
                elif data:
                    _writen(master_fd,data)
            #print ("wait counter is set", wait_counter)

            # if not data:
            #     fds.remove(STDIN_FILENO)
            # else:
            #     print ("data in hello", data)
            #     _writen(master_fd, data)
def read_infile(infile):
    command ={}
    with open(infile) as data_file:
        commands = json.load(data_file)
    return commands
def main():
    extra_input = sys.argv[1]
    interactive_command = sys.argv[2]
    commands = read_infile(extra_input)
    if hasattr(os, "fsencode"):
        # convert them back to bytes
        # http://bugs.python.org/issue8776
        interactive_command = os.fsencode(interactive_command)
        extra_input = os.fsencode(extra_input)

    # add implicit newline
    if extra_input and extra_input[-1] != b'\n':
        extra_input += b'\n'

    # replace LF with CR (shells like CR for some reason)
    extra_input = extra_input.replace(b'\n', b'\r')

    pid, master_fd = pty.fork()

    if pid == 0:
        os.execlp("sh", "/bin/sh", "-c", interactive_command)

    try:
        mode = tty.tcgetattr(STDIN_FILENO)
        tty.setraw(STDIN_FILENO)
        restore = True
    except tty.error:    # This is the same as termios.error
        restore = False
    try:
        main_loop(master_fd, commands)
        tty.tcsetattr(0, tty.TCSAFLUSH, mode)
    except OSError:
        if restore:
             tty.tcsetattr(0, tty.TCSAFLUSH, mode)
    os.close(master_fd)
    os.kill(pid, signal.SIGTERM)
    return os.waitpid(pid, 0)[1]

if __name__ == "__main__":
    main()
