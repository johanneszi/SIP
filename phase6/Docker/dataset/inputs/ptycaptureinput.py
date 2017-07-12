import sys
import os
import pty
import tty
import select
import subprocess

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
instr=[]
def main_loop(master_fd, extra_input):
    global instr
    fds = [master_fd, STDIN_FILENO]
    #_writen(master_fd, extra_input)

    wait_counter = 0
    while True:
        rfds, _, _ = select.select(fds, [], [])
        if master_fd in rfds:
            data = os.read(master_fd, 1024)
            if not data:
                fds.remove(master_fd)
            else:
                os.write(STDOUT_FILENO, data)
                wait_counter+=1
        if STDIN_FILENO in rfds:
            data = os.read(STDIN_FILENO, 1024)
            if not data:
                fds.remove(STDIN_FILENO)
            elif data:
                _writen(master_fd,data)
                instr.append((wait_counter,data.decode("utf-8")))
                wait_counter=0
def dump_instr(outputfilename):
    global instr
    print (instr)
    print (outputfilename)
    import json
    with open(outputfilename, "w", encoding="utf8") as outfile:
        json.dump(instr, outfile)
def main():
    extra_input = sys.argv[1]
    interactive_command = sys.argv[2]
    p_name = interactive_command.replace("./","")
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
        main_loop(master_fd, extra_input)
        tty.tcsetattr(0, tty.TCSAFLUSH, mode)
    except OSError:
        if restore:
             tty.tcsetattr(0, tty.TCSAFLUSH, mode)

    os.close(master_fd)
    dump_instr(p_name+".in")

    return os.waitpid(pid, 0)[1]

if __name__ == "__main__":
    main()
