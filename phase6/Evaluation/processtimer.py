import psutil
import subprocess
import time

class ProcessTimer:
    def __init__(self,command):
        self.command = command
        self.execution_state = False

    def execute(self):
        self.max_vms_memory = 0
        self.max_rss_memory = 0

        self.t0 = time.time()
        self.t1 = None
        self.p = subprocess.Popen(self.command,shell=False)
        self.execution_state = True

    def poll(self):
        if not self.check_execution_state():
            return False

        try:
            pp = psutil.Process(self.p.pid)
            pinfo = pp.as_dict(ad_value='')
            #obtain a list of the subprocess and all its descendants
            descendants = list(pp.children(recursive=True))
            descendants = descendants + [pp]

            rss_memory = 0
            vms_memory = 0
            # print(pinfo['cpu_times'])
            # self.t1 = pinfo['cpu_times'].user
            self.t1 = time.time()
            #calculate and sum up the memory of the subprocess and all its descendants 
            for descendant in descendants:
                try:
                    pinfo = descendant.as_dict()
                    mem_info = pinfo['memory_info'] # descendant.get_memory_info()
                    #print(mem_info)
                    rss_memory += mem_info[0]
                    vms_memory += mem_info[1]
                except psutil.NoSuchProcess:
                    #sometimes a subprocess descendant will have terminated between the time
                    # we obtain a list of descendants, and the time we actually poll this
                    # descendant's memory usage.
                    pass
            self.max_vms_memory = max(self.max_vms_memory,vms_memory)
            self.max_rss_memory = max(self.max_rss_memory,rss_memory)

        except psutil.NoSuchProcess:
            return self.check_execution_state()

        return self.check_execution_state()


    def is_running(self):
        return psutil.pid_exists(self.p.pid) and self.p.poll() == None

    def check_execution_state(self):
        if not self.execution_state:
            return False
        if self.is_running():
            return True
        self.executation_state = False
        self.t1 = time.time()
        return False

    def close(self,kill=False):
        try:
            pp = psutil.Process(self.p.pid)
            if kill:
                pp.kill()
            else:
                pp.terminate()
        except psutil.NoSuchProcess:
            pass
