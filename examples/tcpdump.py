import subprocess


class TCPDump:
    """
    Represents a tcpdump instance to capture outgoing packets from server
    """

    def __init__(self, interface, output_file):
        self.interface = interface
        self.output_file = output_file
        self.proc = None

    def start(self):
        cmd = "sudo " + " ".join(self.get_start_cmd())
        print(cmd)
        self.proc = subprocess.Popen(cmd, shell=True)

    def stop(self):
        if self.proc:
            subprocess.run("sudo pkill tcpdump".split(" "))
            self.proc.wait()
        else:
            print("No process to stop!")

    def get_start_cmd(self):
        return [
            "tcpdump",
            "-B",
            "8192",
            "-i",
            self.interface,
            "-s",
            "100",
            "-w",
            self.output_file,
        ]
