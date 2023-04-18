import sys
import paramiko
from time import sleep

class SSHInstance:
    def __init__(self, *args, **kwargs):
        self.ssh=None
        self.host = kwargs['address']
        self.username = kwargs['user']
        self.password = kwargs['pwd']
        self.port = kwargs['port']
        self.results=[]
        self.downloadResults=[]
        self.uploadResults=[]

    def SSHConnect(self):#, host, port, user, pwd):
        try:
            ssh=paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.host, self.port, self.username, self.password)
            self.ssh=ssh
            #return ssh
        except paramiko.AuthenticationException as err:
            sys.exit("Failed SSH authentification:\n{0}".format(err))

    def SSHComm(self, comm, test_length=3, retries=0):
        try:
            stdin, stdout, stderr = self.ssh.exec_command(comm, timeout = test_length*3)
            if (comm!="iperf3 -s"):
                lines=stdout.readlines()
                errLines=stderr.readlines()
                return lines, errLines
        except paramiko.SSHException as err:
            if(err=="SSH session not active"):
                if(retries<5):
                    print("Executing the command failed due to SSH error. Trying again...")
                    self.SSHConnect()
                    return self.SSHComm(comm, test_length, retries+1)
            sys.exit("Executing the command failed due to SSH error:\n{0}".format(err))

    def AverageValues(self,interimResults, test_length):
        finalResults=[]
        for i in range(test_length):
            values=[]
            for j in range(len(interimResults)):
                values.append(float(interimResults[j][i]))
            #print(values)
            finalResults.append(round(sum(values)/float(len(values)),2))
        return finalResults
    
    def ServerSequence(self):
        print("Setting up iperf3 listener... " + self.host)
        #connects to server instance
        self.SSHComm("iperf3 -s")

    def ClientSequence(self, test_count, test_length, connectionType):
        try:
            self.results=[]
            self.downloadResults=[]
            self.uploadResults=[]

            self.results.append(self.GetLabels(test_length))
            print("Starting download test...")

            for i in range (test_count):
                results, errs = self.TestDownload(test_length, connectionType)
                if(len(errs)==0):
                    self.downloadResults.append(results)
                    print("{0}/{1}".format(i+1,test_count))
                else:
                    print(errs)
                    raise paramiko.SSHException
                sleep(0.5)
            print("Download test has finished.")

            print("Starting upload test...")

            for i in range (test_count):
                results, errs = self.TestUpload(test_length, connectionType)
                if(len(errs)==0):
                    self.uploadResults.append(results)
                    print("{0}/{1}".format(i+1,test_count))
                else:
                    print(errs)
                    raise paramiko.SSHException
                sleep(0.5)
            print("Upload test has finished.")

            self.results.append(self.AverageValues(self.downloadResults, test_length))
            self.results.append(self.AverageValues(self.uploadResults, test_length))

            return self.results
        
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))
        
        
    def GetLabels(self, test_length):
        labels=[]
        for i in range(test_length):
            labels.append("{0}.00-{1}.00".format(i, i+1))
        return labels
    
    def TestDownload(self, test_length, connectionType):
        testResults=[]
        match connectionType:
            case "tun":
                host="172.16.10.1"
            case "tap":
                host="192.168.2.2"
        lines, errs=self.SSHComm("iperf3 -f m -t {0} -R -c {1}"
                .format(test_length,host),test_length)
        if(len(errs)==0):
            for line in lines[4:(4+test_length)]:
                parts=line.split()
                testResults.append(parts[6])
        sleep(0.5)
        return testResults, errs
    
    def TestUpload(self, test_length, connectionType):
        testResults=[]
        match connectionType:
            case "tun":
                host="172.16.10.1"
            case "tap":
                host="192.168.2.2"
        lines, errs=self.SSHComm("iperf3 -f m -t {0} -c {1}"
                .format(test_length, host),test_length)
        if(len(errs)==0):
            for line in lines[3:(3+test_length)]:
                parts=line.split()
                testResults.append(parts[6])
        sleep(0.5)
        return testResults, errs
    
    def Close(self):
        print("Closing SSH connection")
        self.ssh.close()
    