from time import sleep
import requests
import sys
import paramiko


#disables openVPN config, sleeps for 5 s, enables the config back on,
#waits 5 s
def DisableEnable(instance, retries=0):
    
    try:
        url=instance.baseURL+ "api/services/openvpn/config/" + instance.name
        headers={
        "Content-Type":"application/json",
        "Authorization": "Bearer "+instance.token
        }
    
        data={"data": {"enable": "0"}}
        #disable instance request
        resp=requests.put(url, json=data, headers=headers).json()
    
        if(resp["success"]==True):
            print("The {name} instance was disabled.".format(name=instance.name))
        else:
            print("Disabling the {name} instance failed.".format(name=instance.name))
            sys.exit("")

        sleep(5) 
     
        data={"data": {"enable": "1"}}
        #enable instance request
        resp=requests.put(url, json=data, headers=headers).json()
    
        if(resp["success"]==True):
            print("The {name} instance was enabled.\n".format(name=instance.name))
        else:
            print("Enabling the {name} instance failed.".format(name=instance.name))
            sys.exit("")

        sleep(5)
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    except OSError as err:
        print("Not responding. Trying again...")
        if(retries<5):
            return DisableEnable(instance, retries+1)
        else:
            sys.exit("Device is unresponsive. Quitting...")    
    

#returns an object that is connected to host via ssh
def SSHConnect(host, port, user, pwd):
    try:
        ssh=paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port, user, pwd)
        return ssh
    except paramiko.AuthenticationException as err:
        sys.exit("Failed SSH authentification:\n{0}".format(err))
    
#executes a command in ssh instance, returns output and
#errors if the command is not "iperf3 -s"
def SSHComm(ssh, comm):
    try:
        stdin, stdout, stderr = ssh.exec_command(comm)
        if (comm!="iperf3 -s"):
            lines=stdout.readlines()
            errLines=stderr.readlines()
            return lines, errLines
    except paramiko.SSHException as err:
        sys.exit("Executing the command failed due to SSH error:\n{0}".format(err))

#performs all actions related to ssh
def SSHSequence(instance1, instance2, test_count):
    try:
        #create lists to store data in
        results=[]
        labels=["0.00-1.00", "1.00-2.00", "2.00-3.00", "3.00-4.00","4.00-5.00",
                "5.00-6.00","6.00-7.00","7.00-8.00","8.00-9.00","9.00-10.00"]
        results.append(labels)
        aggregatedResults=[]
        
        print("Setting up iperf3 listener...")
        #connects to server instance
        ssh1=SSHConnect(instance1.url,instance1.port, instance1.user, instance1.pwd)
        SSHComm(ssh1, "iperf3 -s")

        print("Starting download test...")

        #connects to client instance
        ssh2=SSHConnect(instance2.url,instance2.port, instance2.user, instance2.pwd)
    
        #executes download test
        for i in range (test_count):
            interimResults=[]
            lines2, errs2=SSHComm(ssh2, "iperf3 -f m -R -c 172.16.10.1")
            if(len(errs2)==0):
                print("{0}/{1}".format(i+1, test_count))
                for line in lines2[4:14]:
                    parts=line.split()
                    interimResults.append(parts[6])
                aggregatedResults.append(interimResults)
            else:
                sys.exit("Download test has failed.\n"+str(errs2))
        print("Download test has finished.")
        results.append(AverageValues(aggregatedResults))

        aggregatedResults=[]
        print("Starting upload test...")

        for i in range(test_count):
            interimResults=[]
            #executes upload test
            lines3, errs3=SSHComm(ssh2, "iperf3 -f m -c 172.16.10.1")

            #stores data in lists if no errors from command
            if(len(errs3)==0):
                print("{0}/{1}".format(i+1, test_count))
                for line in lines3[3:13]:
                    parts=line.split()
                    interimResults.append(parts[6])
                aggregatedResults.append(interimResults)
            else:
                sys.exit("Upload test has failed.\n"+str(errs3))
        print("Upload test has finished.")

        results.append(AverageValues(aggregatedResults))

        #close both connections
        ssh1.close()
        ssh2.close()

        return results
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))

def AverageValues(interimResults):
    finalResults=[]
    for i in range(10):
        values=[]
        for j in range(len(interimResults)):
            values.append(float(interimResults[j][i]))
        print(values)
        finalResults.append(round(sum(values)/float(len(values)),2))
    return finalResults

def main():
    pass
    
if __name__ == "__main__":
    main()