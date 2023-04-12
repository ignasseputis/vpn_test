from time import sleep
import requests
import sys
import paramiko
import vpn_setup
from datetime import datetime

def CheckConnection(instanceClient, instanceServer):
    counter=0
        #checks if instance actually exists
    status=vpn_setup.VPNStatus(instanceClient)
    if(not(instanceClient.name in status["data"])):
        sys.exit("Instance not found")

    #wait for OpenVPN client to become active 
    while(status["data"]["client"]["status"] != "1"):
            if(counter==120):
                print("Couldn't establish connection between client and server")
                raise OSError
            if(counter>0 and counter%20==0):
                print("\nDisabling and enabling the client instance\n")
                DisableEnable(instanceClient)
            
            if(counter>0 and counter%60==0):
                print("\nDisabling and enabling the server instance\n")
                DisableEnable(instanceServer)

            print("Connection is currently not active, trying again in 1 second... ({0})"
                .format(str(datetime.now())[0:19]))
            counter+=1
            sleep(1)
            status=vpn_setup.VPNStatus(instanceClient) #gets status for next loop iteration

    print("\nA connection has been established\n")
    return True

def CheckServer(instanceServer):
    counter=0
        #checks if instance actually exists
    status=vpn_setup.VPNStatus(instanceServer)
    if(not(instanceServer.name in status["data"])):
        sys.exit("Instance not found")

    #wait for OpenVPN client to become active
    while(status["data"][instanceServer.name]["status"] != "2"):
            if(counter==60):
                print("The server instance could not be activated")
                raise OSError
            if(counter>0 and counter%20==0):
                print("Disabling and enabling the server instance\n")
                DisableEnable(instanceServer)
            
            print("Server is currently not active, trying again in 1 second... ({0})"
                .format(str(datetime.now())[0:19]))
            counter+=1
            sleep(1)
            status=vpn_setup.VPNStatus(instanceServer) #gets status for next loop iteration

    print("Server instance has been activated\n")
    return True


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
def SSHComm(ssh, comm, test_length):
    try:
        stdin, stdout, stderr = ssh.exec_command(comm, timeout = test_length*3)
        if (comm!="iperf3 -s"):
            lines=stdout.readlines()
            errLines=stderr.readlines()
            return lines, errLines
    except paramiko.SSHException as err:
        sys.exit("Executing the command failed due to SSH error:\n{0}".format(err))

#performs all actions related to ssh
def SSHSequence(instance1, instance2, test_count, test_length, test_IP):
    try:
        #create lists to store data in
        results=[]
        labels=[]
        for i in range(test_length):
            labels.append("{0}.00-{1}.00".format(i, i+1))
        results.append(labels)
        aggregatedResults=[]
        
        print("Setting up iperf3 listener... " + test_IP)
        #connects to server instance
        ssh1=SSHConnect(instance1.url,instance1.port, instance1.user, instance1.pwd)
        SSHComm(ssh1, "iperf3 -s", test_length)

        print("Starting download test...")

        #connects to client instance
        ssh2=SSHConnect(instance2.url,instance2.port, instance2.user, instance2.pwd)
    
        #executes download test
        for i in range (test_count):
            interimResults=[]
            lines2, errs2=SSHComm(ssh2, "iperf3 -f m -t {0} -R -c {1}".format(test_length,test_IP),test_length)
            if(len(errs2)==0):
                print("{0}/{1}".format(i+1, test_count))
                for line in lines2[4:(4+test_length)]:
                    parts=line.split()
                    interimResults.append(parts[6])
                aggregatedResults.append(interimResults)
            else:
                print(errs2)
                raise paramiko.SSHException
            sleep(0.5)
        print("Download test has finished.\n")
        results.append(AverageValues(aggregatedResults, test_length))

        aggregatedResults=[]
        print("Starting upload test...")

        for i in range(test_count):
            interimResults=[]
            #executes upload test
            lines3, errs3=SSHComm(ssh2, "iperf3 -f m -t {0} -c {1}".format(test_length, test_IP),test_length)

            #stores data in lists if no errors from command
            if(len(errs3)==0):
                print("{0}/{1}".format(i+1, test_count))
                for line in lines3[3:(3+test_length)]:
                    parts=line.split()
                    interimResults.append(parts[6])
                aggregatedResults.append(interimResults)
            else:
                 print(errs3)
                 raise paramiko.SSHException
            sleep(0.5)
        print("Upload test has finished.\n")

        results.append(AverageValues(aggregatedResults, test_length))

        #close both connections
        ssh1.close()
        ssh2.close()

        return results
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))

def AverageValues(interimResults, test_length):
    finalResults=[]
    for i in range(test_length):
        values=[]
        for j in range(len(interimResults)):
            values.append(float(interimResults[j][i]))
        #print(values)
        finalResults.append(round(sum(values)/float(len(values)),2))
    return finalResults

def main():
    pass
    
if __name__ == "__main__":
    main()