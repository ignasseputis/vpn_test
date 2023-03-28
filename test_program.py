from time import sleep
import sys
from datetime import datetime
import os

import files
import vpn_setup
import speed_test


#class of an OpenVPN instance
class VPNInstance:
    def __init__(self, URL="", type="", name="", config="", files="", user="", pwd="", port=""):
        self.url=URL
        self.baseURL = "http://"+URL+"/"
        self.type = type
        self.name = name
        self.token = ""
        self.config=config
        self.files=files
        self.user=user
        self.pwd=pwd
        self.port=port


configFile="config.json" #main config file name
outFile = "output.csv" #test data output file name

serverInstance=VPNInstance()
clientInstance=VPNInstance()
  
def VPNSetup(instance):
    vpn_setup.RemoveAll(instance) #removes all instances on device
    
    print("\nCreating OpenVPN {type} instance...".format(type=instance.type))
    resp=vpn_setup.CreateVPNInstance(instance) #creates new instance
    
    resp=vpn_setup.SetConfig(instance) #sets configuration
    
    files.UploadFiles(instance) #uploads and sets all certificate files

    print("{instance} setup is finished.\n\n".format(instance=instance.name))

def InitiateSpeedtest(instanceServer,instanceClient):
    try:    
        counter=0
    
        #checks if instance actually exists
        status=vpn_setup.VPNStatus(instanceClient)
        if(not(instanceClient.name in status["data"])):
            sys.exit("Instance not found")

        #wait for OpenVPN client to become active
        while(status["data"]["client"]["status"] != "1"):
                #if client doesn't activate in 20 seconds, disables
                #and enables the client
                if(counter>0 and counter%20==0):
                    print("\nDisabling and enabling the instance\n")
                    speed_test.DisableEnable(instanceClient)

                #if doesn't activate in 300 seconds, turns off program
                if(counter==300):
                    sys.exit("Couldn't establish connection between client and server")

                print("Connection is currently not active, trying again in 1 second... ({time})"
                  .format(time=str(datetime.now())[0:19]))
                counter+=1
                sleep(1)
                status=vpn_setup.VPNStatus(instanceClient) #gets status for next loop iteration

        print("\nA connection has been established\n")

        #remove output file if it already exists
        if(os.path.isfile(outFile)):
            os.remove(outFile)

        #get speed test results
        results = speed_test.SSHSequence(instanceServer, instanceClient)

        print("Final speed test results:")
        print('|{label1:<10}|{label2:<10}|{label3:<10}|'.format(
                label1="Time", label2="Download", label3="Upload"))
        #if results complete, print to terminal and save to file
        if(len(results[0])==10 and len(results[1])==10 and len(results[2])==10):
           for i in range(10):
                data=[results[0][i], results[1][i], results[2][i]]
                print('|{time:>10}|{down:>10}|{up:>10}|'.format(
                    time=results[0][i], down=results[1][i], up=results[2][i]))
                files.WriteData(outFile, data)
        else:
            sys.exit("Some of the data seems to have gotten lost.")
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
            
def main():
    try:
        #creates VPN instance objects for both devices
        serverInstance=files.GetInstance(configFile,"server")
        clientInstance=files.GetInstance(configFile,"client")
                               
        #login  
        serverInstance.token=vpn_setup.Login(serverInstance)
        clientInstance.token=vpn_setup.Login(clientInstance)

        #displays basic info from both devices
        vpn_setup.DeviceInfo(serverInstance)
        vpn_setup.DeviceInfo(clientInstance)
    
        #creates and configures VPN instances on both devices
        VPNSetup(serverInstance)
        VPNSetup(clientInstance)

        print("Checking VPN connection...")
        #waits for client to activate
        sleep(5)
        
        #starts speed test
        InitiateSpeedtest(serverInstance,clientInstance)

        print("Getting FTP server information...")
        credentials=files.ReadCredentials(configFile)
        if(os.path.isfile(outFile)):
            print("Sending {0} data file to FTP server...".format(outFile))
            #sends data file to FTP server
            files.SendFileFTP(outFile, credentials)
            print("File transfer was successful.")
        else:
           sys.exit("{filename} file does not exist".format(filename=outFile))
        
        print("Work is done. Quitting...")

    except KeyboardInterrupt as e:
        sys.exit("\nProgram was shut off by keyboard interrupt")
    

if __name__ == "__main__":
    main()
