from time import sleep
import sys
from datetime import datetime
import os

import files
import vpn_setup
import speed_test


#class of an OpenVPN instance
class VPNInstance:
    def __init__(self, URL="", type="", name="", tls_config="", tls_pwd_config="",pwd_config="",psk_config="", files="", user="", pwd="", port=""):
        self.url=URL
        self.baseURL = "http://"+URL+"/"
        self.type = type
        self.name = name
        self.token = ""
        self.tls_config=tls_config
        self.tls_pwd_config=tls_pwd_config
        self.pwd_config=pwd_config
        self.psk_config=psk_config
        self.files=files
        self.user=user
        self.pwd=pwd
        self.port=port
        self.deviceName=""


configFile="./config.json" #main config file name
outFile = "output.csv" #test data output file name

serverInstance=VPNInstance()
clientInstance=VPNInstance()
  
def VPNSetup(instance):
    vpn_setup.RemoveAll(instance) #removes all instances on device
    
    print("\nCreating OpenVPN {type} instance...".format(type=instance.type))
    resp=vpn_setup.CreateVPNInstance(instance) #creates new instance
    
    resp=vpn_setup.SetBaseConfig(instance) #sets configuration
    
    files.UploadFiles(instance) #uploads and sets all certificate files

    print("{instance} setup is finished.\n\n".format(instance=instance.name))

def InitiateSpeedtest(instanceServer,instanceClient, testName, test_count):
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
        results = speed_test.SSHSequence(instanceServer, instanceClient, test_count)

        print("Final speed test results:")
        print('|{label1:<10}|{label2:<10}|{label3:<10}|'.format(
                label1="Time", label2="Download", label3="Upload"))
        #if results complete, print to terminal and save to file
        if(len(results[0])==10 and len(results[1])==10 and len(results[2])==10):
            files.WriteData(outFile, [testName])
            for i in range(10):
                data=[results[0][i], results[1][i], results[2][i]]
                print('|{time:>10}|{down:>10}|{up:>10}|'.format(
                    time=results[0][i], down=results[1][i], up=results[2][i]))
                files.WriteData(outFile, data)
        else:
            sys.exit("Some of the data seems to have gotten lost.")
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))

def TestConfig(instanceServer, instanceClient, configs, ftpCreds, test_count):
    print ("\nPerforming tests for different cipher configurations:")
    for i in range(28):
            for j in range (6):
                cipherName="cipher_test{0}".format(i+1)
                authName="auth_test{0}".format(j+1)
                currentCipher=configs[cipherName]
                currentAuth=configs[authName]
                currentConf=currentCipher | currentAuth
                print("Testing cipher: {cipher} + {auth}".format(cipher = currentCipher["cipher"], auth = currentAuth["auth"]))
                vpn_setup.SetTestConfig(instanceServer, currentConf, "{0} + {1}".format(currentCipher["cipher"],currentAuth["auth"]))
                vpn_setup.SetTestConfig(instanceClient, currentConf, "{0} + {1}".format(currentCipher["cipher"],currentAuth["auth"]))
                sleep(5)
                print("Checking VPN connection...")
                InitiateSpeedtest(instanceServer,instanceClient,"{0} + {1}".format(currentCipher["cipher"],currentAuth["auth"]), test_count)

                if(os.path.isfile(outFile)):
                    print("Sending {0} data file to FTP server...".format(outFile))
                    #sends data file to FTP server
                    files.SendFileFTP(outFile, ftpCreds, instanceClient.deviceName, "./vpn_tests")
                    print("File transfer was successful.")
                else:
                    sys.exit("{filename} file does not exist".format(filename=outFile))


            
def main():
    try:
        #creates VPN instance objects for both devices
        serverInstance=files.GetInstance(configFile,"server")
        clientInstance=files.GetInstance(configFile,"client")
                               
        #login  
        serverInstance.token=vpn_setup.Login(serverInstance)
        clientInstance.token=vpn_setup.Login(clientInstance)

        #displays basic info from both devices
        serverDeviceName=vpn_setup.DeviceInfo(serverInstance)
        serverInstance.deviceName=serverDeviceName
        clientDeviceName=vpn_setup.DeviceInfo(clientInstance)
        clientInstance.deviceName=clientDeviceName
    
        #creates and configures VPN instances on both devices
        VPNSetup(serverInstance)
        VPNSetup(clientInstance)

        print("Getting FTP server information...")
        credentials=files.ReadCredentials(configFile)
        
        
        testConfigs=files.ReadTestConfigs(configFile)
        TestConfig(serverInstance,clientInstance, testConfigs, credentials,3)

        print("Work is done. Quitting...")
        
    except KeyboardInterrupt as e:
        sys.exit("\nProgram was shut off by keyboard interrupt")
    

if __name__ == "__main__":
    main()
