import sys
import requests
from time import sleep
from datetime import datetime
import paramiko

class SpeedTest:
    def __init__(self, *args, **kwargs):
        self.instanceServer=kwargs['server']
        self.instanceClient=kwargs['client']
        self.outFile=kwargs['output']
        self.serverSSH=self.instanceServer.sshClient
        self.clientSSH=self.instanceClient.sshClient
        self.csv=kwargs['csv']

    def InitiateSpeedtest(self, test_count, test_length, connectionType, parameters):
        try:    
            self.CheckServer()
            self.CheckConnection()

            #get speed test results
            self.serverSSH.ServerSequence()
            results = self.clientSSH.ClientSequence(test_count, test_length, connectionType)
            
            if(len(results[0])==test_length and len(results[1])==test_length and len(results[2])==test_length):
                self.WriteData(results, test_length, parameters)
                return True
            else:
                print("Some of the data seems to have gotten lost.")
                raise OSError
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))
        except ZeroDivisionError as err:
            print("Zero tests are performed")
            self.WriteError(parameters)
            return False
        except (ConnectionResetError, paramiko.SSHException, TimeoutError, OSError) as err:
            print("Connectivity error. Moving on to other configuration...")
            self.WriteError(parameters)
            sleep(10)
            return False
    
    def WriteData(self, results, test_length, parameters):
        #if results complete, print to terminal and save to file
            self.csv.WriteData(parameters+[" Download ->"]+results[1]+[" Download averages ->"]+
                               results[3]+results[5]+[" Upload ->"]+results[2]+["Upload averages ->"]+results[4]+results[6])
            self.PrintInTerminal(test_length, results)
            
    def ResultsAverage(self, results):
        downAverage=round(sum(results[1])/float(len(results[1])),2)
        upAverage=round(sum(results[2])/float(len(results[2])),2)
        return downAverage, upAverage

    def PrintInTerminal(self, test_length, results):
        print("Final speed test results:")
        print('|{label1:<10}|{label2:<10}|{label3:<10}|'.format(
                label1="Time", label2="Download", label3="Upload"))
        for i in range(test_length):
            print('|{time:>10}|{down:>10}|{up:>10}|'.format(
                time=results[0][i], down=results[1][i], up=results[2][i]))

    def WriteError(self,parameters):
        self.csv.WriteData(parameters+["Test has failed."])

    def CheckConnection(self):
        counter=0
            #checks if instance actually exists
        status=self.instanceClient.VPNStatus()
        if(not(self.instanceClient.name in status["data"])):
            sys.exit("Instance not found")

        #wait for OpenVPN client to become active 
        while(status["data"]["client"]["status"] != "1"):
                if(counter==80):
                    print("Couldn't establish connection between client and server")
                    raise OSError
                if(counter>0 and counter%20==0):
                    print("\nDisabling and enabling the client instance\n")
                    self.DisableEnable(self.instanceClient)
                
                if(counter>0 and counter%40==0):
                    print("\nDisabling and enabling the server instance\n")
                    self.DisableEnable(self.instanceServer)

                print("Connection is currently not active, trying again in 1 second... ({0})"
                    .format(str(datetime.now())[0:19]))
                counter+=1
                sleep(1)
                status=self.instanceClient.VPNStatus()

        print("\nA connection has been established\n")
        return True

    def CheckServer(self):
        counter=0
            #checks if instance actually exists
        status=self.instanceServer.VPNStatus()
        if(not(self.instanceServer.name in status["data"])):
            sys.exit("Instance not found")

        #wait for OpenVPN client to become active
        while(status["data"][self.instanceServer.name]["status"] != "2"):
                if(counter==60):
                    print("The server instance could not be activated")
                    raise OSError
                if(counter>0 and counter%20==0):
                    print("Disabling and enabling the server instance\n")
                    self.DisableEnable(self.instanceServer)
                
                print("Server is currently not active, trying again in 1 second... ({0})"
                    .format(str(datetime.now())[0:19]))
                counter+=1
                sleep(1)
                status=self.instanceServer.VPNStatus()
        print("Server instance has been activated\n")
        return True


    #disables openVPN config, sleeps for 5 s, enables the config back on,
    #waits 5 s
    def DisableEnable(self, instance, retries=0):
        
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
                return self.DisableEnable(instance, retries+1)
            else:
                sys.exit("Device is unresponsive. Quitting...")   