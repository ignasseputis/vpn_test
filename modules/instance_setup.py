import sys
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
from time import sleep

from modules.api_uploader import APIUploader
from modules.ssh_handler import SSHInstance

class VPNInstance:
    def __init__(self, *args, **kwargs):
        self.url = None
        self.baseURL = None#"http://"+URL+"/"
        self.type = None
        self.name = None
        self.token = None
            
        self.tun_tls_config=None
        self.tun_tls_pwd_config=None
        self.tun_pwd_config=None
        self.tun_psk_config=None

        self.tap_tls_config=None
        self.tap_tls_pwd_config=None
        self.tap_pwd_config=None
        self.tap_psk_config=None

        self.files=None
        
        self.tun_lan=None
        self.tap_lan=None
        self.deviceName=None
        
        self.user=None
        self.pwd=None
        self.port=None

        self.uploader=None
        self.sshClient=None
        


    def GetInstance(self, configReader, inst_type, ip_addr):
        instanceData=configReader.ReadInstanceData(inst_type)
        try:
            if(ip_addr == ""):
                ip_address=instanceData["ip_addr"]
            else:
                ip_address=ip_addr
            
            self.url=ip_address
            self.baseURL="http://"+ip_address+"/"
            self.type=instanceData["inst_type"]
            self.name=instanceData["inst_name"]
            
            self.tun_tls_config=instanceData["tun_tls_config"]
            self.tun_tls_pwd_config=instanceData["tun_tls_pwd_config"]
            self.tun_pwd_config=instanceData["tun_pwd_config"]
            self.tun_psk_config=instanceData["tun_psk_config"]

            self.tap_tls_config=instanceData["tap_tls_config"]
            self.tap_tls_pwd_config=instanceData["tap_tls_pwd_config"]
            self.tap_pwd_config=instanceData["tap_pwd_config"]
            self.tap_psk_config=instanceData["tap_psk_config"]

            self.files=instanceData["files"]

            self.user=instanceData["user"]
            self.pwd=instanceData["pwd"]
            self.port=instanceData["port"]

            if(self.type=="server"):
                self.tun_lan=instanceData["tun_lan_config"]
                self.tap_lan=instanceData["tap_lan_config"]
           
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))
    
    def Login(self, retries=0):
        print("Trying to connect to {0} at {1}".format(self.type,self.baseURL))
        try:
            headers={"Content-Type":"application/json"}
            #login credentials
            params = {"username":"admin", "password":"Admin123"}

            #sends login post request
            resp=requests.post(self.baseURL+"api/login", json=params, headers=headers,timeout=5).json()
            if(resp["success"]==True):
                print("Login to "+self.baseURL+" was successful\n")
                #returns jwt token
                token=resp["jwtToken"]
                self.token=token
                self.uploader=APIUploader(instance=self)
                return token
            else:
                sys.exit("Unsuccessful login. Quitting...")
        except OSError  as err:
            print("Not responding. Trying again...")
            if(retries<10):
                sleep(5)
                return self.Login(retries+1)
            else:
                sys.exit("Couldn't connect to {0}. Quitting...".format(self.baseURL))
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))
        except json.decoder.JSONDecodeError as err:
            sys.exit("Selected IP address returned a response that isn't readable. Quitting...")

    def SetUpSSH(self):
        self.sshClient=SSHInstance(address=self.url, 
            user=self.user, pwd=self.pwd, port= self.port)
        self.sshClient.SSHConnect()

    def CloseSSH(self):
        self.sshClient.Close()

    def DeviceInfo(self, retries=0):
        headers={
        "Content-Type":"application/json",
        "Authorization": "Bearer "+self.token
        }
        try:
            #sends info get request to device
            resp=requests.get(self.baseURL + "api/system/device/info",headers=headers, timeout=5).json()
            if(resp["success"]==False):
                print("Couldn't get {0} device info".format(self.name))
                self.Login()
                raise OSError
            else:
                #displays device name and serial number
                print("\n{0} device information:\nDevice name:\n{1}\nDevice serial No.:\n{2}\n"
                .format(self.name,resp["data"]["static"]["device_name"],
                    resp["data"]["mnfinfo"]["serial"]))
                self.deviceName=resp["data"]["static"]["device_name"]
                return resp["data"]["static"]["device_name"]
        except OSError  as err:
            print("Not responding. Trying again...")
            if(retries<5):
                self.DeviceInfo(retries+1)
            else:
                sys.exit("Device is unresponsive. Quitting...")
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))

    def DeleteVPN(self, name, retries=0):
        headers={
        "Content-Type":"application/json",
        "Authorization": "Bearer "+self.token
        }
        try:
            #request params set to selected instance name
            params= {"data":[name]}
            #sends delete request
            resp=requests.delete(self.baseURL+"api/services/openvpn/config",json=params,headers=headers, timeout=5).json()
            if(resp["success"]==True):
                print("Successfully removed {0} instance".format(name))
            else:
                print("Removing {0} instance failed".format(name))
                self.Login()
                raise OSError
        except OSError  as err:
            print("Not responding. Trying again...")
            if(retries<5):
                return self.DeleteVPN(name, retries+1)
            else:
                sys.exit("Device is unresponsive. Quitting...")
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))    


    def RemoveAll(self):
        print("Removing all OpenVPN instances in {0} device".format(self.name))
        #gets status of all device instances
        status = self.VPNStatus()
        try:
            #deletes all of the instances one by one
            for inst in status["data"]:
                self.DeleteVPN(inst)
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))

    def VPNStatus(self, retries=0):
        headers={
        "Content-Type":"application/json",
        "Authorization": "Bearer "+self.token
        }
        try:
            #sends get request
            resp=requests.get(self.baseURL+"api/services/openvpn/status/",headers=headers, timeout=10).json()
            if(resp["success"]==False):
                print("Cannot get {name} VPN status".format(name=self.name))
                self.Login()
                raise OSError
            else:
                return resp   
        except OSError  as err:
            print("Not responding. Trying again... ")
            if(retries<5):
                return self.VPNStatus(retries+1)
            else:
                sys.exit("Device is unresponsive. Quitting...")
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))

    def CreateVPNInstance(self, retries=0):
        print("\nCreating OpenVPN {0} instance...".format(self.type))
        headers={
        "Content-Type":"application/json",
        "Authorization": "Bearer "+self.token
        }
        try:
            #request params - selected name and instance type
            params={"data":{"id":self.name,"type":self.type}}
        
            #sends post request 
            resp=requests.post(self.baseURL+"api/services/openvpn/config", json=params, headers=headers, timeout=5).json()
            if(resp["success"]==True):
                print("New {0} instance created: {1}.\n".format(self.type, self.name))
            else:
                print("New {0} instance could not be created\n".format(self.type))
                self.Login()
                raise OSError
            return resp["success"] 
        except OSError  as err:
            print("Not responding. Trying again...")
            if(retries<5):
                return self.CreateVPNInstance(retries=retries+1)
            else:
                sys.exit("Device is unresponsive. Quitting...")
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))

    def SetConfig(self, conf, retries=0):
        url=self.baseURL+ "api/services/openvpn/config/" + self.name
        try:
            headers={
            "Content-Type":"application/json",
            "Authorization": "Bearer "+self.token
            }
            #sets request body to instance config
            body=conf
            #sets id and type to the ones from config
            body["data"]["id"]=self.name
            body["data"]["type"]=self.type
        
            #sends put request
            resp=requests.put(url, json=body, headers=headers, timeout=5).json()
            if(resp["success"]==True):
                print("The {0} configuration was set successfully.\n".format(self.name))
            else:
                print("Setting the {0} configuration failed: {1}".format(self.name, resp))
                self.Login()
                
                raise OSError
            return resp["success"]
        except OSError  as err:
            print("Not responding. Trying again...")
            if(retries<5):
                return self.SetConfig(conf, retries+1)
            else:
                sys.exit("Device is unresponsive. Quitting...")
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))

    def AddHMAC(self, testConfig, additionalAuth):
        match additionalAuth:
            case "tls-crypt":
                HMACPath=self.uploader.UploadFile(self.files["hmac"], "tls_crypt",self)
                newTestConfig = testConfig | {"tls_crypt": HMACPath}
                return newTestConfig
            case "tls-auth":
                HMACPath=self.uploader.UploadFile(self.files["hmac"], "tls_auth",self)
                if(self.type=="server"):
                    newTestConfig = testConfig | {"tls_auth": HMACPath, "key_direction": "1"}
                if(self.type=="client"):
                    newTestConfig = testConfig | {"tls_auth": HMACPath, "key_direction": "0"}
                sleep(2)    
                return newTestConfig
            case _:
                return testConfig
            
        
    
    def ChangeLAN(self, connectionType, retries=0):
        print("Changing LAN settings for {0} connection...".format(connectionType))

        url=self.baseURL+ "api/bulk"
        match connectionType:
            case "tun":
                configLAN=self.tun_lan
            case "tap":
                configLAN=self.tap_lan
            case _:
                sys.exit("Selected connection type does not exist. Quitting...")
        try:
            headers={
            "Content-Type":"application/json",
            "Authorization": "Bearer "+self.token
            }
            #sets request body to instance LAN config
            body=configLAN
            #sends put request
            resp=requests.post(url, json=body, headers=headers, timeout=5).json()
            sleep(5)
            if(resp["success"]==True):
                print("The {0} LAN configuration was successfully set to {1}.\n".format(self.name, resp["data"][0]["data"]["ipaddr"]))
            else:
                print("Setting the {0} LAN configuration failed.:\n{1}".format(self.name, str(resp)))
                self.Login()
                raise OSError
            return resp["success"]
        except OSError  as err:
            print("Not responding. Trying again...:\n{0}".format(err))
            if(retries<5):
                return self.ChangeLAN(configLAN, retries+1)
            else:
                sys.exit("Device is unresponsive. Quitting...")

    def SetUpVPN(self,connection, authentication, testConfig, additionalAuth=""):
        self.RemoveAll()
        
        self.CreateVPNInstance(self) #creates new instance

        fileDict=self.uploader.FileUpload(authentication) #uploads and sets all certificate file
        if(len(additionalAuth)>0):
            newTestConfig=self.AddHMAC(testConfig, additionalAuth)
            sleep(2)
            newTestConfig=newTestConfig |fileDict
        else:
            newTestConfig=testConfig |fileDict

        
        sleep(2)

        match [connection, authentication]:
            case ["tun", "tls"]:
                newConf={"data":self.tun_tls_config["data"]|newTestConfig}
                resp=self.SetConfig(newConf) #sets configuration
            case ["tun", "tls_pwd"]:
                newConf={"data":self.tun_tls_pwd_config["data"]|newTestConfig}
                resp=self.SetConfig(newConf) #sets configuration   
            case ["tun", "pwd"]:
                newConf={"data":self.tun_pwd_config["data"]|newTestConfig}
                resp=self.SetConfig(newConf) #sets configuration     
            case ["tun", "psk"]:
                newConf={"data":self.tun_psk_config["data"]|newTestConfig}
                resp=self.SetConfig(newConf) #sets configuration
            case ["tap", "tls"]:
                newConf={"data":self.tap_tls_config["data"]|newTestConfig}
                resp=self.SetConfig(newConf) #sets configuration
            case ["tap", "tls_pwd"]:
                newConf={"data":self.tap_tls_pwd_config["data"]|newTestConfig}
                resp=self.SetConfig(newConf) #sets configuration    
            case ["tap", "pwd"]:
                newConf={"data":self.tap_pwd_config["data"]|newTestConfig}
                resp=self.SetConfig(newConf) #sets configuration   
            case ["tap", "psk"]:
                newConf={"data":self.tap_psk_config["data"]|newTestConfig}
                resp=self.SetConfig(newConf) #sets configuration
        print("{0} setup is finished.\n\n".format(self.name))