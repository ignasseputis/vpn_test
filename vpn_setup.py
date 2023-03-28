
import requests
import sys
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

#logs in to the device and returns jwt token for further requests
def Login(instance, retries=0):
    print("Trying to connect to {0}".format(instance.baseURL))
    try:
        headers={"Content-Type":"application/json"}
        #login credentials
        params = {"username":"admin", "password":"Admin123"}

        #sends login post request
        resp=requests.post(instance.baseURL+"api/login", json=params, headers=headers,timeout=5).json()
        if(resp["success"]==True):
            print("Login to "+instance.baseURL+" was successful")
            #returns jwt token
            token=resp["jwtToken"]
            return token
        else:
            sys.exit("Unsuccessful login. Quitting...")
    except OSError  as err:
        print("Not responding. Trying again...")
        if(retries<5):
            return Login(instance,retries+1)
        else:
            sys.exit("Couldn't connect to {0}. Quitting...".format(instance.baseURL))
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))

#gets and displays basic device info
def DeviceInfo(instance, retries=0):
    headers={
    "Content-Type":"application/json",
    "Authorization": "Bearer "+instance.token
    }
    try:
        #sends info get request to device
        resp=requests.get(instance.baseURL + "api/system/device/info",headers=headers, timeout=5).json()
        if(resp["success"]==False):
            print("Couldn't get {name} device info".format(name=instance.name))
        else:
            #displays device name and serial number
            print("\n{instanceName} device information:\nDevice name:\n{name}\nDevice serial No.:\n{serial}\n"
            .format(instanceName=instance.name,name=resp["data"]["static"]["device_name"],
                  serial=resp["data"]["mnfinfo"]["serial"]))
    except OSError  as err:
        print("Not responding. Trying again...")
        if(retries<5):
            DeviceInfo(instance, retries+1)
        else:
            sys.exit("Device is unresponsive. Quitting...")
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))


#remove all openVPN instances on device
def RemoveAll(instance):
    print("Removing all OpenVPN instances in {instance} device".format(instance=instance.name))
    #gets status of all device instances
    status = VPNStatus (instance)
    try:
        #deletes all of the instances one by one
        for inst in status["data"]:
            DeleteVPN(instance, inst)
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))

#get's status of device's openVPN instances 
def VPNStatus(instance, retries=0):
    headers={
    "Content-Type":"application/json",
    "Authorization": "Bearer "+instance.token
    }
    try:
        #sends get request
        resp=requests.get(instance.baseURL+"api/services/openvpn/status/",headers=headers, timeout=5).json()
        if(resp["success"]==False):
            sys.exit("Cannot get {name} VPN status".format(name=instance.name))
        else:
            return resp   
    except OSError  as err:
        print("Not responding. Trying again...")
        if(retries<5):
            return VPNStatus(instance,retries+1)
        else:
            sys.exit("Device is unresponsive. Quitting...")
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))

#creates new vpn instance with selected name and type
def CreateVPNInstance(instance, retries=0):
    headers={
    "Content-Type":"application/json",
    "Authorization": "Bearer "+instance.token
    }
    try:
        #request params - selected name and instance type
        params={"data":{"id":instance.name,"type":instance.type}}
    
        #sends post request 
        resp=requests.post(instance.baseURL+"api/services/openvpn/config", json=params, headers=headers, timeout=5).json()
        if(resp["success"]==True):
            print("New {type} instance created: {name}.".format(type=instance.type, name=instance.name))
        else:
            print("New {type} instance could not be created".format(type=instance.type))
        return resp["success"] 
    except OSError  as err:
        print("Not responding. Trying again...")
        if(retries<5):
            return CreateVPNInstance(instance,retries+1)
        else:
            sys.exit("Device is unresponsive. Quitting...")
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))

#deletes vpn instance with selected name
def DeleteVPN(instance, name, retries=0):
    headers={
    "Content-Type":"application/json",
    "Authorization": "Bearer "+instance.token
    }
    try:
        #request params set to selected instance name
        params= {"data":[name]}

        #sends delete request
        resp=requests.delete(instance.baseURL+"api/services/openvpn/config",json=params,headers=headers, timeout=5).json()
        if(resp["success"]==True):
            print("Successfully removed {name} instance".format(name=name))
        else:
            sys.exit("Removing {name} instance failed".format(name=name))
    except OSError  as err:
        print("Not responding. Trying again...")
        if(retries<5):
            return DeleteVPN(instance, name, retries+1)
        else:
            sys.exit("Device is unresponsive. Quitting...")
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))

#sets the device's openvpn config to the settings from the config file
def SetConfig(instance, retries=0):
    url=instance.baseURL+ "api/services/openvpn/config/" + instance.name
    try:
        headers={
        "Content-Type":"application/json",
        "Authorization": "Bearer "+instance.token
        }
        #sets request body to instance config
        body=instance.config
        #sets id and type to the ones from config
        body["data"]["id"]=instance.name
        body["data"]["type"]=instance.type
    
        #sends put request
        resp=requests.put(url, json=body, headers=headers, timeout=5).json()
        if(resp["success"]==True):
            print("The {name} configuration was set successfully.\n".format(name=instance.name))
        else:
            sys.exit("Setting the {name} configuration failed.".format(name=instance.name))
        return resp["success"]
    except OSError  as err:
        print("Not responding. Trying again...")
        if(retries<5):
            return SetConfig(instance,retries+1)
        else:
            sys.exit("Device is unresponsive. Quitting...")
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))

def main():
    pass
    
if __name__ == "__main__":
    main()