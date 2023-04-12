import json
import requests
import sys
import urllib3
import csv
import ftplib
from ftplib import FTP
from datetime import datetime
from time import sleep

from test_program import VPNInstance
from vpn_setup import Login
#opens config file and gets selected type openvpn instance config
def ReadInstanceData(filename, type):
    try:
        mainConfig = json.loads(open(filename).read())
        instanceData=mainConfig[type]
        return instanceData
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    except IOError as err:
        sys.exit("Reading the configuration file was not successful:\n{0}".format(err))
    

#opens config file and gets FTP server creds
def ReadCredentials(filename):
    try:
        mainConfig = json.loads(open(filename).read())
        credentialsFTP=mainConfig["ftp"]
        return credentialsFTP
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    except IOError as err:
        sys.exit("Reading the configuration file was not successful:\n{0}".format(err))
    
def ReadTestConfigs(filename):
    try:
        mainConfig = json.loads(open(filename).read())
        credentialsFTP=mainConfig["tests"]
        return credentialsFTP
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    except IOError as err:
        sys.exit("Reading the configuration file was not successful:\n{0}".format(err))

#sends file over FTP
def SendFileFTP(filename, credentials, deviceName, uploadDirectory):
    #connects to FTP server
    try:
        ftp=ftplib.FTP()
        ftp.connect(credentials["ip_addr"], int(credentials["port"]))
        ftp.login(credentials["user"], credentials["pwd"])
        ChangeDir(ftp, uploadDirectory)
        #generates new file name
        newName="{device} {date}.csv".format(date=str(datetime.now())[0:19],device=deviceName, file=filename)
        #sends file
        ftp.storbinary('STOR '+newName, open(filename, 'rb'))
        #disconnects from server
        ftp.quit()
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    except ftplib.all_errors as err:
        sys.exit("Could not send file due to FTP error:\n{0}".format(err))


def ChangeDir(ftp, uploadDir):
    if uploadDir != "":
        try:
            ftp.cwd(uploadDir)
        except ftplib.all_errors:
            ftp.mkd(uploadDir.split("/")[-1])
            ftp.cwd(uploadDir)

#returns openvpn instance after reading config file of
#selected type
def GetInstance(filename, type, ip_addr):
    #gets the data from file
    instanceData=ReadInstanceData(filename, type)
    try:
        #assigns values from file to variables
        if(ip_addr == ""):
            baseInstanceURL=instanceData["ip_addr"]
            
        else:
            baseInstanceURL=ip_addr

        instanceType=instanceData["inst_type"]
        instanceName=instanceData["inst_name"]
        instanceUser=instanceData["user"]
        instancePwd=instanceData["pwd"]
        instancePort=instanceData["port"]
        instanceVPNConfigs={
            "tun_tls_config": instanceData["tun_tls_config"],
            "tun_tls_pwd_config": instanceData["tun_tls_pwd_config"],
            "tun_pwd_config": instanceData["tun_pwd_config"],
            "tun_psk_config": instanceData["tun_psk_config"],
            "tap_tls_config": instanceData["tap_tls_config"],
            "tap_tls_pwd_config": instanceData["tap_tls_pwd_config"],
            "tap_pwd_config": instanceData["tap_pwd_config"],
            "tap_psk_config": instanceData["tap_psk_config"]
            }
        instanceFiles=instanceData["files"]
        if(instanceType=="server"):
            instanceTunLAN=instanceData["tun_lan_config"]
            instanceTapLAN=instanceData["tap_lan_config"]
        else:
            instanceTunLAN=""
            instanceTapLAN=""
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    #creates new instance from variables
    instance=VPNInstance(baseInstanceURL, instanceType, 
                        instanceName, instanceVPNConfigs, instanceFiles, instanceUser, instancePwd, instancePort, instanceTunLAN, instanceTapLAN)
    return instance

#uploads one of the certificate files to device
def UploadFile(file, fileType, instance, retries=0):
    http = urllib3.PoolManager(timeout=5)
    #file upload url
    url = instance.baseURL + "api/services/openvpn/config/" + instance.name
    filename=file.split('/')[-1]
    #forming multi-part form data request
    try:
        req=http.request("POST", 
                   url, 
                   fields={
                        'option': fileType, 
                        "file":(filename, open(file).read())},
                    headers={
                            "Authorization": "Bearer "+ instance.token
                            },
                    )
        #sends request
        resp=json.loads(req.data.decode('utf-8'))
        #if successful, returns path, else, quit program
        if(resp["success"]==True):
            print("File {name} was uploaded to {path}.".format(name=file, path=resp["data"]["path"]))
            return resp["data"]["path"]
        else:
            print("Upload of file {name} has failed.".format(name=file))
            jwtToken=Login(instance)
            if(instance.type=="server"):
                instance.token=jwtToken
                global serverInstance
                serverInstance=instance
            if(instance.type=="client"):
                instance.token=jwtToken
                global clientInstance
                clientInstance=instance
            raise OSError
    except FileNotFoundError as err:
        sys.exit("File was not found. Quitting...")
    except OSError as err:
        print("Not responding. Trying again...")
        if(retries<5):
            return UploadFile(file, fileType, instance, retries+1)
        else:
            sys.exit("Device is unresponsive. Quitting...")
    
#adds uploaded file to instance config
def PutFile(path, type, instance, retries=0):
    #instance config url
    url=instance.baseURL+ "api/services/openvpn/config/" + instance.name
    #request headers and body
    headers={
    "Content-Type":"application/json",
    "Authorization": "Bearer "+instance.token
    }
    body = {
    "success": True,
    "data": {type: path}
    }
    #sends request
    try:
        resp=requests.put(url, json=body, headers=headers, timeout=5).json()
    
        #if successful, outputs success to terminal,
        #else quits program
        if(resp["success"]==True):
            print("{name} {type} file was set to {path}.\n"
              .format(name=instance.name, type = type, path = path))
            return resp["success"]
        else:
            print("Setting {name} {type} file was not successful.\n".
              format(name=instance.name, type = type, path = path))
            jwtToken=Login(instance)
            if(instance.type=="server"):
                instance.token=jwtToken
                global serverInstance
                serverInstance=instance
            if(instance.type=="client"):
                instance.token=jwtToken
                global clientInstance
                clientInstance=instance
            raise OSError
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    except OSError as err:
        print("Not responding. Trying again...")
        if(retries<5):
            return PutFile(path, type, instance, retries+1)
        else:
            sys.exit("Device is unresponsive. Quitting...")
    
    
    
def FileUpload(instance, encryptionType):
    
    print("Uploading files to {0} instance:".format(instance.name))
    try:
        if(encryptionType=="psk"):
            PSKPath=UploadFile(instance.files["secret"], "secret", instance)
            PutFile(PSKPath, "secret", instance)

        if(encryptionType=="tls" or encryptionType =="tls_pwd" or encryptionType=="pwd"):
            caPath=UploadFile(instance.files["ca"], "ca", instance)
            PutFile(caPath, "ca", instance)
            
        if(encryptionType=="tls" or encryptionType =="tls_pwd" or (encryptionType=="pwd" and instance.type=="server")):
            certPath=UploadFile(instance.files["cert"], "cert", instance)
            PutFile(certPath, "cert", instance)
            keyPath=UploadFile(instance.files["key"], "key", instance)
            PutFile(keyPath, "key", instance)
        
        if((encryptionType=="tls" or encryptionType =="tls_pwd" or encryptionType=="pwd") and instance.type=="server"):
            dhPath=UploadFile(instance.files["dh"], "dh", instance)
            PutFile(dhPath, "dh", instance)
        
        if((encryptionType =="tls_pwd" or encryptionType=="pwd") and instance.type=="server"):
            pwdPath=UploadFile(instance.files["userpass"], "userpass", instance)
            PutFile(pwdPath, "userpass", instance)
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    except OSError as err:
        sys.exit("Could not read data off of files:\n{0}".format(err))

    print("All {name} files were uploaded correctly.\n".format(name=instance.name))
    pass 

#opens csv file and appends row to end of it
def WriteData(file, data):
    try:
        with open(file, 'a') as f:
            writer = csv.writer(f)
            writer.writerow(data)
    except IOError as err:
        sys.exit("Writing file to {0} file was unsuccessful:\n{1}".format(file, err))

def main():
    pass
    
if __name__ == "__main__":
    main()