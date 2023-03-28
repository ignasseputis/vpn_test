import json
import requests
import sys
import urllib3
import csv
import ftplib
from ftplib import FTP
from datetime import datetime

from test_program import VPNInstance

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
    

#sends file over FTP
def SendFileFTP(filename, credentials):
    #connects to FTP server
    try:
        ftp=ftplib.FTP()
        ftp.connect(credentials["ip_addr"], int(credentials["port"]))
        ftp.login(credentials["user"], credentials["pwd"])
    
        #generates new file name
        newName="output {date}.csv".format(date=str(datetime.now())[0:19], file=filename)
        #sends file
        ftp.storbinary('STOR '+newName, open(filename, 'rb'))
        #disconnects from server
        ftp.quit()
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    except ftplib.all_errors as err:
        sys.exit("Could not send file due to FTP error:\n{0}".format(err))

#returns openvpn instance after reading config file of
#selected type
def GetInstance(filename, type):
    #gets the data from file
    instanceData=ReadInstanceData(filename, type)
    try:
        #assigns values from file to variables
        baseInstanceURL=instanceData["ip_addr"]
        instanceType=instanceData["inst_type"]
        instanceName=instanceData["inst_name"]
        instanceUser=instanceData["user"]
        instancePwd=instanceData["pwd"]
        instancePort=instanceData["port"]
        instanceConfig={"data" : instanceData["data"]}
        instanceFiles=instanceData["files"]
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    #creates new instance from variables
    instance=VPNInstance(baseInstanceURL, instanceType, 
                        instanceName, instanceConfig, instanceFiles, 
                        instanceUser, instancePwd, instancePort)
    return instance

#uploads one of the certificate files to device
def UploadFile(file, fileType, instance, retries=0):
    http = urllib3.PoolManager(timeout=5)
    #file upload url
    url = instance.baseURL + "api/services/openvpn/config/" + instance.name
    #forming multi-part form data request
    try:
        req=http.request("POST", 
                   url, 
                   fields={
                        'option': fileType, 
                        "file":(file, open(file).read())},
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
            sys.exit("Upload of file {name} has failed.".format(name=file))
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
            sys.exit("Setting {name} {type} file was not successful.\n".
              format(name=instance.name, type = type, path = path))
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    except OSError as err:
        print("Not responding. Trying again...")
        if(retries<5):
            return PutFile(path, type, instance, retries+1)
        else:
            sys.exit("Device is unresponsive. Quitting...")
    
    
    

#uploads all files to device and sets their values in config
def UploadFiles(instance):
    try:
        caPath=UploadFile(instance.files["ca"], "ca", instance)
        PutFile(caPath, "ca", instance)
        certPath=UploadFile(instance.files["cert"], "cert", instance)
        PutFile(certPath, "cert", instance)
        keyPath=UploadFile(instance.files["key"], "key", instance)
        PutFile(keyPath, "key", instance)
        if(instance.type=="server"):
            dhPath=UploadFile(instance.files["dh"], "dh", instance)
            PutFile(dhPath, "dh", instance)
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))

    print("All {name} files were uploaded correctly.\n\n".format(name=instance.name))

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