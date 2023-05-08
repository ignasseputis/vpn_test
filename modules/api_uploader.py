import urllib3
import json
import sys

class APIUploader:
    def __init__(self, *args, **kwargs):
        self.instance=kwargs['instance']
        
    def UploadFile(self, file, fileType, retries=0):
        http = urllib3.PoolManager(timeout=5)
        #file upload url
        url = self.instance.baseURL + "api/services/openvpn/config/" + self.instance.name
        filename=file.split('/')[-1]
        #forming multi-part form data request
        try:
            req=http.request("POST", 
                    url, 
                    fields={
                            'option': fileType, 
                            "file":(filename, open(file).read())},
                        headers={
                                "Authorization": "Bearer "+ self.instance.token
                                },
                        )
            #sends request
            resp=json.loads(req.data.decode('utf-8'))
            #if successful, returns path, else, quit program
            if(resp["success"]==True):
                print("File {0} was uploaded to {1}.".format(file, resp["data"]["path"]))
                return resp["data"]["path"]
            else:
                print("Upload of file {0} has failed.".format(file))
                self.instance.Login()
                raise OSError
        except FileNotFoundError as err:
            sys.exit("File was not found. Quitting...")
        except OSError as err:
            print("Not responding. Trying again...")
            if(retries<5):
                return self.UploadFile(file, fileType, retries+1)
            else:
                print("Device is unresponsive. Moving on to next configuration...")
                raise OSError
        
        
    def FileUpload(self, encryptionType):
        fileDict={}
        print("Uploading files to {0} instance:".format(self.instance.name))
        try:
            if(encryptionType=="psk"):
                PSKPath=self.UploadFile(self.instance.files["secret"], "secret", self.instance)
                fileDict= fileDict | {"secret":PSKPath}

            if(encryptionType=="tls" or encryptionType =="tls_pwd" or encryptionType=="pwd"):
                caPath=self.UploadFile(self.instance.files["ca"], "ca", self.instance)
                fileDict= fileDict | {"ca":caPath}
                
            if(encryptionType=="tls" or encryptionType =="tls_pwd" or (encryptionType=="pwd" and self.instance.type=="server")):
                certPath=self.UploadFile(self.instance.files["cert"], "cert", self.instance)
                fileDict= fileDict | {"cert":certPath}
                keyPath=self.UploadFile(self.instance.files["key"], "key", self.instance)
                fileDict= fileDict | {"key":keyPath}
            
            if((encryptionType=="tls" or encryptionType =="tls_pwd" or encryptionType=="pwd") and self.instance.type=="server"):
                dhPath=self.UploadFile(self.instance.files["dh"], "dh", self.instance)
                fileDict= fileDict | {"dh":dhPath}
            
            if((encryptionType =="tls_pwd" or encryptionType=="pwd") and self.instance.type=="server"):
                pwdPath=self.UploadFile(self.instance.files["userpass"], "userpass", self.instance)
                fileDict= fileDict | {"userpass":pwdPath}
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))
        except OSError as err:
            print("Could not read data off of files:\n{0}".format(err))
            raise OSError

        print("All {name} files were uploaded correctly.\n".format(name=self.instance.name))
        return fileDict