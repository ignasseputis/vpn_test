import ftplib
import sys
from datetime import datetime

class FTPInstance:
    def __init__(self, *args, **kwargs):
        self.ftp=None
        self.credentials=None


    def Connect(self, credentials):
        self.credentials=credentials
        try:
            self.ftp=ftplib.FTP(host=credentials["ip_addr"],
                           user=credentials["user"],
                           passwd=credentials["pwd"])
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))
        except ftplib.all_errors as err:
            sys.exit("Could not connect to FTP server:\n{0}".format(err))
    
    def ChangeDir(self, dirName):
        if dirName != "":
            try:
                self.ftp.cwd(dirName)
            except ftplib.all_errors:
                self.ftp.mkd(dirName.split("/")[-1])
                self.ftp.cwd(dirName)

    def SendFile(self, filename, deviceName):
        try:
            newName="{0} {1}.csv".format(deviceName, str(datetime.now())[0:19])
            #sends file
            self.ftp.storbinary('STOR '+newName, open(filename, 'rb'))
        except ftplib.error_temp:
            self.Connect(self.credentials)
            self.SendFile(filename, deviceName)

    
    def Disconnect(self):
        print("Closing FTP session")
        self.ftp.close()