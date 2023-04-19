from time import sleep
import os

from modules.speed_test import SpeedTest
from modules.csv_handler import CSVHandler


class TestHandler:
    def __init__(self, *args, **kwargs):
        
        self.instanceServer=kwargs['server']
        self.instanceClient=kwargs['client']
        self.ftp=kwargs['ftp']
        self.arguments=kwargs["arguments"]
        self.outFile=kwargs["outFile"]
        self.csv=CSVHandler(outFile=self.outFile)
        
        
    def TestVPN(self):
        self.csv.PrepareCSV(self.arguments, self.instanceServer, self.instanceClient)
        infoDict={"connectionType":"","authenticationType":"","protocol":"","lzo":"",
                  "encryptionProtocol":"","tlsCipher":"", "authenticationAlgorithm":"",
                  "additionalHMACAuthentication":""}
        for connection in self.arguments.connection_types:
            self.instanceServer.ChangeLAN(connection)
            newInfoDict=infoDict|{"connectionType":connection}
            infoLine="Connection type: {0}".format(connection)
            self.SetAuthenticationConfig(connection, infoLine, newInfoDict)
        self.SendFile()
        

    def SetAuthenticationConfig(self, connection, infoLineOld, infoDict):
        for auth in self.arguments.auth_types:
            serverConfig={}
            clientConfig={}
            newInfoDict=infoDict|{"authenticationType":auth}
            infoLine=infoLineOld+", Authentication type: "+auth 
            self.SetProtocolConfig(connection, auth, serverConfig, clientConfig, infoLine, newInfoDict)

    def SetProtocolConfig(self, connection, authentication, serverConfig, clientConfig, infoLineOld, infoDict):
        for protocol in self.arguments.protocols:
            newInfoDict=infoDict|{"protocol":protocol["server"]["proto"][0:3]}
            infoLine=infoLineOld+", Protocol: "+protocol["server"]["proto"]
            newServerConfig=serverConfig | protocol["server"]
            newClientConfig=clientConfig | protocol["client"]
            self.SetLZOConfig(connection, authentication, infoLine, newServerConfig, newClientConfig, newInfoDict)

    def SetLZOConfig(self, connection, authentication, infoLineOld, serverConfig, clientConfig, infoDict):
        for lzo in self.arguments.lzo:
            newInfoDict=infoDict|{"lzo":lzo["comp_lzo"]}
            infoLine=infoLineOld+", LZO: "+lzo["comp_lzo"]
            newServerConfig=serverConfig | lzo
            newClientConfig=clientConfig | lzo
            self.SetEncryptionConfig(connection, authentication, infoLine, newServerConfig, newClientConfig, newInfoDict)

    def SetEncryptionConfig(self, connection, authentication, infoLineOld, serverConfig, clientConfig, infoDict):
        match authentication:
            case "psk":
                encryptionProtocols=self.arguments.psk_encryption_types
            case "tls" | "tls_pwd" | "pwd":
                encryptionProtocols=self.arguments.encryption_types
        for encryption in encryptionProtocols:
            newInfoDict=infoDict|{"encryptionProtocol": encryption["cipher"]}
            infoLine=infoLineOld+", Encryption protocol: "+encryption["cipher"]
            newServerConfig=serverConfig | encryption
            newClientConfig=clientConfig | encryption
            match authentication:
                case "psk":
                    self.InitiateTest(connection, authentication, infoLine, newServerConfig, newClientConfig, newInfoDict)
                case "tls" | "tls_pwd":
                    self.SetTLSCipherConfig(connection, authentication, infoLine, newServerConfig, newClientConfig, newInfoDict)
                case "pwd":
                    self.SetAuthAlgoConfig(connection, authentication, infoLine, newServerConfig, newClientConfig, newInfoDict)

    def SetTLSCipherConfig(self, connection, authentication, infoLineOld, serverConfig, clientConfig, infoDict):
        for TLSCipher in self.arguments.tls_cipher:
            if(TLSCipher["_tls_cipher"]=="all"):
                newInfoDict=infoDict|{"tlsCipher": TLSCipher["_tls_cipher"]}
                infoLine=infoLineOld+", TLS cipher: "+TLSCipher["_tls_cipher"]
            else:
                newInfoDict=infoDict|{"tlsCipher": TLSCipher["tls_cipher"][0]}
                infoLine=infoLineOld+", TLS cipher: "+TLSCipher["tls_cipher"][0]

            newServerConfig=serverConfig | TLSCipher
            newClientConfig=clientConfig | TLSCipher
            self.SetAuthAlgoConfig(connection, authentication, infoLine, newServerConfig, newClientConfig, newInfoDict)

    def SetAuthAlgoConfig(self, connection, authentication, infoLineOld, serverConfig, clientConfig, infoDict):
        for auth in self.arguments.authentication_algorithms:
            newInfoDict=infoDict| {"authenticationAlgorithm":auth["auth"]}
            infoLine=infoLineOld+", Authentication algorithm: " + auth["auth"]
            newServerConfig=serverConfig | auth
            newClientConfig=clientConfig | auth
            self.SetHMACConfig(connection, authentication, infoLine, newServerConfig, newClientConfig,newInfoDict)

    def SetHMACConfig(self, connection, authentication, infoLineOld, serverConfig, clientConfig, infoDict):
        for hmac in self.arguments.hmac_authentication:
            newInfoDict=infoDict|{"additionalHMACAuthentication": hmac["_tls_auth"]}
            infoLine=infoLineOld+", Additional HMAC authentication: " + hmac["_tls_auth"]
            newServerConfig=serverConfig | hmac
            newClientConfig=clientConfig | hmac 
            self.InitiateTest(connection, authentication, infoLine, newServerConfig, newClientConfig, newInfoDict, True)

    def InitiateTest(self, connection, authentication, infoLine, serverConfig, clientConfig, newInfoDict, hmac=False):
        parameters=list(newInfoDict.values())
        newClientConfig=clientConfig|{"remote": self.instanceServer.url}

        print("Setting the configuration to:\n{0}\n".format(infoLine))
        if(hmac==True):
            hmac_line=serverConfig["_tls_auth"]
        else:
            hmac_line=""
        self.instanceServer.SetUpVPN(connection, authentication, serverConfig, hmac_line)
        self.instanceClient.SetUpVPN(connection, authentication, newClientConfig, hmac_line)

        sleep(5)

        speedTest=SpeedTest(server=self.instanceServer, client=self.instanceClient, output=self.outFile, csv=self.csv)
        speedTest.InitiateSpeedtest(infoLine, self.arguments.test_count, self.arguments.test_length, connection, parameters)

        #self.SendFile()

        print(infoLine)
        print("\n\n")
    
    def SendFile(self):
        if(os.path.isfile(self.outFile)):
            print("Sending {0} data file to FTP server...".format(self.outFile))
            #sends data file to FTP server
            self.ftp.SendFile(self.outFile, self.instanceClient.deviceName)
            print("File transfer was successful.")
        else:
            print("{filename} file does not exist.".format(filename=self.outFile))
    