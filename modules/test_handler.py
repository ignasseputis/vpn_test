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
        for connection in self.arguments.connection_types:
            self.instanceServer.ChangeLAN(connection)
            infoLine="Connection type: {0}".format(connection)
            self.SetAuthenticationConfig(connection, infoLine)
        

    def SetAuthenticationConfig(self, connection, infoLineOld):
        for auth in self.arguments.auth_types:
            serverConfig={}
            clientConfig={}
            infoLine=infoLineOld+", Authentication type: "+auth 
            self.SetProtocolConfig(connection, auth, serverConfig, clientConfig, infoLine)

    def SetProtocolConfig(self, connection, authentication, serverConfig, clientConfig, infoLineOld):
        for protocol in self.arguments.protocols:
            infoLine=infoLineOld+", Protocol: "+protocol["server"]["proto"]
            newServerConfig=serverConfig | protocol["server"]
            newClientConfig=clientConfig | protocol["client"]
            self.SetLZOConfig(connection, authentication, infoLine, newServerConfig, newClientConfig)

    def SetLZOConfig(self, connection, authentication, infoLineOld, serverConfig, clientConfig):
        for lzo in self.arguments.lzo:
            infoLine=infoLineOld+", LZO: "+lzo["comp_lzo"]
            newServerConfig=serverConfig | lzo
            newClientConfig=clientConfig | lzo
            self.SetEncryptionConfig(connection, authentication, infoLine, newServerConfig, newClientConfig)

    def SetEncryptionConfig(self, connection, authentication, infoLineOld, serverConfig, clientConfig):
        match authentication:
            case "psk":
                encryptionProtocols=self.arguments.psk_encryption_types
            case "tls" | "tls_pwd" | "pwd":
                encryptionProtocols=self.arguments.encryption_types
        for encryption in encryptionProtocols:
            infoLine=infoLineOld+", Encryption protocol: "+encryption["cipher"]
            newServerConfig=serverConfig | encryption
            newClientConfig=clientConfig | encryption
            match authentication:
                case "psk":
                    self.InitiateTest(connection, authentication, infoLine, newServerConfig, newClientConfig)
                case "tls" | "tls_pwd":
                    self.SetTLSCipherConfig(connection, authentication, infoLine, newServerConfig, newClientConfig)
                case "pwd":
                    self.SetAuthAlgoConfig(connection, authentication, infoLine, newServerConfig, newClientConfig)

    def SetTLSCipherConfig(self, connection, authentication, infoLineOld, serverConfig, clientConfig):
        for TLSCipher in self.arguments.tls_cipher:
            if(TLSCipher["_tls_cipher"]=="all"):
                infoLine=infoLineOld+", TLS cipher: "+TLSCipher["_tls_cipher"]
            else:
                infoLine=infoLineOld+", TLS cipher: "+TLSCipher["tls_cipher"][0]

            newServerConfig=serverConfig | TLSCipher
            newClientConfig=clientConfig | TLSCipher
            self.SetAuthAlgoConfig(connection, authentication, infoLine, newServerConfig, newClientConfig)

    def SetAuthAlgoConfig(self, connection, authentication, infoLineOld, serverConfig, clientConfig):
        for auth in self.arguments.authentication_algorithms:
            infoLine=infoLineOld+", Authentication algorithm: " + auth["auth"]
            newServerConfig=serverConfig | auth
            newClientConfig=clientConfig | auth
            self.SetHMACConfig(connection, authentication, infoLine, newServerConfig, newClientConfig)

    def SetHMACConfig(self, connection, authentication, infoLineOld, serverConfig, clientConfig):
        for hmac in self.arguments.hmac_authentication:
            infoLine=infoLineOld+", Additional HMAC authentication: " + hmac["_tls_auth"]
            newServerConfig=serverConfig | hmac
            newClientConfig=clientConfig | hmac 
            self.InitiateTest(connection, authentication, infoLine, newServerConfig, newClientConfig, True)

    def InitiateTest(self, connection, authentication, infoLine, serverConfig, clientConfig, hmac=False):
        
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
        speedTest.InitiateSpeedtest(infoLine, self.arguments.test_count, self.arguments.test_length, connection)

        self.SendFile()

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
    