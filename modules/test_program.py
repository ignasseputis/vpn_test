from time import sleep
import sys
from datetime import datetime
import os
import argparse
import ipaddress
import paramiko

import files
import vpn_setup
import speed_test
import argument_verification


#class of an OpenVPN instance
class VPNInstance:
    def __init__(self, URL="", type="", name="", vpn_configs={}, files="", user="", pwd="", port="", tun_lan="", tap_lan=""):
        self.url=URL
        self.baseURL = "http://"+URL+"/"
        self.type = type
        self.name = name
        self.token = ""
        if(len(vpn_configs) !=0):
            self.tun_tls_config=vpn_configs["tun_tls_config"]
            self.tun_tls_pwd_config=vpn_configs["tun_tls_pwd_config"]
            self.tun_pwd_config=vpn_configs["tun_pwd_config"]
            self.tun_psk_config=vpn_configs["tun_psk_config"]

            self.tap_tls_config=vpn_configs["tap_tls_config"]
            self.tap_tls_pwd_config=vpn_configs["tap_tls_pwd_config"]
            self.tap_pwd_config=vpn_configs["tap_pwd_config"]
            self.tap_psk_config=vpn_configs["tap_psk_config"]
        else:
            self.tun_tls_config=""
            self.tun_tls_pwd_config=""
            self.tun_pwd_config=""
            self.tun_psk_config=""

            self.tap_tls_config=""
            self.tap_tls_pwd_config=""
            self.tap_pwd_config=""
            self.tap_psk_config=""

        self.files=files
        self.user=user
        self.pwd=pwd
        self.port=port
        self.tun_lan=tun_lan
        self.tap_lan=tap_lan
        self.deviceName=""


configFile="./files/config.json" #main config file n ame
outFile = "./files/output.csv" #test data output file name

serverInstance=VPNInstance()
clientInstance=VPNInstance()

def VPNSetup(instance, connectionType, encryptionType, testConfig, additionalAuth=""):
    vpn_setup.RemoveAll(instance) #removes all instances on device
    print("\nCreating OpenVPN {type} instance...".format(type=instance.type))
    resp=vpn_setup.CreateVPNInstance(instance) #creates new instance

    if(additionalAuth=="tls-crypt"):
        HMACPath=files.UploadFile(instance.files["hmac"], "tls_crypt",instance)
        testConfig = testConfig | {"tls_crypt": HMACPath}
    if(additionalAuth=="tls-auth"):
        HMACPath=files.UploadFile(instance.files["hmac"], "tls_auth",instance)
        if(instance.type=="server"):
            testConfig = testConfig | {"tls_auth": HMACPath, "key_direction": "1"}
        if(instance.type=="client"):
            testConfig = testConfig | {"tls_auth": HMACPath, "key_direction": "0"}    
        
    files.FileUpload(instance, encryptionType) #uploads and sets all certificate file
    sleep(1)
    if(connectionType=="tun"):
        if(encryptionType=="tls"):
            newConf={"data":instance.tun_tls_config["data"]|testConfig}
            resp=vpn_setup.SetConfig(instance, newConf) #sets configuration
        elif(encryptionType=="tls_pwd"):
            newConf={"data":instance.tun_tls_pwd_config["data"]|testConfig}
            resp=vpn_setup.SetConfig(instance, newConf) #sets configuration       
        elif(encryptionType=="pwd"):
            newConf={"data":instance.tun_pwd_config["data"]|testConfig}
            resp=vpn_setup.SetConfig(instance, newConf) #sets configuration     
        elif(encryptionType=="psk"):
            newConf={"data":instance.tun_psk_config["data"]|testConfig}
            resp=vpn_setup.SetConfig(instance, newConf) #sets configuration
            
    elif(connectionType=="tap"):
        if(encryptionType=="tls"):
            newConf={"data":instance.tap_tls_config["data"]|testConfig}
            resp=vpn_setup.SetConfig(instance,newConf) #sets configuration
        elif(encryptionType=="tls_pwd"):
            newConf={"data":instance.tap_tls_pwd_config["data"]|testConfig}
            resp=vpn_setup.SetConfig(instance, newConf) #sets configuration         
        elif(encryptionType=="pwd"):
            newConf={"data":instance.tap_pwd_config["data"]|testConfig}
            resp=vpn_setup.SetConfig(instance, newConf) #sets configuration         
        elif(encryptionType=="psk"):
            newConf={"data":instance.tap_psk_config["data"]|testConfig}
            resp=vpn_setup.SetConfig(instance, newConf) #sets configuration
    sleep(2)
    print("{instance} setup is finished.\n\n".format(instance=instance.name))
  

def InitiateSpeedtest(instanceServer,instanceClient, testName, test_count, test_length, test_IP):
    try:    
        speed_test.CheckServer(instanceServer)
        speed_test.CheckConnection(instanceClient,instanceServer)

        #remove output file if it already exists
        if(os.path.isfile(outFile)):
            os.remove(outFile)

        #get speed test results
        results = speed_test.SSHSequence(instanceServer, instanceClient, test_count, test_length, test_IP)
        
        print("Final speed test results:")
        print('|{label1:<10}|{label2:<10}|{label3:<10}|'.format(
                label1="Time", label2="Download", label3="Upload"))
        #if results complete, print to terminal and save to file
        if(len(results[0])==test_length and len(results[1])==test_length and len(results[2])==test_length):
            files.WriteData(outFile, [instanceClient.deviceName])
            files.WriteData(outFile, [testName])
            for i in range(test_length):
                data=[results[0][i], results[1][i], results[2][i]]
                print('|{time:>10}|{down:>10}|{up:>10}|'.format(
                    time=results[0][i], down=results[1][i], up=results[2][i]))
                files.WriteData(outFile, data)
            return True
        else:
            print("Some of the data seems to have gotten lost.")
            raise OSError
    except KeyError as err:
        sys.exit("Could not get data due to key error:\n{0}".format(err))
    except ZeroDivisionError as err:
        print("Zero tests are performed")
        if(os.path.isfile(outFile)):
            os.remove(outFile)
        files.WriteData(outFile, [instanceClient.deviceName])
        files.WriteData(outFile, [testName])
        files.WriteData(outFile, ["test has failed."])
        return False
    except (ConnectionResetError, paramiko.SSHException, TimeoutError, OSError) as err:
        print("Connectivity error. Moving on to other configuration...")
        if(os.path.isfile(outFile)):
            os.remove(outFile)
        files.WriteData(outFile, [testName])
        files.WriteData(outFile, ["test has failed."])
        sleep(10)
        return False


def TestConfig(instanceServer, instanceClient, ftpCreds, args, connectionType, successCounter, failCounter):
    if(connectionType=="tap"):
        test_IP="192.168.2.2"
    elif(connectionType=="tun"):
        test_IP="172.16.10.1"

    print ("\nPerforming tests for different cipher configurations:")
    for authType in args.auth_types:
        if(authType=="tls"):
                successCounter, failCounter = TestTLS(instanceServer, instanceClient, 
                ftpCreds, args,connectionType, authType, test_IP, successCounter, failCounter)
        if(authType=="tls_pwd"):
                successCounter, failCounter = TestTLS(instanceServer, instanceClient, 
                ftpCreds, args,connectionType,authType, test_IP, successCounter, failCounter, True)
        if(authType=="pwd"):
                successCounter, failCounter = TestPWD(instanceServer, instanceClient, 
                ftpCreds, args,connectionType, authType, test_IP,successCounter, failCounter)
        if(authType=="psk"):
                successCounter, failCounter = TestPSK(instanceServer, instanceClient, 
                ftpCreds, args,connectionType, authType, test_IP, successCounter, failCounter)
    
    return successCounter, failCounter

    
    
def TestTLS(instanceServer, instanceClient, ftpCreds, args, connectionType, authType,  test_IP, successCounter, failCounter, PWD=False):
    count=0
    if PWD:
        infoLine="Connection type: {0}, Authentication type: TLS/PWD".format(connectionType)
    else:
        infoLine="Connection type: {0}, Authentication type: TLS".format(connectionType)
    serverConfDict={}
    clientConfDict={}
    for protocol in args.protocols:
        infoLineProtocol=infoLine+", Protocol: "+protocol["server"]["proto"]
        serverConfDictProtocol=serverConfDict | protocol["server"]
        clientConfDictProtocol=clientConfDict | protocol["client"]
        for lzo in args.lzo:
            infoLineLZO=infoLineProtocol+", LZO: "+lzo["comp_lzo"]
            serverConfDictLZO=serverConfDictProtocol | lzo
            clientConfDictLZO=clientConfDictProtocol | lzo
            for encryption in args.encryption_types:
                infoLineCipher=infoLineLZO+", Encryption protocol: "+encryption["cipher"]
                serverConfDictCipher=serverConfDictLZO| encryption
                clientConfDictCipher=clientConfDictLZO | encryption
                for TLSCipher in args.tls_cipher:
                    if(TLSCipher["_tls_cipher"]=="all"):
                        infoLineTLSCipher=infoLineCipher+", TLS cipher: "+TLSCipher["_tls_cipher"]
                    else:
                        infoLineTLSCipher=infoLineCipher+", TLS cipher: "+TLSCipher["tls_cipher"][0]
                    
                    serverConfDictTLSCipher=serverConfDictCipher| TLSCipher
                    clientConfDictTLSCipher=clientConfDictCipher | TLSCipher
                    for auth in args.authentication_algorithms:
                        infoLineAuth=infoLineTLSCipher+", Authentication algorithm: " + auth["auth"]
                        serverConfDictAuth=serverConfDictTLSCipher| auth
                        clientConfDictAuth=clientConfDictTLSCipher | auth
                        for hmac in args.hmac_authentication:
                            infoLineHMAC=infoLineAuth+", Additional HMAC authentication: " + hmac["_tls_auth"]
                            serverConfDictHMAC=serverConfDictAuth | hmac
                            clientConfDictHMAC=clientConfDictAuth | hmac | {"remote": instanceServer.url}

                            if(PWD):
                                if(connectionType=="tun"):
                                    data={"user":instanceClient.tun_tls_pwd_config["data"]["user"], 
                                                  "pass":instanceClient.tun_tls_pwd_config["data"]["pass"]}
                                    clientConfDictHMAC=clientConfDictHMAC|data
                                elif(connectionType=="tap"):
                                    data={"user":instanceClient.tap_tls_pwd_config["data"]["user"], 
                                                  "pass":instanceClient.tap_pwd_config["data"]["pass"]}
                                    clientConfDictHMAC=clientConfDictHMAC|data
                            print("Setting the configuration to:\n{0}\n".format(infoLineHMAC))
                            VPNSetup(instanceServer,connectionType,authType, serverConfDictHMAC, hmac["_tls_auth"])
                            VPNSetup(instanceClient,connectionType,authType, clientConfDictHMAC, hmac["_tls_auth"])
                            sleep(4)

                            if(InitiateSpeedtest(instanceServer,instanceClient,"{0}".format(infoLineHMAC), args.test_count, args.test_length, test_IP)):
                                successCounter+=1
                            else:
                                failCounter+=1
                            print(infoLineHMAC)
                            print()
                            if(os.path.isfile(outFile)):
                                print("Sending {0} data file to FTP server...".format(outFile))
                                #sends data file to FTP server
                                files.SendFileFTP(outFile, ftpCreds, instanceClient.deviceName, "./vpn_tests")
                                print("File transfer was successful.\n\n")
                            else:
                                print("{filename} file does not exist\n\n".format(filename=outFile))
                                pass
                            count+=1
    return successCounter, failCounter
                            

def TestPWD(instanceServer, instanceClient, ftpCreds, args, connectionType, authType, test_IP, successCounter, failCounter):
    count=0
    infoLine="Connection type: {0}, Authentication type: PWD".format(connectionType)
    serverConfDict={}
    clientConfDict={}
    for protocol in args.protocols:
        infoLineProtocol=infoLine+", Protocol: "+protocol["server"]["proto"]
        serverConfDictProtocol=serverConfDict | protocol["server"]
        clientConfDictProtocol=clientConfDict | protocol["client"]
        for lzo in args.lzo:
            infoLineLZO=infoLineProtocol+", LZO: "+lzo["comp_lzo"]
            serverConfDictLZO=serverConfDictProtocol | lzo
            clientConfDictLZO=clientConfDictProtocol | lzo
            for encryption in args.encryption_types:
                infoLineCipher=infoLineLZO+", Encryption protocol: "+encryption["cipher"]
                serverConfDictCipher=serverConfDictLZO| encryption
                clientConfDictCipher=clientConfDictLZO | encryption
                for auth in args.authentication_algorithms:
                    infoLineAuth=infoLineCipher+", Authentication algorithm: " + auth["auth"]
                    serverConfDictAuth=serverConfDictCipher | auth
                    clientConfDictAuth=clientConfDictCipher | auth
                    for hmac in args.hmac_authentication:
                        infoLineHMAC=infoLineAuth+", Additional HMAC authentication: " + hmac["_tls_auth"]
                        serverConfDictHMAC=serverConfDictAuth | hmac
                        clientConfDictHMAC=clientConfDictAuth | hmac | {"remote": instanceServer.url}
                        
                        if(connectionType=="tun"):
                            data={"user":instanceClient.tun_tls_pwd_config["data"]["user"], 
                                            "pass":instanceClient.tun_tls_pwd_config["data"]["pass"]}
                            clientConfDictHMAC=clientConfDictHMAC|data
                        elif(connectionType=="tap"):
                            data={"user":instanceClient.tap_tls_pwd_config["data"]["user"], 
                                            "pass":instanceClient.tap_pwd_config["data"]["pass"]}
                            clientConfDictHMAC=clientConfDictHMAC|data
                        print("Setting the configuration to:\n{0}\n".format(infoLineHMAC))
                        VPNSetup(instanceServer,connectionType,authType,serverConfDictHMAC, hmac["_tls_auth"])
                        VPNSetup(instanceClient,connectionType,authType, clientConfDictHMAC, hmac["_tls_auth"])
                        sleep(4)

                        if(InitiateSpeedtest(instanceServer,instanceClient,"{0}".format(infoLineHMAC), args.test_count, args.test_length, test_IP)):
                            successCounter+=1
                        else:
                            failCounter+=1
                        print(infoLineHMAC)
                        print()
                        if(os.path.isfile(outFile)):
                            print("Sending {0} data file to FTP server...".format(outFile))
                            #sends data file to FTP server
                            files.SendFileFTP(outFile, ftpCreds, instanceClient.deviceName, "./vpn_tests")
                            print("File transfer was successful.\n\n")
                        else:
                            print("{filename} file does not exist\n\n".format(filename=outFile))
                            pass
                        count+=1
    return successCounter, failCounter
                        


def TestPSK(instanceServer, instanceClient, ftpCreds, args,connectionType, authType, test_IP, successCounter, failCounter):
    count=0
    infoLine="Connection type: {0}, Authentication type: PSK".format(connectionType)
    serverConfDict={}
    clientConfDict={}
    for protocol in args.protocols[0:10]:
        print(protocol)
        
        infoLineProtocol=infoLine+", Protocol: "+protocol["server"]["proto"]
        serverConfDictProtocol=serverConfDict | protocol["server"]
        clientConfDictProtocol=clientConfDict | protocol["client"]
        for lzo in args.lzo:
            infoLineLZO=infoLineProtocol+", LZO: "+lzo["comp_lzo"]
            serverConfDictLZO=serverConfDictProtocol | lzo
            clientConfDictLZO=clientConfDictProtocol | lzo
            for encryption in args.encryption_types:
                infoLineCipher=infoLineLZO+", Encryption protocol: "+encryption["cipher"]
                serverConfDictCipher=serverConfDictLZO| encryption
                clientConfDictCipher=clientConfDictLZO | encryption | {"remote": instanceServer.url}
                
                print("Setting the configuration to:\n{0}\n".format(infoLineCipher))
                VPNSetup(instanceServer,connectionType,authType,serverConfDictCipher)
                VPNSetup(instanceClient,connectionType,authType, clientConfDictCipher)
                sleep(4)

                if(InitiateSpeedtest(instanceServer,instanceClient,"{0}".format(infoLineCipher), args.test_count, args.test_length,test_IP)):
                    successCounter+=1
                else:
                    failCounter+=1
                print(infoLineCipher)
                print()
                if(os.path.isfile(outFile)):
                    print("Sending {0} data file to FTP server...".format(outFile))
                    #sends data file to FTP server
                    files.SendFileFTP(outFile, ftpCreds, instanceClient.deviceName, "./vpn_tests")
                    print("File transfer was successful.\n\n")
                else:
                    print("{filename} file does not exist\n\n".format(filename=outFile))
                    pass
                count+=1
    return successCounter, failCounter
                
                
def main():
    defaultValues={
        "test_count":3,
        "test_length":10,
        "connection_types":["tun", "tap"],
        "auth_types":["tls", "tls_pwd", "pwd", "psk"],
        "protocols":["udp", "tcp"],
        "lzo":["none", "yes", "no"],
        "encryption_types":["BF-CBC", "DES-CBC", "DES-EDE-CBC", "DES-EDE3-CBC", 
            "DESX-CBC", "CAST5-CBC", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "none", "RC2-CBC", 
            "RC2-40-CBC", "RC2-64-CBC", "AES-128-CFB", "AES-128-CFB1", "AES-128-CFB8", "AES-128-OFB",
            "AES-128-GCM", "AES-192-CFB", "AES-192-CFB1", "AES-192-CFB8", "AES-192-OFB", "AES-192-GCM", 
            "AES-256-GCM", "AES-256-CFB", "AES-256-CFB1", "AES-256-CFB8", "AES-256-OFB"],
        "authentication_algorithms":["sha1", "none", "md5", "sha256", "sha384", "sha512"],
        "hmac_authentication":["none", "tls-auth", "tls-crypt"],
        "tls_cipher":["all", "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384", 
            "TLS-DHE-RSA-WITH-AES-256-CBC-SHA", "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256", 
            "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA","TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA",
            "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256", "TLS-DHE-RSA-WITH-AES-128-CBC-SHA", 
            "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256", "TLS-DHE-RSA-WITH-SEED-CBC-SHA", 
            "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA", "TLS-DHE-RSA-WITH-DES-CBC-SHA"]
    }
    parser= argparse.ArgumentParser()
    parser.add_argument('-s','--server_ip', dest='server_ip', type=str, help='server IP address')
    parser.add_argument('-c','--client_ip', dest='client_ip', type=str, help='client IP address')
    parser.add_argument('-n','--test_count', dest='test_count', type=int, default=defaultValues["test_count"], 
                        help='number of tests to run')
    parser.add_argument('-tl','--test_length', dest='test_length', type=int, default=defaultValues["test_length"], 
                        help='length of the tests that are going to be run (s)')
    parser.add_argument('-ct','--connection_types', dest='connection_types', nargs='+', type=str, 
                        default=defaultValues["connection_types"], help='list of connection types to test (tun, tap)')
    parser.add_argument('-t','--auth_types', dest='auth_types', nargs='+', type=str, 
                        default=defaultValues["auth_types"], help='list of authentication types to test')
    parser.add_argument('-p','--protocols', dest='protocols', nargs='+', 
                        type=str, default=defaultValues["protocols"], help='list of data transfer protocols to test')
    parser.add_argument('-l','--lzo', dest='lzo', nargs='+', type=str, default=defaultValues["lzo"], 
                        help='Enabling of LZO (yes, no, none)')
    parser.add_argument('-e','--encryption_types', dest='encryption_types', 
                        nargs='+', type=str, default=defaultValues["encryption_types"], help='list of encryption algorithms to test')
    parser.add_argument('-a','--authentication_algorithms', dest='authentication_algorithms', 
                        nargs='+', type=str, default=defaultValues["authentication_algorithms"], 
                        help='list of authentication algorithms to test')
    parser.add_argument('-ha','--hmac_authentication', dest='hmac_authentication', 
                        nargs='+', type=str, default=defaultValues["hmac_authentication"], 
                        help='list of additional HMAC authentication options to test (none, tls_auth, tls_crypt)')
    parser.add_argument('-tc','--tls_cipher', dest='tls_cipher', 
                        nargs='+', type=str, default=defaultValues["tls_cipher"], 
                        help='list of TLS cipher algorithms to test')


    args = parser.parse_args()
    allConfigs=files.ReadTestConfigs(configFile)
    newArgs=argument_verification.VerifyArgs(args, allConfigs)
   
    try:
        #creates VPN instance objects for both devices
        serverInstance=files.GetInstance(configFile,"server", newArgs.server_ip)
        clientInstance=files.GetInstance(configFile,"client", newArgs.client_ip)    
        #login  
        
        serverInstance.token=vpn_setup.Login(serverInstance)
        clientInstance.token=vpn_setup.Login(clientInstance)

        #displays basic info from both devices
        serverDeviceName=vpn_setup.DeviceInfo(serverInstance)
        serverInstance.deviceName=serverDeviceName
        clientDeviceName=vpn_setup.DeviceInfo(clientInstance)
        clientInstance.deviceName=clientDeviceName

    
        print("Getting FTP server login information...\n")
        credentials=files.ReadCredentials(configFile)
        successCounter=0
        failCounter=0
        for connectionType in newArgs.connection_types:
            print("Changing server device LAN address...")
            vpn_setup.ChangeLAN(serverInstance, connectionType)
            successCounter, failCounter = TestConfig(serverInstance,clientInstance, 
                credentials, newArgs, connectionType, successCounter, failCounter)
        print("Out of {0} performed tests\n{1} was/were successful,\n{2} was/were not successful"
        .format(successCounter+failCounter, successCounter, failCounter))
        #creates and configures VPN instances on both devices
        print("Work is done. Quitting...")
        
    except KeyboardInterrupt as e:
        sys.exit("\nProgram was shut off by keyboard interrupt")
    

if __name__ == "__main__":
    main()
