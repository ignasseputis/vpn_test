import sys

from modules.argument_parsing import ArgumentParser
from modules.instance_setup import VPNInstance
from modules.test_handler import TestHandler
from modules.ftp_handler import FTPInstance
from modules.config_reader import ConfigReader

configFile="./files/config.json" #main config file n ame
outFile = "./files/output.csv" #test data output file name

serverInstance=None
clientInstance=None

configReader=None
argumentParser=None 
ftpClient=None
testHandler=None


def InitializeModules():
    global argumentParser
    allConfigs=InitializeConfigReader()
    newArgs=InitializeArgumentParser(allConfigs)
    InitializeFTP()
    return newArgs

def InitializeConfigReader():
    global configReader
    configReader = ConfigReader (configFile=configFile)
    allConfigs=configReader.ReadTestConfigs()
    return allConfigs

def InitializeArgumentParser(allConfigs):
    global argumentParser
    argumentParser = ArgumentParser(config_reader=configReader)
    argumentParser.ParseDefaults(configFile)
    argumentParser.ParseArguments()
    newArgs=argumentParser.VerifyArgs(allConfigs)
    return newArgs

def InitializeFTP():
    global ftpClient
    print("Getting FTP server login information...\n")
    credentials=configReader.ReadCredentials()
    ftpClient=FTPInstance()
    ftpClient.Connect(credentials)
    ftpClient.ChangeDir("vpn_tests")


def InitializeInstance(newArgs, instanceType):
    match instanceType:
        case "server":
            global serverInstance
            serverInstance=VPNInstance()
            serverInstance.GetInstance(configReader, "server", newArgs.server_ip)
            serverInstance.Login()
            serverInstance.SetUpSSH()
            serverInstance.DeviceInfo()
        case "client":
            global clientInstance
            clientInstance=VPNInstance()
            clientInstance.GetInstance(configReader, "client", newArgs.client_ip)
            clientInstance.Login()
            clientInstance.SetUpSSH()
            clientInstance.DeviceInfo()
                
def InitializeTests(newArgs):
    global testHandler
    testHandler=TestHandler(server=serverInstance, client=clientInstance,
                     ftp=ftpClient, arguments=newArgs, outFile=outFile)
    testHandler.TestVPN()

def CloseConnections():
    serverInstance.sshClient.Close()
    clientInstance.sshClient.Close()
    ftpClient.Disconnect()

def main():
    try:
        newArgs=InitializeModules()
        InitializeInstance(newArgs, "server")
        InitializeInstance(newArgs, "client")
        InitializeTests(newArgs)
        CloseConnections()

        print("Work is done. Program is quitting...")
    except KeyboardInterrupt as e:
        sys.exit("\nProgram was shut off by keyboard interrupt")

if __name__ == "__main__":
    main()