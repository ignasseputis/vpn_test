import sys
import json

class ConfigReader:
    def __init__(self, *args, **kwargs):
        self.file=kwargs['configFile']

    def ReadInstanceData(self, type):
        try:
            mainConfig = json.loads(open(self.file).read())
            instanceData=mainConfig[type]
            return instanceData
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))
        except IOError as err:
            sys.exit("Reading the configuration file was not successful:\n{0}".format(err))
        

    #opens config file and gets FTP server creds
    def ReadCredentials(self):
        try:
            configFile = json.loads(open(self.file).read())
            credentialsFTP=configFile["ftp"]
            return credentialsFTP
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))
        except IOError as err:
            sys.exit("Reading the configuration file was not successful:\n{0}".format(err))

    def ReadArgumentDefaults(self):
        try:
            configFile = json.loads(open(self.file).read())
            defaults=configFile["default_values"]
            return defaults
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))
        except IOError as err:
            sys.exit("Reading the configuration file was not successful:\n{0}".format(err))
        
    def ReadTestConfigs(self):
        try:
            mainConfig = json.loads(open(self.file).read())
            credentialsFTP=mainConfig["tests"]
            return credentialsFTP
        except KeyError as err:
            sys.exit("Could not get data due to key error:\n{0}".format(err))
        except IOError as err:
            sys.exit("Reading the configuration file was not successful:\n{0}".format(err))