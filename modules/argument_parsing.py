import argparse
import ipaddress
import sys

class ArgumentParser:
    def __init__(self, *args, **kwargs):
        self.args = None
        self.defaults = None
        self.configReader=kwargs['config_reader']
        self.newArgs=None

    def ParseArguments(self):
        parser= argparse.ArgumentParser()
        parser.add_argument('-s','--server_ip', dest='server_ip', type=str, help='server IP address')
        parser.add_argument('-c','--client_ip', dest='client_ip', type=str, help='client IP address')
        parser.add_argument('-n','--test_count', dest='test_count', type=int, default=self.defaults["test_count"], 
                            help='number of tests to run')
        parser.add_argument('-tl','--test_length', dest='test_length', type=int, default=self.defaults["test_length"], 
                            help='length of the tests that are going to be run (s)')
        parser.add_argument('-ct','--connection_types', dest='connection_types', nargs='+', type=str, 
                            default=self.defaults["connection_types"], help='list of connection types to test (tun, tap)')
        parser.add_argument('-t','--auth_types', dest='auth_types', nargs='+', type=str, 
                            default=self.defaults["auth_types"], help='list of authentication types to test')
        parser.add_argument('-p','--protocols', dest='protocols', nargs='+', 
                            type=str, default=self.defaults["protocols"], help='list of data transfer protocols to test')
        parser.add_argument('-l','--lzo', dest='lzo', nargs='+', type=str, default=self.defaults["lzo"], 
                            help='Enabling of LZO (yes, no, none)')
        parser.add_argument('-e','--encryption_types', dest='encryption_types', 
                            nargs='+', type=str, default=self.defaults["encryption_types"], help='list of encryption algorithms to test')
        parser.add_argument('-a','--authentication_algorithms', dest='authentication_algorithms', 
                            nargs='+', type=str, default=self.defaults["authentication_algorithms"], 
                            help='list of authentication algorithms to test')
        parser.add_argument('-ha','--hmac_authentication', dest='hmac_authentication', 
                            nargs='+', type=str, default=self.defaults["hmac_authentication"], 
                            help='list of additional HMAC authentication options to test (none, tls_auth, tls_crypt)')
        parser.add_argument('-tc','--tls_cipher', dest='tls_cipher', 
                            nargs='+', type=str, default=self.defaults["tls_cipher"], 
                            help='list of TLS cipher algorithms to test')
        self.args = parser.parse_args()
       

    def ParseDefaults(self, fileName):
        self.defaults=self.configReader.ReadArgumentDefaults()

    def VerifyArgs(self, configs):
        newArgs=argparse.Namespace()
        newArgs.server_ip, newArgs.client_ip = self.VerifyIP()
        newArgs.test_count=self.VerifyCount()
        newArgs.test_length=self.VerifyTestLength()
        newArgs.connection_types=self.VerifyConnections()
        newArgs.auth_types=self.VerifyAuthTypes()
        newArgs.protocols=self.VerifyProtocols(configs)
        newArgs.lzo=self.VerifyLZO(configs)
        newArgs.encryption_types=self.VerifyEncryptionTypes(configs)
        newArgs.psk_encryption_types=self.VerifyPSKEncryptionTypes(configs)
        newArgs.authentication_algorithms=self.VerifyAuthenticationAlgorithms(configs)
        newArgs.hmac_authentication=self.VerifyHMAC(configs)
        newArgs.tls_cipher=self.VerifyTLSCipher(configs)
        self.newArgs=newArgs
        return newArgs

    def VerifyIP(self):
        try:
            if(self.args.server_ip):
                ipaddress.ip_address(self.args.server_ip)
                server_ip=self.args.server_ip
            else:
                server_ip=""
            if(self.args.client_ip):
                ipaddress.ip_address(self.args.client_ip)
                client_ip=self.args.client_ip
            else:
                client_ip=""
            return server_ip, client_ip
        except ValueError as err:
            sys.exit("At least one of the arguments is not a valid IP address. Quitting...")
        
    def VerifyCount(self):
        if(self.args.test_count>0):
            return self.args.test_count
        else:
            sys.exit("The entered number of tests cannot be performed. Quitting...")

    def VerifyTestLength(self):
        if(self.args.test_length>0):
            return self.args.test_length
        else:
            sys.exit("Tests of the entered length cannot be performed. Quitting...")

    def VerifyConnections(self):
        newConnections=[]
        allOptions = ["tun","tap"]
        connections=self.args.connection_types
        for conn in connections:
            if(conn.lower()=="tun" or conn.lower()=="tap"):
                newConnections.append(conn)
        if(len(newConnections)==0):
            newConnections = allOptions
        return newConnections

    def VerifyAuthTypes(self):
        newAuthTypes=[]
        allOptions=["tls", "tls_pwd", "pwd", "psk"]
        authTypes=self.args.auth_types
        for authType in authTypes:
            if(authType.lower() in (option.lower() for option in allOptions)):
                newAuthTypes.append(authType)
        if(len(newAuthTypes)==0):
            newAuthTypes = allOptions
        return newAuthTypes

    def VerifyProtocols(self, configs):
        newProtocols=[]
        protocols=self.args.protocols
        protocolConfigs=[]
        for i in range(2):
            protocolName="protocol_test{0}".format(i+1)
            protocolConfigs.append(configs[protocolName])
        for protocol in protocols:
            for protocolConfig in protocolConfigs:
                if(protocol.lower() in (protocolConfig["server"]["proto"]).lower() 
                or protocol.lower() in (protocolConfig["client"]["proto"]).lower()):
                    newProtocols.append(protocolConfig)
        if(len(newProtocols)==0):
            newProtocols=protocolConfigs
        return newProtocols

    def VerifyLZO(self, configs):
        newLZO=[]
        LZOConfigs=[]
        for i in range(3):
            lzoName="lzo_test{0}".format(i+1)
            LZOConfigs.append(configs[lzoName])
        LZO=self.args.lzo
        for arg in LZO:
            if(arg.lower()=="none"):
                newLZO.append(LZOConfigs[0])
            elif(arg.lower()=="yes"):
                newLZO.append(LZOConfigs[1])
            elif(arg.lower()=="no"):
                newLZO.append(LZOConfigs[2])
        if(len(newLZO)==0):
            newLZO=LZOConfigs
        return newLZO

    def VerifyEncryptionTypes(self, configs):
        newEncryption=[]
        cipherConfigs=[]
        for i in range(28):
            cipherName="cipher_test{0}".format(i+1)
            cipherConfigs.append(configs[cipherName])
        encryption=self.args.encryption_types
        for arg in encryption:
            for cipherConfig in cipherConfigs:
                if(arg.lower() == (cipherConfig["cipher"]).lower()):
                    newEncryption.append(cipherConfig)
        if(len(newEncryption)==0):
            newEncryption=cipherConfigs
        return newEncryption
    
    def VerifyPSKEncryptionTypes(self, configs):
        newEncryption=[]
        cipherConfigs=[]
        for i in range(10):
            cipherName="cipher_test{0}".format(i+1)
            cipherConfigs.append(configs[cipherName])
        encryption=self.args.encryption_types
        for arg in encryption:
            for cipherConfig in cipherConfigs:
                if(arg.lower() == (cipherConfig["cipher"]).lower()):
                    newEncryption.append(cipherConfig)
        if(len(newEncryption)==0):
            newEncryption=cipherConfigs
        return newEncryption

    def VerifyAuthenticationAlgorithms(self, configs):
        newAuthentication=[]
        authentication=self.args.authentication_algorithms
        authConfigs=[]
        for i in range(6):
            authName="auth_test{0}".format(i+1)
            authConfigs.append(configs[authName])
        for arg in authentication:
            for authConfig in authConfigs:
                if(arg.lower() == (authConfig["auth"]).lower()):
                    newAuthentication.append(authConfig)
        if(len(newAuthentication)==0):
            newAuthentication=authConfigs
        return newAuthentication

    def VerifyHMAC(self, configs):
        newHMAC=[]
        HMAC=self.args.hmac_authentication
        HMACConfigs=[]
        for i in range(3):
            HMACName="hmac_test{0}".format(i+1)
            HMACConfigs.append(configs[HMACName])
        for arg in HMAC:
            for HMACConfig in HMACConfigs:
                if(arg.lower() == (HMACConfig["_tls_auth"]).lower()):
                    newHMAC.append(HMACConfig)
        if(len(newHMAC)==0):
            newHMAC=HMACConfigs
        return newHMAC

    def VerifyTLSCipher(self, configs):
        newTLSCipher=[]
        TLSCipher=self.args.tls_cipher
        TLSConfigs=[]
        for i in range(11):
            TLSName="tls_cipher_test{0}".format(i+1)
            TLSConfigs.append(configs[TLSName])
        for arg in TLSCipher:
            for TLSConfig in TLSConfigs:
                if(arg.lower() == (TLSConfig["_tls_cipher"]).lower()):
                    newTLSCipher.append(TLSConfig)
                elif(TLSConfig["_tls_cipher"].lower()=="dhe_rsa"):
                    if(arg.lower() == (TLSConfig["tls_cipher"][0]).lower()):
                        newTLSCipher.append(TLSConfig)
        if(len(newTLSCipher)==0):
            newTLSCipher=TLSConfigs
        return newTLSCipher

