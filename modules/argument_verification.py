import argparse
import ipaddress
import sys

def VerifyArgs(args, configs):
    newArgs=argparse.Namespace()
    newArgs.server_ip, newArgs.client_ip = VerifyIP(args)
    newArgs.test_count=VerifyCount(args)
    newArgs.test_length=VerifyTestLength(args)
    newArgs.connection_types=VerifyConnections(args)
    newArgs.auth_types=VerifyAuthTypes(args)
    newArgs.protocols=VerifyProtocols(args, configs)
    newArgs.lzo=VerifyLZO(args, configs)
    newArgs.encryption_types=VerifyEncryptionTypes(args, configs)
    newArgs.authentication_algorithms=VerifyAuthenticationAlgorithms(args, configs)
    newArgs.hmac_authentication=VerifyHMAC(args,configs)
    newArgs.tls_cipher=VerifyTLSCipher(args,configs)
    return newArgs

def VerifyIP(args):
    try:
        if(args.server_ip):
            ipaddress.ip_address(args.server_ip)
            server_ip=args.server_ip
        else:
            server_ip=""
        if(args.client_ip):
            ipaddress.ip_address(args.client_ip)
            client_ip=args.client_ip
        else:
            client_ip=""
        return server_ip, client_ip
    except ValueError as err:
        sys.exit("At least one of the arguments is not a valid IP address. Quitting...")
    
def VerifyCount(args):
    if(args.test_count>0):
        return args.test_count
    else:
        sys.exit("The entered number of tests cannot be performed. Quitting...")

def VerifyTestLength(args):
    if(args.test_length>0):
        return args.test_length
    else:
        sys.exit("Tests of the entered length cannot be performed. Quitting...")

def VerifyConnections(args):
    newConnections=[]
    allOptions = ["tun","tap"]
    connections=args.connection_types
    for conn in connections:
        if(conn.lower()=="tun" or conn.lower()=="tap"):
            newConnections.append(conn)
    if(len(newConnections)==0):
        print("No connection types were selected correctly. Testing will commence with all available options")
        newConnections = allOptions
    return newConnections

def VerifyAuthTypes(args):
    newAuthTypes=[]
    allOptions=["tls", "tls_pwd", "pwd", "psk"]
    authTypes=args.auth_types
    for authType in authTypes:
       if(authType.lower() in (option.lower() for option in allOptions)):
           newAuthTypes.append(authType)
    if(len(newAuthTypes)==0):
        print("No authentication types were selected correctly. Testing will commence with all available options")
        newAuthTypes = allOptions
    return newAuthTypes

def VerifyProtocols(args, allConfigs):
    newProtocols=[]
    protocols=args.protocols
    protocolConfigs=[]
    for i in range(2):
        protocolName="protocol_test{0}".format(i+1)
        protocolConfigs.append(allConfigs[protocolName])
    for protocol in protocols:
        for protocolConfig in protocolConfigs:
            if(protocol.lower() in (protocolConfig["server"]["proto"]).lower() 
               or protocol.lower() in (protocolConfig["client"]["proto"]).lower()):
                newProtocols.append(protocolConfig)
    if(len(newProtocols)==0):
        print("No communication protocols were selected correctly. Testing will commence with all available options")
        newProtocols=protocolConfigs
    return newProtocols

def VerifyLZO(args, allConfigs):
    newLZO=[]
    LZOConfigs=[]
    for i in range(3):
        lzoName="lzo_test{0}".format(i+1)
        LZOConfigs.append(allConfigs[lzoName])
    LZO=args.lzo
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

def VerifyEncryptionTypes(args, allConfigs):
    newEncryption=[]
    cipherConfigs=[]
    for i in range(28):
        cipherName="cipher_test{0}".format(i+1)
        cipherConfigs.append(allConfigs[cipherName])
    encryption=args.encryption_types
    for arg in encryption:
        for cipherConfig in cipherConfigs:
            if(arg.lower() == (cipherConfig["cipher"]).lower()):
                newEncryption.append(cipherConfig)
    if(len(newEncryption)==0):
        print("No encryption types were selected correctly. Testing will commence with all available options")
        newEncryption=cipherConfigs
    return newEncryption

def VerifyAuthenticationAlgorithms(args, allConfigs):
    newAuthentication=[]
    authentication=args.authentication_algorithms
    authConfigs=[]
    for i in range(6):
        authName="auth_test{0}".format(i+1)
        authConfigs.append(allConfigs[authName])
    for arg in authentication:
        for authConfig in authConfigs:
            if(arg.lower() == (authConfig["auth"]).lower()):
                newAuthentication.append(authConfig)
    if(len(newAuthentication)==0):
        print("No authentication algorithms were selected correctly. Testing will commence with all available options")
        newAuthentication=authConfigs
    return newAuthentication

def VerifyHMAC(args, allConfigs):
    newHMAC=[]
    HMAC=args.hmac_authentication
    HMACConfigs=[]
    for i in range(3):
        HMACName="hmac_test{0}".format(i+1)
        HMACConfigs.append(allConfigs[HMACName])
    for arg in HMAC:
        for HMACConfig in HMACConfigs:
            if(arg.lower() == (HMACConfig["_tls_auth"]).lower()):
                newHMAC.append(HMACConfig)
    if(len(newHMAC)==0):
        print("No additional HMAC authentication options were selected correctly. Testing will commence with all available options")
        newHMAC=HMACConfigs
    return newHMAC

def VerifyTLSCipher(args, allConfigs):
    newTLSCipher=[]
    TLSCipher=args.tls_cipher
    TLSConfigs=[]
    for i in range(11):
        TLSName="tls_cipher_test{0}".format(i+1)
        TLSConfigs.append(allConfigs[TLSName])
    for arg in TLSCipher:
        for TLSConfig in TLSConfigs:
            if(arg.lower() == (TLSConfig["_tls_cipher"]).lower()):
                newTLSCipher.append(TLSConfig)
            elif(TLSConfig["_tls_cipher"].lower()=="dhe_rsa"):
                if(arg.lower() == (TLSConfig["tls_cipher"][0]).lower()):
                    newTLSCipher.append(TLSConfig)
    if(len(newTLSCipher)==0):
        print("No authentication algorithms were selected correctly. Testing will commence with all available options")
        newTLSCipher=TLSConfigs
    return newTLSCipher


def main():
    pass
    
if __name__ == "__main__":
    main()