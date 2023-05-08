import sys

from datetime import datetime

class CertVerifier:
    def __init__(self, *args, **kwargs):
        self.serverInstance=kwargs["server"]
        self.clientInstance=kwargs["client"]

    def VerifyServerCert(self):
        validity=self.ReadValidity(self.clientInstance.files["cert"])
        parsedValidity=self.ParseValidity(validity)
        return self.CompareDatetimes(parsedValidity, self.clientInstance.name)

    def VerifyClientCert(self):
        validity=self.ReadValidity(self.serverInstance.files["cert"])
        parsedValidity=self.ParseValidity(validity)
        return self.CompareDatetimes(parsedValidity, self.serverInstance.name)


    def ReadValidity(self, file):
        file = open(file, "r")
        searchItem="Not After : "
        s=file.read()
        startIndex=s.find(searchItem)+len(searchItem)
        endIndex=s.find("\n",startIndex)
        file.close()
        return s[startIndex:endIndex]
    
    def ParseValidity(self,line):
        date = datetime.strptime(line, "%b %d %H:%M:%S %Y %Z")
        return date
    
    def CompareDatetimes(self, time, name):
        currentTime=datetime.now()
        if(currentTime>=time):
            sys.exit("{0} instance certificate is not valid anymore. Expired at {1}".format(name, time))
        else:
            print("{0} instance certificate valid until {1}.\n".format(name, time))
            return True
