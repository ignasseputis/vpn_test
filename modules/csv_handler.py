import os
import csv
import sys

class CSVHandler:
    def __init__(self, *args, **kwargs):
        self.file=kwargs['outFile']

    def RemoveCSV(self):
        if(os.path.isfile(self.file)):
                    os.remove(self.file)     


    def GetLabels(self, test_length):
        labels=[]
        for i in range(test_length):
            labels.append("{0}.00-{1}.00".format(i, i+1))
        return labels

    def PrepareCSV(self, arguments, instanceServer, instanceClient):
        self.RemoveCSV()
        self.WriteData([instanceServer.deviceName, instanceServer.name])
        self.WriteData([instanceClient.deviceName, instanceClient.name])
        self.WriteData(["Test length:", arguments.test_length, "Test count:",arguments.test_count])
        
        header=["Connection type", "Authentication type", "Protocol", 
            "LZO", "Encryption protocol", "TLS cipher", "Authentication algorithm", 
            "Additional HMAC authentication",""]
        fullHeader=header+self.GetLabels(arguments.test_length)+[""]+self.GetLabels(arguments.test_length)
        self.WriteData(fullHeader)

    def WriteData(self, data):
        try:
            with open(self.file, 'a') as f:
                writer = csv.writer(f)
                writer.writerow(data)
        except IOError as err:
            sys.exit("Writing file to {0} file was unsuccessful:\n{1}".format(self.file, err))

   