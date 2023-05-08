import os
import csv
import sys

class CSVHandler:
    def __init__(self, *args, **kwargs):
        self.file=kwargs['outFile']

    def RemoveCSV(self):
        if(os.path.isfile(self.file)):
            os.remove(self.file)
            return True


    def GetLabels(self, test_length):
        labels=[]
        for i in range(test_length):
            labels.append("{0}.00-{1}.00".format(i, i+1))
        labels+=[""]
        return labels
    
    def GetAverageLabels(self, test_count):
        labels=[]
        for i in range(test_count):
            labels.append("Test {0}".format(i+1))
        labels+=["Overall average:",""]
        return labels

    def PrepareCSV(self, arguments, instanceServer, instanceClient):
        self.RemoveCSV()
        self.WriteData(["Device name:",instanceServer.deviceInfo["name"], "Instance Type:", 
            instanceServer.name,"Device serial no.:", instanceServer.deviceInfo["serial"], 
            "Firmware used:", instanceServer.deviceInfo["firmware"]])
        self.WriteData(["Device name:",instanceClient.deviceInfo["name"], "Instance Type:", 
            instanceClient.name, "Device serial no.:", instanceClient.deviceInfo["serial"], 
            "Firmware used:", instanceClient.deviceInfo["firmware"]])
        self.WriteData(["Test length:", arguments.test_length, "Test count:", 
            arguments.test_count])
        
        header=["Connection type", "Authentication type", "Protocol", 
            "LZO", "Encryption protocol", "TLS cipher", "Authentication algorithm", 
            "Additional HMAC authentication",""]
        label=self.GetLabels(arguments.test_length)
        averageLabel=self.GetAverageLabels(arguments.test_count)
        fullHeader=header+label+averageLabel+label+averageLabel
        self.WriteData(fullHeader)

    def WriteData(self, data):
        try:
            with open(self.file, 'a') as f:
                writer = csv.writer(f)
                writer.writerow(data)
                return True
        except IOError as err:
            sys.exit("Writing file to {0} file was unsuccessful:\n{1}".format(self.file, err))

   