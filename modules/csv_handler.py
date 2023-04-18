import os
import csv
import sys

class CSVHandler:
    def __init__(self, *args, **kwargs):
        self.file=kwargs['outFile']

    def RemoveCSV(self):
        if(os.path.isfile(self.file)):
                    os.remove(self.file)     

    def WriteData(self, data):
        try:
            with open(self.file, 'a') as f:
                writer = csv.writer(f)
                writer.writerow(data)
        except IOError as err:
            sys.exit("Writing file to {0} file was unsuccessful:\n{1}".format(self.file, err))

   