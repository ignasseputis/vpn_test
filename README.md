# vpn_test
Program for automatically applying OpenVPN configurations and measuring their data transfer speeds.

# Requirements
For the server device:
1. The device must have internet access (preferably mobile);
2. Configure the device to have a static public IP;
3. In Administration / Access control, enable Remote SSH Access (and optionally Remote HTTP access, if you want to access the device through the UI).
4. While connected to device via terminal, use this command to install iperf3:
```
opkg install iperf3
```

For the client device:
1. The device must hace internet access;
2. Set LAN IP to 192.168.2.1;
3. Set static LAN lease for the device that you are using to connect to the router;
4. Disable LAN DHCP server;
5. Disable DHCP on the device's that is running the program network interface which is used to connect to the router and set the IP to something in the client device's LAN subnet range (for example, 192.168.2.233).
6. While connected to device via terminal, use this command to install iperf3:
```
opkg install iperf3
```
# Running the program
1. Download and extract the files to a directory
2. Navigate to the extracted directory
3. Run the program with parameters:
```
$ /bin/python3 main.py -h
usage: main.py [-h] [-s SERVER_IP] [-c CLIENT_IP] [-n TEST_COUNT] [-tl TEST_LENGTH] [-ct CONNECTION_TYPES [CONNECTION_TYPES ...]]
               [-t AUTH_TYPES [AUTH_TYPES ...]] [-p PROTOCOLS [PROTOCOLS ...]] [-l LZO [LZO ...]] [-e ENCRYPTION_TYPES [ENCRYPTION_TYPES ...]]
               [-a AUTHENTICATION_ALGORITHMS [AUTHENTICATION_ALGORITHMS ...]] [-ha HMAC_AUTHENTICATION [HMAC_AUTHENTICATION ...]]
               [-tc TLS_CIPHER [TLS_CIPHER ...]]

options:
  -h, --help            show this help message and exit
  -s SERVER_IP, --server_ip SERVER_IP
                        server IP address
  -c CLIENT_IP, --client_ip CLIENT_IP
                        client IP address
  -n TEST_COUNT, --test_count TEST_COUNT
                        number of tests to run
  -tl TEST_LENGTH, --test_length TEST_LENGTH
                        length of the tests that are going to be run (s)
  -ct CONNECTION_TYPES [CONNECTION_TYPES ...], --connection_types CONNECTION_TYPES [CONNECTION_TYPES ...]
                        list of connection types to test (tun, tap)
  -t AUTH_TYPES [AUTH_TYPES ...], --auth_types AUTH_TYPES [AUTH_TYPES ...]
                        list of authentication types to test
  -p PROTOCOLS [PROTOCOLS ...], --protocols PROTOCOLS [PROTOCOLS ...]
                        list of data transfer protocols to test
  -l LZO [LZO ...], --lzo LZO [LZO ...]
                        Enabling of LZO (yes, no, none)
  -e ENCRYPTION_TYPES [ENCRYPTION_TYPES ...], --encryption_types ENCRYPTION_TYPES [ENCRYPTION_TYPES ...]
                        list of encryption algorithms to test
  -a AUTHENTICATION_ALGORITHMS [AUTHENTICATION_ALGORITHMS ...], --authentication_algorithms AUTHENTICATION_ALGORITHMS [AUTHENTICATION_ALGORITHMS ...]
                        list of authentication algorithms to test
  -ha HMAC_AUTHENTICATION [HMAC_AUTHENTICATION ...], --hmac_authentication HMAC_AUTHENTICATION [HMAC_AUTHENTICATION ...]
                        list of additional HMAC authentication options to test (none, tls_auth, tls_crypt)
  -tc TLS_CIPHER [TLS_CIPHER ...], --tls_cipher TLS_CIPHER [TLS_CIPHER ...]
                        list of TLS cipher algorithms to test
```
After running the program with desired arguments, the program runs these steps:
1. The received arguments are verified with the default values;
2. The test handler compiles a configuration from from the selected arguments;
3. Neccessary files are uploaded to both of the devices;
4. The compiled configuration is applied to both of the devices;
5. The program connects to the server device via SSH and starts an iperf3 listener;
6. The program connects to the client device via SSH and starts an iperf3 speed test;
7. The average values are calculated and the device outputs the test results into a CSV file;
8. Steps 2-7 are repeated until all possible configuration combinations that are selected by the arguments are tested;
9. The full test file is uploaded to the FTP server.

# Configuration file structure
The JSON configuration file has these main 4 parts:
1. server - contains the server device's API login information, OpenVPN configuration file locations and 8 base configurations that are made up of combinations of connection and authentication types;
2. client - contains the same information as the server part does, only for the client device;
3. tests - contains configuration data for all other variables used for the VPN configuration, except for connection and authentication types;
4. ftp - contains the credentials for logging in to the FTP server;
5. default_values - contains all of the default values that are used to verify the arguments.


# Example of testing connection and authentication types
1. Fulfill all the conditions mentioned in the requirements section;
2. Connect your computer to the client device's LAN port;
3. Run the program with these arguments:
```
/bin/python3 main.py -n 3 -tl 3 -p udp -l none -e BF-CBC -a sha1 -ha none -tc all
```
In this scenario, we have specified the test count, test length, protocol, LZO compression, encryption algorithm, 
authentication algorithm, additional HMAC authentication and TLS cipher. This leaves the connection type (tun, tap) 
and authentication type (TLS, TLS + PWD, PWD, PSK) not specified, which means that the combinations of these 2 variables will be tested.
4. Wait for the program to finish its work.
5. Check for the file in the FTP server. It should look something like this (since the opened file takes up a lot of horizontal space, it is split
into 2 screenshots):
![Screenshot from 2023-05-08 11-46-35](https://user-images.githubusercontent.com/78542745/236779359-892d548d-35ef-477c-9c1c-0a92459bf5d8.png)
![Screenshot from 2023-05-08 11-47-38](https://user-images.githubusercontent.com/78542745/236780464-bb991280-4d65-4246-82a4-5d0301f6dd38.png)

- The first 2 lines show information about the devices that are being tested. This information includes the device name, type of OpenVPN instance created
on the device, the device's serial number and the firmware used for the tests that are being completed.
- The third line displays the number of tests performed for each configuration and the length of these performed tests (in seconds).
- The fourth line displays the labels for the following lines.
- All of the following lines describe a single test that is performed. The lines are structured in this way:

  > The first 8 collumns describe the variables that make up the configuration.
  > 
  > The collumns following "Download" display the results of all of the performed download tests averaged by the seconds of the performed tests.
  > 
  > The collumns following "Download averages" display the results of all of the performed download tests averaged for each of the performed tests.
  > 
  > The collumn under "Overall average" displays the average value of all the values measured during the duration of all performed download tests.
  > 
  > The collumns following "Upload" display the results of all of the performed upload tests averaged by the seconds of the performed tests.
  > 
  > The collumns following "Upload averages" display the results of all of the performed upload tests averaged for each of the performed tests.
  > 
  > The collumn under the second "Overall average" displays the average value of all the values measured during the duration of all performed upload tests. 
  >
