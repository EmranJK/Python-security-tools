#!/usr/bin/python3


'''
REFERENCES ARE AT THE BOTTOM OF THIS SCRIPT

Below I am importing all the important libraries I have to use for this assignment:
1- os library is for running system commands when necessary like the clear command.
2- sys library is for being able to use args to pass arguments to the script that can be used when the script is executed.
3- scapy library is for all the network interractions which include sniffing traffic and sending and receiving packets.
'''

import os
import sys
from scapy.all import *

def main():
    '''
    - In this function I defined the variable args which will be used for getting the arguments passed.
    - An if statement checks if 4 arguments were passed and if the 3rd one is -i or --iface, if no then the help function will be called.
    - If yes then the 2nd argument is checked, if it was -p or --passive then passive_scan function will be called, if it was -a or --active then active_recon
    function will be called, if the argument was non of what was mentioned earlier then the hel function will be called.
    '''
    args = sys.argv # [1]
    
    if len(args) == 4 and (args[2] == '-i' or args[2] == '--iface'):

        if args[1] == '-p' or args[1] == '--passive':
            passive_scan(args[3])
        elif args[1] == '-a' or args[1] == '--active':
            active_recon(args[3])
        else:
            help()

    else:
        help()

def help():
    '''
    - This function shows the user how to use the script.
    - It only consists of print statement that shows how to execute the script and how to pass the arguments.
    '''
    
    print('Run the tool as follows: sudo ./net_recone.py <argument> -i or --iface <interface>')
    print('-a or --active: Active recon')
    print('-p or --passive: Passive scan')
    print('-i or --iface: Interface')
    print('Example: sudo ./net_recon.py -a -i eth0')


'''
The two lists below are used in the passive_scan function, more will be explained below
'''

pairings = []
all_traffic = []


def passive_scan(iface):
    '''
    - This function carries out a passive scan through sniffing traffic and takes one parameter for the interface.
    - The two commented lines below where used for testing this function and the main function before adding the network interraction code.
    - After the two commented lines there is a nested function called track_pack
    '''
    
    #print('passive')
    #print('passive ' + str(iface))
    def track_pack(pkt):
        '''
        - This function takes one parameter which is the packet and is supposed to be executed for every packet capture.
        - The source and destination IPs in the ARP header of the packet are added to the all_traffic list.
        - The packet's op value of the ARP header is checked to be 2.
        - If it was then the packet's source IP and MAC is checked to see if they exists or not.
        - If both of them exist then they are both added to the parings list togeather in one string.
        - If one of them exists then it is added as a string and the other one that doesn't exist is added to that string in the form of question marks.
        - The terminal is then cleared to allow for the enhanced display. The code used for clearing the terminal executes the clear command or the cls command,
        this makes the clearing command that works get executed and the one that doesn't work will not be exeucted [3]. This is good in case we don't know whether
        the script will be executed on a Linux or a Windows system.
        - Print statements display a form of a table where the relevent values go under.
        - In the first print statement, the inteface value is taken from the parameter of the passive_scan function and formatted in the string printed,
        as well as that the number of hosts is also formatted in the printed string by getting the length of the pairnings list as a set to ignore duplicated pairnigns.
        - A for loop goes through the set castation of the list pairings to not encounter any pairing more than once (i.e. not iterate through duplicates).
        - the for loop adds a list with two sub lists for every pairing, the first sub list contains one element which is the number of times the 
        IP address was seen in the all_traffic list,(This information is needed to count the host activity based on the IP addresses only. 
        This sublist is also important because it can be used to sort the pairings based on their host activity value). The second sublist 
        contains one element which is the pairing itself in the form of a string and with tabs added to it to position it under the right table
        column for the enhanced display.
        - The reason why host activity is counted based on the IP addresses only is that in an ARP request usually the destination MAC address is FF:FF:FF:FF:FF:FF,
        however the destination IP address is defined and is legit. This way it is possible to know if the address received a request and if it sent a reply
        based on its IP address.
        - The temp_list is then sorted in a decending order. The list elements are sorted by the value of the element in the first sublist which is the value of
        host activity.
        - After that, another loop goes through the elements (lists) of temp_listy and prints the second sub element (sublist) which is the pairing
        in a form of string.
        - In the last line of the function we have the sniff function call which uses the arp filter to only sniff arp requests, takes the interface
        provided in the passive_scan function parameter and executes the track_pack function for every packet.
        '''
        
        all_traffic.append(str(pkt.psrc))
        all_traffic.append(str(pkt.pdst))

        if pkt.op == 2:      # [2]

            if bool(pkt.hwsrc) == True and bool(pkt.psrc) == True:
                pairings.append(str(pkt.hwsrc) + ' : ' + str(pkt.psrc))

            elif bool(pkt.hwsrc) == False and bool(pkt.psrc) == True:
                pairings.append('??:??:??:??:??:??' + ' : ' + str(pkt.psrc))
                
            elif bool(pkt.hwsrc) == True and bool(pkt.psrc) == False:
                pairings.append(str(pkt.hwsrc) + ' : ' + '???.???.???.???')
                

            os.system('clear||cls') # [3]

            print(f'Interface: {iface} \t Mode: Passive \t\t Found {len(set(pairings))} hosts ')
            print('---------------------------------------------------------------------')
            print('MAC \t\t\t IP \t\t\t Host Activity ')
            print('---------------------------------------------------------------------')
            temp_listy = []
            for i in set(pairings):
                temp_listy.append([[all_traffic.count(i[20:])], f'{i[0:18]} \t {i[20:]} \t\t {all_traffic.count(i[20:])}'])
                temp_listy.sort(reverse=True)
                
            for i in temp_listy:
                print(i[1])


            
    sniff(iface=iface, filter='arp', prn=track_pack) # [4]



def active_recon(iface):
    # Please use Ctrl+z to stop the active recon when you want to stop it because Ctrl+c doesn't work on active recon for some reason but works ok for passive recon


    '''
    - This function carries out active recon by sending ICMP requests to the devices on the network and getting back replies. 
    It takes one parameter which is the interface
    - The commented line below is the code I used to test the function call before adding the network interraction code.
    - After that line I defined an empty string which should later carry have the IP address value.
    - I then defined a variable called ip_address which gets the IP address of the current machine using the interface provided in the paramter and splits it
    based on the '.' special char. This makes every number before or after the  '.' special char in a seperate element in a list and this list is the value of
    the variable ip_address.
    - The value of the ip_address variable is then changed to make it only the first 3 numbers of the IP address.
    - A for loop then iterates through the elements (numbers) of the ip_address variable appending them to a string and appending a '.' special char after 
    each one of them. 
    - An empty list called listy is then created to be used later.
    - A for loop which iterates from number 2 to number 254 is created.
    - For each iteration, an ICMP packet is created with an Ether header and the destination IP address of the ip_string variable value plus the number that the for loop has reached
    in the range of numbers casted to a string.
    - A variable called ans stores the reply of the ICMP echo request packet which uses the inteface provided in the parameter of the active_recon function.
    - The function call that sends the packet and stores the reply is srp1 and it is also given the timeout value of 0.5 to wait for half a second only after sending
    the request packet [7][8]. 
    - Before using srp1 I used sr1 but I was unable to get the Ether header of the reply with it. This is because sr1 doesn't allow the user to handle the Ether header
     and makes scapy handle it instead [7]. 
    To handle the ether header I had to use srp1 so I can add the Ether header manually to the request and be able to view it in the reply [7].
    - It also has the value 0 for the verbose parameter to prevent it from displaying a lot of information on the terminal [8]. 
    - The ans variable is checked whether it has stored a reply or not.
    - If yes then the existence of the IP and MAC addresses is checked as well.
    - If both of them exist then they are both added to the listy list as one string, if not then one is added and the other is also added but in the form of 
    question marks.
    - The terminal is then cleared to allow for the enhanced display.
    - Then some print statements are added to draw the table on the terminal.
    - A nested for loop goes through the elements (addresses) of listy and prints them under the relevent table column.
    - The for loop also prints a MAC address of ??:??:??:??:??:?? since the reply packets contain IP addresses only
    '''
    #print('active ' + str(iface))

    ip_string = ''
    ip_address =(str(get_if_addr(iface))).split('.') # [5]
    ip_address = ip_address[0:3]


    for i in ip_address:
        ip_string+=(i+'.')


    listy = []

    for i in range(2, 255):
        pkt = Ether()/IP(dst=f'{ip_string}{str(i)}')/ICMP() # [6][7]
        ans = srp1(pkt, iface=iface, timeout=0.5, verbose=0) # [7][8]
        if ans: 
            if bool(ans['Ether'].src) == True and bool(ans['IP'].src) == True:
                listy.append(ans['Ether'].src + ' \t '+ ans['IP'].src)
            elif bool(ans['Ether'].src) == False and bool(ans['IP'].src) == True:
                listy.append('??:??:??:??:??:??' + ' \t '+ ans['IP'].src)
            elif bool(ans['Ether'].src) == True and bool(ans['IP'].src) == False:
                listy.append(ans['Ether'].src + ' \t '+ '???.???.???.???')
        os.system('clear||cls')
        print(f'Interface: {iface} \t Mode: Active \t\t Found {len(set(listy))} hosts ')
        print('---------------------------------------------------------------------')
        print('MAC \t\t\t IP')
        print('---------------------------------------------------------------------')
        for j in listy:
            print(j)


main()

'''
References:

[1]: Tutorialspoint, Python - Command Line Arguments, 
Available at: https://www.tutorialspoint.com/python/python_command_line_arguments.htm, [accessed 24 October 2023]

[2]: Thepacketgeek, (2019), Scapy p.07 Monitoring ARP, 
Available at: https://thepacketgeek.com/scapy/building-network-tools/part-07/, [accessed 24 October 2023]

[3]: Stackoverflow, (2016 and 2017), Clear terminal in Python [duplicate], 
Available at: https://stackoverflow.com/questions/2084508/clear-terminal-in-python, [accessed 25 October 2023]

[4]: Dylan Smith MTU Notes, Scripting for Cybersecurity Lab 6 Capturing Packets, 
Available at: https://cit.instructure.com/courses/97536/files/3049138?module_item_id=854687, [accessed 24 October 2023]

[5]: W3schools, Python String split() Method, 
Available at: https://www.w3schools.com/python/ref_string_split.asp, [accessed 27 October 2023]

[6]: Dylan Smith MTU Notes, Scripting for Cybersecurity Interacting with Networks 1,
Available at: https://cit.instructure.com/courses/97536/files/3049127?module_item_id=854674, [accessed 31 October 2023]

[7]: Stackoverflow, (2019), Differences between scapy.sr and scapy.srp, 
Available at: https://stackoverflow.com/questions/55176879/differences-between-scapy-sr-and-scapy-srp, [accessed 31 October 2023]

[8]: scapy.readthedocs.io, Usage, 
Available at: https://scapy.readthedocs.io/en/latest/usage.html, [accessed 31 October 2023]

'''