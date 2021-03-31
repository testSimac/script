import json
import socket
import os
import colorama
from colorama import Fore,Style



INFORMATION_LOG = 1001
BRUTE_FORCE_LOG = 6001
PORT_SCAN_LOG = 5001
HTTP_SCAN_LOG = 3000

log_data = []
information_logs = []
bruteforce_logs = []
portscan_logs = []
http_logs = []

def parse_logfile(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            log_data.append(json.loads(line))

def sort_totals():
    for a in log_data:
        if a["logtype"] == INFORMATION_LOG:
            information_logs.append(a)
        elif a["logtype"] == BRUTE_FORCE_LOG:
            bruteforce_logs.append(a)
        elif a["logtype"] == PORT_SCAN_LOG:
            portscan_logs.append(a)
        else:
            http_logs.append(a)
##Works
def print_information_logs():
    print(f"[*] Information logs : {len(information_logs)}")
    for info in information_logs:       
        if info['logdata']['msg'] == "Canary running!!!":
            print(Fore.GREEN + f"[*] T: {info['local_time']} > {info['logdata']['msg']}")
        else:
            print(Fore.CYAN + f"[*] T: {info['local_time']} > {info['logdata']['msg']['logdata']}")
## Not tested yet
def print_bruteforce_logs():
    print(f"[*] Bruteforce logs : {len(bruteforce_logs)}")
    for brute in bruteforce_logs:
        creds = brute['logdata']
        print(Fore.RED + "[*] T: {0:25} >  P: {1} Src: {2:20} U: {3:15} P: {4:15}"
            .format(brute['local_time'],
                    brute['dst_port'], 
                    brute['src_host'],
                    creds['USERNAME'], 
                    creds['PASSWORD']))
##Works
def print_portscan_logs():
    print(f"[*] Portscan logs : {len(portscan_logs)}")
    for scan in portscan_logs:
        print(Fore.RED + " Datum: {0:25} > Port: {1} Source IP: {2:20}"
            .format(scan['local_time'],
                    scan['dst_port'], 
                    scan['src_host']))
##Works
def print_http_logs():
    print(f"[*] Miscellaneous logs : {len(http_logs)}")
    for http in http_logs:
        print(Fore.RED+ "[*] Time: {0:25} >  Port: {1} Source: {2:20} > All Log: \n {3} "
            .format(http['local_time'],
                    http['dst_port'],
                    http['src_host'],
		    http['logdata']))

def print_bruteforce_analytics():
    list_of_ips = []
    usernames = []
    passwords = []   

    for brute in bruteforce_logs:
        creds = brute['logdata']
        if brute['src_host'] not in list_of_ips:
            list_of_ips.append(brute['src_host'])
        if creds["USERNAME"] not in usernames:
            usernames.append(creds['USERNAME'])
        if creds['PASSWORD'] not in passwords:
            passwords.append(creds['PASSWORD'])
    
    list_of_ips.sort()
    usernames.sort()
    passwords.sort()

    print("[*] Bruteforce IP/Hosts")
    for ip in list_of_ips:
        try:
            hostname = socket.gethostbyaddr(ip)
        except:
            hostname = 'host not found'
        
        print(f"IP: {ip} > {hostname}")

    print("[*] Usernames used")
    for username in usernames:
        print(username)

    print("[*] Passwords used") 
    for password in passwords:
        print(password)

def main():
    CANARY_FILE = "opencanary.log"
    choice = 0
    parse_logfile(CANARY_FILE)
    sort_totals()
    while choice ==0:
       os.system("clear")
       print("Author: Umut Ergunes")
       print("#####  Main Menu  #####")
       print(" ")
       print(Fore.BLUE + " 1) Information Logs... ")
       print(Fore.GREEN + " 2) Bruteforce Logs...")
       print(Fore.YELLOW + " 3) Portscan Logs...")
       print(Fore.MAGENTA + " 4) HTTP Logs...")
       print(Fore.CYAN + " 5) Bruteforce Analytics...")
       print(Fore.RED + " 6) Exit...")
       print("")
       choice = int(input(Fore.WHITE + "Enter your choice:"))
       if choice == 1:
         os.system("clear")
         print_information_logs()
         print("")
         print(" 0) <- Go Back")
         choice = int(input("Your Choice : "))
       elif choice == 2:
         os.system("clear")
         print_bruteforce_logs()
         print("")
         print(" 0) <- Go Back")
         choice = int(input("Your Choice : "))
       elif choice == 3:
         os.system("clear")
         print_portscan_logs()
         print("")
         print(" 0) <- Go Back")
         choice = int(input("Your Choice : "))
       elif choice == 4:
         os.system("clear")
         print_http_logs()
         print("")
         print(" 0) <- Go Back")
         choice = int(input("Your Choice : "))
       elif choice == 5:
         os.system("clear")
         print_bruteforce_analytics()
         print("")
         print(" 0) <- Go Back")
         choice = int(input("Your Choice : "))
       elif choice == 6:
         os.system("clear")
         break
       else:
         print("Wrong Input...")
         print("Enter please 0 ....")
         choice = int(input("Your Choice: "))
         
         
    #parse_logfile(CANARY_FILE)
    #sort_totals()
    #print("[*] Log totals\n")
    #print_information_logs()
    #print_bruteforce_logs()
    #print_portscan_logs()
    #print_http_logs()
    #print_bruteforce_analytics()

if __name__ == "__main__":
    main()
