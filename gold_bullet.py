#!/usr/bin/python
# -*- coding: utf-8 -*-

import pexpect
import os
import time
import commands
import subprocess
import telnetlib
import sys
from subprocess import call

author = 'Noor Al Darraji'
version = '1.0.5'



class bcolors:
    MAGENTA = '\033[95m'
    NC = '\033[0m'
    RED = '\033[31m'
    HEART = '\033[1;31m'
    GREEN = '\033[32m'
    GOLD = '\033[33m'
    HGREEN = '\033[92m'
    ARROWH = '\033[95m=\033[0m\033[96m>\033[0m'
    CYAN = '\033[96m'
M = bcolors.MAGENTA
NOC = bcolors.NC
R = bcolors.RED
GR = bcolors.GREEN
GO = bcolors.GOLD
HG = bcolors.HGREEN
AH = bcolors.ARROWH
H = bcolors.HEART
CYAN = bcolors.CYAN


#grep -A 3 '"C220M4-BIOS-[4,9]' /usr/kcsdist/src/UCS/RACKS/DF/FST/FST_VarInit.spk | grep UDIBmcDiagImage | head -n1 | awk '{gsub(/"/, "");print $2}'


def image_name(file_name='', user=os.environ.get('USER')):
   ''' Gets the the image file name from gold bullet config file'''

   check_file = commands.getoutput('ls /home/' + user + '/gold_bullet_config.txt')
   image = ''
   
   if 'cannot access' in check_file: 
       subprocess.Popen(['cp', '/home/noora/gold_bullet_config.txt', '/home/' + user + '/gold_bullet_config.txt'])
       time.sleep(1)
   
   f = subprocess.Popen(['grep', file_name , '/home/' + user + '/gold_bullet_config.txt'], stdout=subprocess.PIPE)
   head = subprocess.Popen(['head' , '-n1'], stdin=f.stdout, stdout=subprocess.PIPE)
   awk = subprocess.Popen(['awk', '{gsub(/,/, "");print $3}'],stdin=head.stdout, stdout=subprocess.PIPE,)
   endOfPipe = awk.stdout
   for line in endOfPipe:
       image = line.strip()
       if image:
           return image 
   if not image:
       return image_name(file_name, user='noora')


print (GO +"    _______       _     _    ______        _ _"+ NOC)
print (GO +"   (_______)     | |   | |  (____  \      | | |         _"+ NOC)
print (GO +"    _   ___  ___ | | __| |   ____)  )_   _| | | _____ _| |_"+ NOC)
print (GO +"   | | (_  |/ _ \| |/ _  |  |  __  (| | | | | || ___ (_   _)"+ NOC)
print (GO +"   | |___) | | | | ( (_| |  | |__)  ) |_| | | || ____| | |_"+ NOC)
print (GO +"    \______/\___/ \_)____|  |______/|____/ \_)_)_____) \___) v" + version + NOC)
print ("")
print (GR + '   Created with ' + R + 'â¤ï¸?' + NOC + GR +' by ' + author + NOC)
#
#â¤ï¸? 
#â?¡ 
print ("")
print ('  +------------------------------------------------------------------------------------------------------------------------------------------+')
print ('  |    CIMC Section [ '+ GO + '#' + NOC +' ]  |    BMC Shell Section [ ' + GO +'$' + NOC +' ]  |    BMC DIAG Section [ ' + GO + '%' + NOC +' ]  |    Linux Shell Section [ ' + GO + '#' + NOC + ' ]  |   UEFI Section [ ' + GO + '>' + NOC + ' ] |')
print ('  +------------------------+-----------------------------+----------------------------+-------------------------------+----------------------+')
print ('  | 01 '+AH+' ' + R + 'SHOW SEL LOG ' + NOC +'    | 19 '+AH+' '+R+'CLEAR DIMM BLACKLIST '+NOC+' | 04 '+AH+' '+ R +'MODULE LEARN ALL   ' +NOC+ '  | 20 '+AH+' '+ R +' BOOT LINUX   ' +NOC+ '          | 23 '+AH+' ' + R + 'BOOT EFI ' + NOC +'      |')
print ('  | 02 '+AH+' ' + R + 'SHOW DIMM PID ' + NOC +'   | 46 '+AH+' '+CYAN+'UPDATE BIOS '+NOC+'          | 05 '+AH+' '+ R +'NETWORK            ' +NOC+ '  | 21 '+AH+' '+ R +' UPGRADE PCIE FW   ' +NOC+ '     | 24 '+AH+' ' + R + 'EFI CACHEX64 ' + NOC +'  |')
print ('  | 03 '+AH+' ' + R + 'SHOW HDD PID ' + NOC +'    |                             | 06 '+AH+' '+ R +'BASEBOARD          ' +NOC+ '  | 22 '+AH+' '+ R +' CKPCIE DIAG   ' +NOC+ '         | 25 '+AH+' ' + R + 'EFI CPUX64' + NOC +'     |')
print ('  | 17 '+AH+' ' + R + 'CLEAR SEL LOG ' + NOC +'   |                             | 07 '+AH+' '+ R +'TEMPSENSOR         ' +NOC+ '  | 34 '+AH+' '+ R +' DISCOVER HDD' +NOC+ '           | 26 '+AH+' ' + R + 'EFI DISKX64' + NOC +'    |')
print ('  | 47 '+AH+' ' + CYAN + 'UPDATE BMC FW ' + NOC +'   |                             | 08 '+AH+' '+ R +'VOLTSENSOR         ' +NOC+ '  | XX '+AH+' '+ R +' TEST USB   ' +NOC+ '            | 27 '+AH+' ' + R + 'EFI GRAPHICX64' + NOC +' |')
print ('  |                        |                             | 09 '+AH+' '+ R +'CURRENTSENSOR        ' +NOC+ '| 36 '+AH+' '+ R +' CHECK BBU   ' +NOC+ '           | 28 '+AH+' ' + R + 'EFI PCHX64' + NOC +'     |')
print ('  |                        |                             | 10 '+AH+' '+ R +'POWERSENSOR          ' +NOC+ '| XX '+AH+' '+ R +' DISK MARVEL   ' +NOC+ '         | 29 '+AH+' ' + R + 'EFI IIOX64' + NOC +'     |')
print ('  |                        |                             | 11 '+AH+' '+ R +'DEVICEINFO           ' +NOC+ '| XX '+AH+' '+ R +' DISK STOR   ' +NOC+ '           | 30 '+AH+' ' + R + 'EFI LPCX64' + NOC +'     |')
print ('  |                        |                             | 12 '+AH+' '+ R +'SPROM                ' +NOC+ '| XX '+AH+' '+ R +' TEST SD   ' +NOC+ '             | 31 '+AH+' ' + R + 'EFI PCIX64' + NOC +'     |')
print ('  |                        |                             | 13 '+AH+' '+ R +'NCSI                 ' +NOC+ '| 40 '+AH+' '+ R +' CPU TEMP   ' +NOC+ '            | 32 '+AH+' ' + R + 'EFI QPIX64' + NOC +'     |')
print ('  |                        |                             | 14 '+AH+' '+ R +'FLASH                ' +NOC+ '| 41 '+AH+' '+ R +' PMEM2 -m1 -s0 -l2 ' +NOC+ '     | 33 '+AH+' ' + R + 'EFI USBX64' + NOC +'     |')
print ('  |                        |                             | 15 '+AH+' '+ R +'GPIO                 ' +NOC+ '| 42 '+AH+' '+ R +' PMEM2 -m2 -s0 -l15' +NOC+ '     |                      |')
print ('  |                        |                             | 16 '+AH+' '+ R +'PMBUS                ' +NOC+ '| 43 '+AH+' '+ R +' PMEM2 -m3 -s0 -l2' +NOC+ '      |                      |')
print ('  |                        |                             |                            | 44 '+AH+' '+ R +' PMEM2 -m4 -s0 -l2' +NOC+ '      |                      |')
print ('  |                        |                             |                            | 45 '+AH+' '+ R +' PMEM2 -m2 -s1 -l2' +NOC+ '      |                      |')
print ('  |                        |                             |                            |                               |                      |')
print ('  +------------------------+-----------------------------+----------------------------+-------------------------------+----------------------+')
print ("")



test_selection = input('[' + M + '+' + NOC + ']'' Please Select your Test Number : ') 

def bmc_sel_test():
    
    ip = input('[' + M + '+' + NOC + ']'' Please enter the UUT IP Address: ' + HG + '10.1.1.' + NOC)
    c = pexpect.spawn('/usr/bin/ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no admin@10.1.1.' + ip )
    #c.expect('\?')
    #c.sendline('yes')
    c.expect('password:', timeout=15)
    c.sendline('password')
    c.expect('#')
    c.sendline('scope sel')
    c.expect('#')
    c.sendline('show entries | no-more')
    c.expect('#')
    
    #c.sendline('ipmi-query sel')
    #c.expect('$')
    print (c.before) 
    #.decode('utf-8').split('\r\n')[1]

def bmc_clear_sel_log():
    
    ip = input('[' + M + '+' + NOC + ']'' Please enter the UUT IP Address: ' + HG + '10.1.1.' + NOC)
    c = pexpect.spawn('/usr/bin/ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no admin@10.1.1.' + ip )
    #c.expect('\?')
    #c.sendline('yes')
    c.expect('password:', timeout=15)
    c.sendline('password')
    print ('[' + M + '+' + NOC + ']' ' Connected through Secure Shell.\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
    c.expect('#')
    c.sendline('scope sel')
    c.expect('#')
    print ('[' + M + '+' + NOC + ']' ' Clearing the SEL log.\t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
    c.sendline('clear')
    c.expect('[y|N]', timeout=10)
    c.sendline('y')
    c.expect('#')
    print ('[' + M + '+' + NOC + ']' ' SEL has been cleared.\t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
    
    #c.sendline('ipmi-query sel')
    #c.expect('$')
    #print c.before#.decode('utf-8').split('\r\n')[1]

def clear_dimmbl():
    
    ip = input('[' + M + '+' + NOC + ']'' Please enter the UUT IP Address: ' + HG + '10.1.1.' + NOC)
    c = pexpect.spawn('/usr/bin/ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no admin@10.1.1.' + ip )
    #c.expect('\?')
    #c.sendline('yes')
    c.expect('password:', timeout=15)
    c.sendline('password')
    print ('[' + M + '+' + NOC + ']' ' Connected through Secure Shell.\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
    c.expect('#')
    c.sendline('connect debug-shell')
    c.expect('#')
    #print ('[' + M + '+' + NOC + ']' ' Clearing the SEL log.\t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
    c.sendline('dimmbl')
    c.expect('#')
    print ("----------------------------------------------------------------------------------------------------------")
    print (c.before)
    print ("----------------------------------------------------------------------------------------------------------")
    print ("")
    clear_dimm_bl = input('[' + M + '+' + NOC + ']' ' Do you want to continue to clear the black list? [Y/n]: ')
    print ("")
    c.sendline('sldp')
    c.expect(']')
    if clear_dimm_bl == 'y' or clear_dimm_bl == 'Y':
        c.sendline('IPMICmd 36 0 1A FF')
        print ('[' + M + '+' + NOC + ']' ' Clearing the DIMM Black List.\t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
        c.expect(']')
        print ('[' + M + '+' + NOC + ']' ' Sending IPMI Command..\t\t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
        print ('[' + M + '+' + NOC + ']' ' DIMM Black List DB has been cleared.\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
        print ('[' + M + '+' + NOC + ']' ' Double check for remaining errors.. \t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
        c.sendline('DimmBL-TestTool -R | grep -i "Yes" | wc -l')
        c.expect(']')
        res = '0'
        if res not in c.before:
          print ('[' + M + '+' + NOC + ']' + R + ' Not all DIMMs has been cleared, error still exist!\t\t\t\t\t '+ NOC)
        elif res in c.before:
          print ('[' + M + '+' + NOC + ']' ' All errors has been gone.. \t\t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
        else:
          print ('[' + M + '+' + NOC + ']' " Operation has been cancelled.")        

def bmc_mem_test():
    
    ip = input('[' + M + '+' + NOC + ']'' Please enter the UUT IP Address: ' + HG + '10.1.1.' + NOC)
    c = pexpect.spawn('/usr/bin/ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no admin@10.1.1.' + ip )
    #c.expect('\?')
    #c.sendline('yes')
    c.expect('password:', timeout=15)
    c.sendline('password')
    c.expect('#')
    c.sendline('scope chassis')
    c.expect('#')
    c.sendline('show dimm-pid | no-more')
    c.expect('#')
    #c.sendline('ipmi-query sel')
    #c.expect('$')
    print (c.before)#.decode('utf-8').split('\r\n')[1]

def bmc_hdd_test():
    
    ip = input('[' + M + '+' + NOC + ']'' Please enter the UUT IP Address: ' + HG + '10.1.1.' + NOC)
    c = pexpect.spawn('/usr/bin/ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no admin@10.1.1.' + ip )
    #c.expect('\?')
    #c.sendline('yes')
    c.expect('password:', timeout=15)
    c.sendline('password')
    c.expect('#')
    c.sendline('scope chassis')
    c.expect('#')
    c.sendline('show hdd-pid | no-more')
    c.expect('#')
    print (c.before)
    #c.sendline('ipmi-query sel')
    #c.expect('$')


def update_bios():
    
    hostname = input('[' + bcolors.MAGENTA + '+' + bcolors.NC + ']' ' Please enter the UUT IP Address: ' + HG + '10.1.1.' + NOC)
    default_image = input('[' + bcolors.MAGENTA + '+' + bcolors.NC + ']' ' Do you want to use the BIOS Image in your Gold Bullet config file? [Y/n]: ')
    if default_image == 'n' or default_image == 'N':
        select_platform = input('[' + bcolors.MAGENTA + '+' + bcolors.NC + ']' ' Please Select the UUT Platform eg. [ ' + GR + 'S3X60M5' + NOC +' ] [ '+ GR  +'C480M5' + NOC +' ] [ '+ GR + 'C240M5' + NOC +' ] [ '+ GR +'C220M5'+ NOC +' ]: ')
        print
        print ('    +---------{' + M +' BIOS IMAGES LIST' + NOC +' }----------+')
        subprocess.call('ls  /tftpboot/ | grep "' + select_platform + '-BIOS"| awk \'{$0="    |\t"$0"\t    |"}\'1', shell=True)
        print ('    +---------------------------------------+')
        print 
        bm = input('[' + bcolors.MAGENTA + '+' + bcolors.NC + ']' ' Enter BIOS Image: ')
        pass
    
    else:
     
        bm = image_name('BIOS')    
        print ('[' +  M + '+' + NOC + ']' ' BIOS Image used [ ' + HG + bm + NOC + ' ].\t [ ' + GR + 'OK' + NOC +' ]') 
        pass

    user = ("root")
    tn = telnetlib.Telnet('10.1.1.' + hostname)
    tn.read_until("login: ")
    print ('[' +  M + '+' + NOC + ']' ' Connection Established.\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
    tn.write(user + "\n")
    tn.read_until("]$")
    print ('[' + M + '+' + NOC + ']' ' Linux prompt found.\t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
    
    tn.write("\n")
    tn.write("blade-power off\n")
    print ('[' + M + '+' + NOC + ']' ' Powering off the UUT.\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
    tn.read_until("[ Success ]")
    print ('[' + M + '+' + NOC + ']' ' UUT is now is in power off state. \t\t\t [ ' + GR + 'OK' + NOC +' ]')
    tn.write("\n")
    tn.read_until("]$")
    tn.write("\n")
    print ('[' + M + '+' + NOC + ']' ' Executing the BIOS-UPDATE command inside the shell.  [ ' + GR + 'OK' + NOC +' ]')
    tn.write("bios-update -P -M -C -b -f -s -r 10.1.1.1 -u " + bm + "\n")
    tn.read_until('[STATUS] = [ Image Download (0 %), OK ]')
    
    sp_to = 3
    sp_error_msg = ('Validation Failed, rc=36')
    
    print ('[' + M + '+' + NOC + ']' ' Downloading Image (10 %). \t \t\t\t [ ' + GR + 'OK' + NOC +' ]')
    nf_to = 3
    nf_error_msg = ('Error code 1: File not found')
    try:
        nf_error_check = tn.read_until((nf_error_msg), nf_to)
    except EOFError as e:
        print ("Connection is not poor: %s" % e)
      
    if ((nf_error_msg) in (nf_error_check)):
        print ('[' + R + '+' + NOC + ']' ' File Not Found! \t\t\t\t\t [' + R + ' CHECK FILE NAME' + NOC + ' ]')
        tn.write("exit\n")
        sys.exit()
    else:
        tn.read_until('[STATUS] = [ Image Signature Validate (0 %), OK ]')
        print ('[' + M + '+' + NOC + ']' ' Image Signature Validate (20 %). \t\t\t [ ' + GR + 'OK' + NOC +' ]')
        tn.read_until('[STATUS] = [ Image Header Verification (0 %), OK ]')
        print ('[' + M + '+' + NOC + ']' ' Image Header Verification (41 %). \t\t\t [ ' + GR + 'OK' + NOC +' ]')
    
        # The reason for a seperate Timeout variable is because each failure fail slower than the other, so i keep it like that in case of a change.


        pf_to = 3
        pf_error_msg = ('[STATUS] = [ Error, Image not for this platform ]')
        hw1_to = 3
        hw1_error_msg = ('[STATUS] = [ Error, CPU ID file read failed ]')
        hw2_to = 3
        hw2_error_msg = ('[STATUS] = [ Error, CPU ID mis-match between uploaded image and the platform ]')
        hw_all_to = 3
        hw_all_error_msg = ('[STATUS] = [ Error,')
        try:
             platform_error_check = tn.read_until((pf_error_msg), pf_to)
        except EOFError as n:
            print ("Image not matching the platform: %" % n)
        if ((pf_error_msg) in (platform_error_check)):
            print ('[' + R + '+' + NOC + ']' ' Image Verification error \t\t\t\t [' + R + ' This Image is not for this Platform!' + NOC + ' ]')
            tn.write("exit\n")
            sys.exit()
            platform_error_check = tn.read_until((hw1_error_msg), hw1_to)
        elif ((hw1_error_msg) in (platform_error_check)):
            print ('[' + R + '+' + NOC + ']' ' CPU ID cannot be found! \t\t\t\t [' + R + ' Possible Hardware Error!' + NOC + ' ]') 
            tn.write("exit\n")
            sys.exit()
            platform_error_check = tn.read_until((hw2_error_msg), hw2_to)
        elif ((hw2_error_msg) in (platform_error_check)):
            print ('[' + R + '+' + NOC + ']' ' CPU ID mis-match between uploaded image and the platform! \t\t [' + R + ' Possible Hardware Error!' + NOC + ' ]')
            tn.write("exit\n")
            sys.exit()
            platform_error_check = tn.read_until((hw_all_error_msg), hw_all_to)
        elif ((hw_all_error_msg) in (platform_error_check)):
            print ('[' + R + '+' + NOC + ']' ' Error accrued during BIOS Update \t\t\t\t [' + R + ' Possible Hardware Error!' + NOC + ' ]') 
            tn.write("exit\n")
            sys.exit()
        else: 
            tn.read_until('[STATUS] = [ Write Host Flash (50 %), OK ]')
            print ('[' + M + '+' + NOC + ']' ' Write Host Flash (90 %). \t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
            tn.read_until("Install Done")
            print ('[' + M + '+' + NOC + ']' ' Install done. \t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
            tn.write("\n")
            print ('[' + M + '+' + NOC + ']' ' Activating the BIOS image. \t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
            tn.write("bios-update -a 0 -s\n")
            tn.read_until('Activation Done')
            print ('[' + M + '+' + NOC + ']' ' Image activated. \t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
            print ('[' + M + '+' + NOC + ']' ' Firmware Update completed successfully. \t\t [ ' + GR + 'OK' + NOC +' ]')
            tn.write("\n")
            tn.write("exit\n")



def update_bmc():
    
    ip = input('[' + bcolors.MAGENTA + '+' + bcolors.NC + ']' ' Please enter the UUT IP Address: ' + HG + '10.1.1.' + NOC)
    fw = image_name('cimc')
    print ('[' + M + '+' + NOC + ']' ' Connecting..') 
    child = pexpect.spawn('/usr/bin/ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no admin@10.1.1.' + ip)
    child.expect('password:', timeout=20)
    child.sendline('password')
    #child.logfile = sys.stdout
    child.expect('#')
    print ('[' + M + '+' + NOC + ']' ' Connected.') 
    print ('[' + M + '+' + NOC + ']' ' Updating the UUT using the Firmware file name in gold bullet config [ ' + HG + fw + NOC + ' ]')
    child.sendline('scope cimc/firmware')
    child.expect('#')
    #print ('[' + M + '+' + NOC + ']' ' UUT Firmware is Updating to [ '+ GR + fw + NOC +' ]')
    child.sendline('update tftp 10.1.1.1 ' + fw)
    child.expect('#')
    child.sendline('show detail | grep Prog')

    while True:
        child.expect('#')
        child.sendline('show detail | grep Prog')
        notpr = child.before.decode('utf-8').split('\r\n')[1]
        pr_output =  ('%s') % notpr.split(' ')[6]
        if pr_output != "100":
            print ('[' + M + '+' + NOC + ']' ' Update Progress:' ' %s' ) % pr_output
            time.sleep(25)
        elif pr_output == "100":
            print ('[' + M + '+' + NOC + ']' ' Update Progress:' ' %s' ) % pr_output
            print ('[' + M + '+' + NOC + ']' ' Firmware has been Updated Successfully!' )   
            child.sendline('activate')
            child.expect('#')
            child.sendline('y')
            child.expect('#')
            print ('[' + M + '+' + NOC + ']' ' Activation Done.' )
            break


def bmc_diag(
        
        run_test_name='',
        print_test_name='',
        timeout_1='',
        timeout_2='',
        timeout_3='',
        timeout_4='',
        image_name=''
        
        ):
    
    ip = input('[' + M + '+' + NOC + ']'' Please enter the UUT IP Address: ' + HG + '10.1.1.' + NOC)
    c = pexpect.spawn('/bin/telnet 10.1.1.' + ip )
    c.expect('login:')
    c.sendline('root')
    c.expect(']', timeout_1)
    print ('[' + M + '+' + NOC + ']' ' Linux prompt found.\t\t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
    print ('[' + M + '+' + NOC + ']' ' Configued DIAG File '+ HG  + image_name + NOC + '\t [ ' + GR + 'OK' + NOC +' ]')
    c.sendline('cd /usr/local/bin/')    
    print ('[' + M + '+' + NOC + ']' ' Changing location to binray directory \t\t\t [ ' + GR + 'OK' + NOC +' ]')
    c.expect(']')
    c.sendline('ls udi*')
    c.expect(']')
    #print c.before.split(' ')
    if image_name not in c.before:
       #c.expect(']', timeout_2)
       c.sendline('tftp -gr ' + image_name + ' 10.1.1.1')
       print ('[' + M + '+' + NOC + ']' ' Downloading the BMC DIAG Image to the UUT. \t\t\t [ ' + GR + 'OK' + NOC +' ]')
       c.expect(']', timeout_3)
       print ('[' + M + '+' + NOC + ']' ' Image Download complete. \t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
       c.sendline('chmod 777 ' + image_name)
       c.expect(']', timeout_4)
       pass
    #else:
    c.sendline('./'+ image_name )
    print ('[' + M + '+' + NOC + ']' ' Image Executed. \t\t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
    c.expect('%')
    print ('[' + M + '+' + NOC + ']' ' BMC DIAG Shell Received. \t\t\t\t\t [ ' + GR + 'OK' + NOC +' ]')
   # c.sendline('exec blade-power cycle')
   # c.expect('%', timeout=40)
   # print ('PCD')
   # time.sleep(5)
   # count = 600
    #while count > 1:
    #    c.sendline('exec cat /proc/nuova/gpio/fm_bios_post_cmplt')
    #    c.expect('%', timeout=15)
        #print c.before.split('\n')
    #    if '0' in c.before:
    #        #print ("DID NOT COMPLETE POST")
    #        count - 1
    #        continue
    #    else:
    c.sendline('module learn all')
    print ('[' + M + '+' + NOC + ']' ' Executed learn Modules all Command. \t\t\t [ ' + GR + 'OK' + NOC +' ]')
    c.expect('%')
    c.sendline('verbosity enable verbose')
    print ('[' + M + '+' + NOC + ']' ' Executed verbosity enable verbose  command. \t\t [ ' + GR + 'OK' + NOC +' ]')
    c.expect('%')
    c.sendline(run_test_name)
    print ('[' + M + '+' + NOC + ']' ' ' + print_test_name +' test executed, waiting for results...  \t\t [ ' + GR + 'OK' + NOC +' ]')
    c.expect('%')
    print ("----------------------------------------------------------------------------------------------------------")
    print (c.before)
    print ("----------------------------------------------------------------------------------------------------------")
     #       break

def mount(
        
        ip_address,
        host_test_name,
        host_boot_order,
        host_boot_mode,
        post_prompt,
        post_state,
        first_command,
        second_command,
        third_command,
        fourth_command,
        first_test_prompt,
        second_test_prompt
        
        ):
    
           
    #print ('[' + M + '+' + NOC + ']' ' UUT is already mounted with the configured image '+NOC)
    
    """     
    here we are going to connect to the unit and set some options so the unit is able to boot to Linux 
    
    """
    
    c = pexpect.spawn('/usr/bin/ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no admin@10.1.1.' + ip_address )
    print ('[' + M + '+' + NOC + ']'' Connecting to UUT') 
    c.expect('password:', timeout=15)
    to = timeout=15
    c.sendline('password')
    c.expect('#', timeout=15)
    print ('[' + M + '+' + NOC + ']'+ HG + ' Connected.' + NOC) 
    c.sendline('scope bios')
    c.expect('#')
    #print c.before
    print ('[' + M + '+' + NOC + ']'' Entered BIOS setting')
    c.sendline('set boot-order ' + host_boot_order)
    print ('[' + M + '+' + NOC + ']'' Set BIOS boot order to ' + host_boot_order)
    c.expect('#', timeout=15)
    print ('[' + M + '+' + NOC + ']'' Commiting change.')
    #c.expect('#', to)
    #print c.before
    #if 'require a reboot' in c.before:
    print ('[' + M + '+' + NOC + ']'' UUT Requires reboot')
    c.sendline('commit')
    #c.expect('#', timeout=15)
    #print c.before
    print ('[' + M + '+' + NOC + ']'' A system reboot has been initiated')
    #elif 'invalid command' in c.before:
    time.sleep(2)
    c.sendline('y')
    time.sleep(2)
    c.expect('#')
    c.sendline('set boot-mode ' + host_boot_mode)
    print ('[' + M + '+' + NOC + ']'' Set BIOS boot mode to ' + host_boot_mode)
    c.expect('#', timeout=15)
    if 'require a reboot' in c.before:
        print ('[' + M + '+' + NOC + ']'' UUT Requires reboot')
        c.sendline('y')
        c.expect('#', timeout=15)
        #print c.before
        print ('[' + M + '+' + NOC + ']'' A system reboot has been initiated')
    else:
        c.sendline('top')
        c.expect('#')
        c.sendline('scope sol')
        c.expect('#')
        #print c.before
        print ('[' + M + '+' + NOC + ']'' Entered Serial Over Lan setting')
        c.sendline('set enabled yes')
        c.expect('#')
        time.sleep(1)
        c.sendline('commit')
        c.expect('#', timeout=60)
        #print c.before
        print ('[' + M + '+' + NOC + ']'' Set SOL enabled')
        c.sendline('top')
        c.expect('#')
        c.sendline('scope bios')
        c.expect('#')
        c.sendline('scope server-management')
        c.expect('#')
        #print c.beforei
        print ('[' + M + '+' + NOC + ']'' Set Console Redirection to COM0')
        c.sendline('set ConsoleRedir COM_0')
        c.expect('#')
        time.sleep(3)
        c.sendline('commit')
        #print c.before
        if 'require a reboot' in c.before:
            print ('[' + M + '+' + NOC + ']'' UUT Requires reboot')
            c.sendline('y')
            c.expect('#')
            #print c.before
            print ('[' + M + '+' + NOC + ']'' A system reboot has been initiated')
        else:
            c.sendline('top')
            c.expect('#')
            #print c.before
            #c.expect('#')
            c.sendline('connect debug-shell')
            c.expect(']')
            print ('[' + M + '+' + NOC + ']'' Connected to debug shell')
            #print c.before
            c.sendline('sldp')
            c.expect(']', to)
            c.sendline('blade-power cycle')
            c.expect('Success', timeout=60)
            c.expect(']', timeout=25)
            print ('[' + M + '+' + NOC + ']'' Sending Power Cycle signal to the UUT..')
            c.sendline('exit')
            time.sleep(4)
            c.expect('#', timeout=60)
            c.sendline('exit')
            c.expect('#')
            print ('[' + M + '+' + NOC + ']'' Connecting to UUT Host through Serial Over Lan')
            c.sendline('connect host')
            c.sendline('\n\n')
            #c.interact()
            #print(pexpect.EOF)
            #time.sleep(15)
            c.expect('Configuring and testing memory..', timeout=500)
            print ('[' + M + '+' + NOC + ']'' Configuring and testing memory')
            c.expect('Configuring platform hardware...', timeout=500)
            print ('[' + M + '+' + NOC + ']'' Configuring and testing hardware..')
            #if 'Insert Boot Media' in c.before:
           #c.expect('Cisco IMC', timeout=500)
            #    print ('[' + M + '+' + NOC + ']'' ' + R + ' ERROR ' + NOC + ': Please unplug the power and plug it back in' + NOC)
            #else:
           #c.expect('Cisco IMC', timeout=500)
        
            '''
      
            DIMMs comparsion need to be done later.
      
            '''
      
            #eff = c.before.decode('utf-8').split(' GB')[-2]
            #effective_memory = eff.split(' ')[-1]
            #ins = c.before.decode('utf-8').split(' = ')[-2]
            #installed_memory = ins.split(' ')[0]
            #print c.before.decode('utf-8').split('Memory')[-3]
            #installed_memory = c.before.decode('utf-8').split(' ')[-11]
            #effective_memory = c.before.decode('utf-8').split(' ')[-6]
            #print('[' + M + '+' + NOC + ']'' Installed Memory = '+ HG + installed_memory + NOC)
            #if installed_memory not in effective_memory:
            #print('[' + M + '+' + NOC + ']'' Effective Memory = '+ R + effective_memory + NOC)
        #else:
           # print('[' + M + '+' + NOC + ']'' Effective Memory = '+ HG + effective_memory + NOC)                 
            # post_prompt='', post_state='', first_command='', second_command='', third_command='', fourth_command='', first_test_prompt='', second_test_prompt='' 
            #time.sleep(120)
            #print c.before
            c.expect(post_prompt, timeout=1000)
            print ('[' + M + '+' + NOC + ']' + HG +' UUT Successfully completed the POST.' + NOC)
            time.sleep(10)
            print ('[' + M + '+' + NOC + ']'' UUT Started to load '+ post_state +'.')
            time.sleep(10)
            print ('[' + M + '+' + NOC + ']'' Interactive Shell or Test Results will be deployed once the ' + post_state + ' completes loading.')
            time.sleep(5)
            print ('[' + M + '+' + NOC + ']'' Please wait for a few minutes..')
            #c.expect('Shell> ', timeout=600)
            c.sendline('\n')
            #c.expect(prompt, timeout=1000) # EFI or Linux Shell
            c.sendline(first_command) 
            c.expect(first_test_prompt, timeout=1000) # Mostly for EFI fs0 [\>]
            c.sendline(second_command) 
            c.expect(second_test_prompt, timeout=1000) # Mostly for EFI fs0 [SRV>]
            c.sendline(third_command) 
            c.expect(second_test_prompt, timeout=1000) # Mostly for EFI fs0 [SRV>]
            c.sendline(fourth_command) 
            c.expect(second_test_prompt, timeout=1000) # Mostly for EFI fs0 [SRV>]
            c.sendline(host_test_name) # run test name
            time.sleep(1)
            print ('[' + M + '+' + NOC + ']'+ HG + ' Deploying shell in 3 seconds...' + NOC)
            time.sleep(1)
            print ('[' + M + '+' + NOC + ']'+ HG + ' Deploying shell in 2 seconds..' + NOC)
            time.sleep(1)
            print ('[' + M + '+' + NOC + ']'+ HG + ' Deploying shell in 1 seconds.' + NOC)
            print ("----------------------------------------------------------------------------------------------------------")
            c.interact()
            #print c.before.decode('utf-8').split('\r\n')
'''

 post_prompt='',
 post_state='',
 first_command='',
 second_command='',
 third_command='',
 fourth_command='',
 first_test_prompt='',
 second_test_prompt=''

'''
def host_boot(

        vmedia_ip_address='',
        vmedia_password='',
        image='',
        host_test_name='',
        host_boot_order='',
        host_boot_mode='',
        post_prompt='',
        post_state='',
        first_command='',
        second_command='',
        third_command='',
        fourth_command='',
        first_test_prompt='',
        second_test_prompt=''
        
        ):

    ip_address = input('[' + M + '+' + NOC + ']'' Please enter the last block of the UUT IP Address: ' + HG + '10.1.1.' + NOC)
    c = pexpect.spawn('/usr/bin/ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@'+ vmedia_ip_address)
    c.expect('password', timeout=15)
    c.sendline(vmedia_password)
    c.expect('#')
    print ('[' + M + '+' + NOC + ']'' Connected to VMedia Server')
    print ('[' + M + '+' + NOC + ']'' Checking Image presence [ '+ GO +  image + NOC +' ]')
    c.sendline ('ls ' + image)
    c.expect('#')
    if 'cannot access' in c.before:
        print ('[' + M + '+' + NOC + '] ' + R + 'The '+ NOC + image + R + ' dose not exist in the VMedia server' + NOC)
        print ('[' + M + '+' + NOC + '] ' 'Please copy the file into your vmedia server and try again') 
    else:
       c.sendline ('ps -ef | grep 10.1.1.' + ip_address + ' | grep -v grep') 
       c.expect('#')
   
       if "10.1.1.%s" % ip_address and image not in c.before:
           
           try:
               
               process_id = c.before.decode('utf-8').split('     ')[1]
               if process_id is not None or ' ':
                   for i in process_id.decode('utf-8').split(' '):
                       if i is not None:
                           cleared_process_id = i
                           
                   print ('[' + M + '+' + NOC + ']'' UUT is Mounted with a different image than the config file.')
                   time.sleep(1)
                   #print cleared_process_id
                   c.sendline ('kill -9 ' + process_id)
                   print ('[' + M + '+' + NOC + ']'' Killing the old mount process..')
                   c.expect('#')
                   print ('[' + M + '+' + NOC + ']'' Process [ ' + cleared_process_id + ' ] has been killed')
                   time.sleep(1)
                   #print process_id
                   print ('[' + M + '+' + NOC + ']' ' Mounting the ISO image using config.txt as a resource.'+NOC)
                   c.sendline ('./vmediactl -ip 10.1.1.%s -user admin -password password -f %s  &' % (ip_address, image))
                   print ('[' + M + '+' + NOC + ']' ' Mounting ['+ GR +' '+ image +' ' + NOC +']')
                   c.expect('#')
                   time.sleep(3)
                   c.sendline('\n\n')
                   c.expect('#')
                   time.sleep(5)
                   #print c.before
                   
                   if "failed" in c.before:
                       print ('[' + M + '+' + NOC + ']'' The script was unable to mount Linux. Check the mounting password and the status of the unit..')
                   if "success" in c.before:
                       #print ('[' + M + '+' + NOC + ']'' Image has been mounted to the UUT.')
                       mount(
                               
                               ip_address,
                               host_test_name,
                               host_boot_order,
                               host_boot_mode,
                               post_prompt,
                               post_state,
                               first_command,
                               second_command,
                               third_command,
                               fourth_command,
                               first_test_prompt,
                               second_test_prompt
                               
                               )
                   else:
                       print ('[' + M + '+' + NOC + ']' + R +' Please check if the UUT is a Live!' + NOC)
                   
           except IndexError as e:
                 
                   #print process_id
                   print ('[' + M + '+' + NOC + ']' ' Mounting the ISO image using config.txt as a resource.'+NOC)
                   c.sendline ('./vmediactl -ip 10.1.1.%s -user admin -password password -f %s  &' % (ip_address, image))
                   print ('[' + M + '+' + NOC + ']' ' Mounting ['+ HG +' '+ image +' ' + NOC +']')
                   c.expect('#')
                   time.sleep(3)
                   c.sendline('\n\n')
                   c.expect('#')
                   time.sleep(5)
                   #print c.before
                   
                   if "failed" in c.before:
                       print ('[' + M + '+' + NOC + ']'' The script was unable to mount Linux. Check the mounting password and the status of the unit..')
                   if "success" in c.before:
                       #print ('[' + M + '+' + NOC + ']'' Image has been mounted to the UUT.')
                       mount(
                               
                               ip_address,
                               host_test_name,
                               host_boot_order,
                               host_boot_mode,
                               post_prompt,
                               post_state,
                               first_command,
                               second_command,
                               third_command,
                               fourth_command,
                               first_test_prompt,
                               second_test_prompt
                               
                               )
                   else:
                       print ('[' + M + '+' + NOC + ']' + R +' The UUT is not a Live!' + NOC)
               
       elif "10.1.1.%s" % ip_address and image in c.before:
           
           print ('[' + M + '+' + NOC + ']' ' UUT is already mounted with the configured image '+NOC)
           
           """     
           
           here we are going to connect to the unit and set some options so the unit is able to boot to Linux 
       
          
           """
       
           c = pexpect.spawn('/usr/bin/ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no admin@10.1.1.' + ip_address )
           print ('[' + M + '+' + NOC + ']'' Connecting to UUT') 
           c.expect('password:', timeout=15)
           to = timeout=15
           c.sendline('password')
           c.expect('#', timeout=15)
           print ('[' + M + '+' + NOC + ']'+ HG + ' Connected.' + NOC) 
           c.sendline('scope bios')
           c.expect('#')
           #print c.before
           print ('[' + M + '+' + NOC + ']'' Entered BIOS setting')
           c.sendline('set boot-order ' + host_boot_order)
           print ('[' + M + '+' + NOC + ']'' Set BIOS boot order to ' + host_boot_order)
           c.expect('#', timeout=15)
           print ('[' + M + '+' + NOC + ']'' Commiting change.')
           #c.expect('#', to)
           #print c.before
           #if 'require a reboot' in c.before:
           print ('[' + M + '+' + NOC + ']'' UUT Requires reboot')
           c.sendline('commit')
           #c.expect('#', timeout=15)
           #print c.before
           print ('[' + M + '+' + NOC + ']'' A system reboot has been initiated')
           #elif 'invalid command' in c.before:
           time.sleep(2)
           c.sendline('y')
           time.sleep(2)
           c.expect('#')
           c.sendline('set boot-mode ' + host_boot_mode)
           print ('[' + M + '+' + NOC + ']'' Set BIOS boot mode to ' + host_boot_mode)
           c.expect('#', timeout=15)
           if 'require a reboot' in c.before:
               print ('[' + M + '+' + NOC + ']'' UUT Requires reboot')
               c.sendline('y')
               c.expect('#', timeout=15)
               #print c.before
               print ('[' + M + '+' + NOC + ']'' A system reboot has been initiated')
           else:
               c.sendline('top')
               c.expect('#')
               c.sendline('scope sol')
               c.expect('#')
               #print c.before
               print ('[' + M + '+' + NOC + ']'' Entered Serial Over Lan setting')
               c.sendline('set enabled yes')
               c.expect('#')
               time.sleep(1)
               c.sendline('commit')
               c.expect('#', timeout=60)
               #print c.before
               print ('[' + M + '+' + NOC + ']'' Set SOL enabled')
               c.sendline('top')
               c.expect('#')
               c.sendline('scope bios')
               c.expect('#')
               c.sendline('scope server-management')
               c.expect('#')
               #print c.beforei
               print ('[' + M + '+' + NOC + ']'' Set Console Redirection to COM0')
               c.sendline('set ConsoleRedir COM_0')
               c.expect('#')
               time.sleep(3)
               c.sendline('commit')
               #print c.before
               if 'require a reboot' in c.before:
                   print ('[' + M + '+' + NOC + ']'' UUT Requires reboot')
                   c.sendline('y')
                   c.expect('#')
                   #print c.before
                   print ('[' + M + '+' + NOC + ']'' A system reboot has been initiated')
               else:
                   c.sendline('top')
                   c.expect('#')
                   #print c.before
                   #c.expect('#')
                   c.sendline('connect debug-shell')
                   c.expect(']')
                   print ('[' + M + '+' + NOC + ']'' Connected to debug shell')
                   #print c.before
                   c.sendline('sldp')
                   c.expect(']', to)
                   c.sendline('blade-power cycle')
                   c.expect('Success', timeout=60)
                   c.expect(']', timeout=25)
                   print ('[' + M + '+' + NOC + ']'' Sending Power Cycle signal to the UUT..')
                   c.sendline('exit')
                   time.sleep(4)
                   c.expect('#', timeout=60)
                   c.sendline('exit')
                   c.expect('#')
                   print ('[' + M + '+' + NOC + ']'' Connecting to UUT Host through Serial Over Lan')
                   c.sendline('connect host')
                   c.sendline('\n\n')
                   #c.interact()
                   #print(pexpect.EOF)
                   #time.sleep(15)
                   c.expect('Configuring and testing memory..', timeout=500)
                   print ('[' + M + '+' + NOC + ']'' Configuring and testing memory')
                   c.expect('Configuring platform hardware...', timeout=500)
                   print ('[' + M + '+' + NOC + ']'' Configuring and testing hardware..')
                   #if 'Insert Boot Media' in c.before:
                   #c.expect('Cisco IMC', timeout=500)
                   #    print ('[' + M + '+' + NOC + ']'' ' + R + ' ERROR ' + NOC + ': Please unplug the power and plug it back in' + NOC)
                   #else:
                   
                   '''
           
                   DIMMs comparsion need to be done later.
           
                   '''
           
                   #eff = c.before.decode('utf-8').split(' GB')[-2]
                   #effective_memory = eff.split(' ')[-1]
                   #ins = c.before.decode('utf-8').split(' = ')[-2]
                   #installed_memory = ins.split(' ')[0]
                   #print c.before.decode('utf-8').split('Memory')[-3]
                   #installed_memory = c.before.decode('utf-8').split(' ')[-11]
                   #effective_memory = c.before.decode('utf-8').split(' ')[-6]
                   #print('[' + M + '+' + NOC + ']'' Installed Memory = '+ HG + installed_memory + NOC)
                   #if installed_memory not in effective_memory:
                   #print('[' + M + '+' + NOC + ']'' Effective Memory = '+ R + effective_memory + NOC)
               #else:
                  # print('[' + M + '+' + NOC + ']'' Effective Memory = '+ HG + effective_memory + NOC)                 
                   #time.sleep(120)
                   #print c.before
                   c.expect(post_prompt, timeout=1000)
                   print ('[' + M + '+' + NOC + ']' + HG +' UUT Successfully completed the POST.' + NOC)
                   time.sleep(10)
                   print ('[' + M + '+' + NOC + ']'' UUT Started to load '+ post_state +'.')
                   time.sleep(10)
                   print ('[' + M + '+' + NOC + ']'' Interactive Shell or Test Results will be deployed once the ' + post_state + ' completes loading.')
                   time.sleep(5)
                   print ('[' + M + '+' + NOC + ']'' Please wait for a few minutes..')
                   #c.expect('Shell> ', timeout=600)
                   c.sendline('\n')
                   #c.expect(prompt, timeout=1000) # EFI or Linux Shell
                   c.sendline(first_command) 
                   c.expect(first_test_prompt, timeout=1000) # Mostly for EFI fs0 [\>]
                   c.sendline(second_command) 
                   c.expect(second_test_prompt, timeout=1000) # Mostly for EFI fs0 [SRV>]
                   c.sendline(third_command) 
                   c.expect(second_test_prompt, timeout=1000) # Mostly for EFI fs0 [SRV>]
                   c.sendline(fourth_command) 
                   c.expect(second_test_prompt, timeout=1000) # Mostly for EFI fs0 [SRV>]
                   c.sendline(host_test_name) # run test name
                   time.sleep(1)
                   print ('[' + M + '+' + NOC + ']'+ HG + ' Deploying shell in 3 seconds...' + NOC)
                   time.sleep(1)
                   print ('[' + M + '+' + NOC + ']'+ HG + ' Deploying shell in 2 seconds..' + NOC)
                   time.sleep(1)
                   print ('[' + M + '+' + NOC + ']'+ HG + ' Deploying shell in 1 seconds.' + NOC)
                   print ("----------------------------------------------------------------------------------------------------------")
                   c.interact()
                   #print c.before.decode('utf-8').split('\r\n')

if test_selection == "01":
    bmc_sel_test()
elif test_selection == "02":
    bmc_mem_test()
elif test_selection == "03":
    bmc_hdd_test()
elif test_selection == "04":
    bmc_diag('module learn all', 'MODULE LEARN ALL', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "05":
    bmc_diag('run network', 'NETWORK', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "06":
    bmc_diag('run baseboard', 'BASEBOARD', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "07":
    bmc_diag('run tempsensor', 'TEMPSENSOR', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "08":
    bmc_diag('run voltsensor', 'VOLTSENSOR', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "09":
    bmc_diag('run currentsensor', 'CURRENTSENSOR', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "10":
    bmc_diag('run powersensor', 'POWERSENSOR', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "11":
    bmc_diag('run deviceinfo', 'DEVICEINFO', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "12":
    bmc_diag('run sprom', 'SPROM', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "13":
    bmc_diag('run ncsi', 'NCSI', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "14":
    bmc_diag('run flash', 'FLASH', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "15":
    bmc_diag('run gpio', 'GPIO', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "16":
    bmc_diag('run pmbus', 'PMBUS', 300, 300, 300, 300, image_name('udi'))
elif test_selection == "17":
    bmc_clear_sel_log()
elif test_selection == "18":
    mount_image_to_uut()
elif test_selection == "19":
    clear_dimmbl()
elif test_selection == "46":
    update_bios()
elif test_selection == "47":
    update_bmc()


    '''

        Linux Section


    '''

elif test_selection == "20":

    ''' 

    vmedia_ip_address='',
    vmedia_password='', 
    image='',
    host_test_name='',
    prompt='',
    host_boot_order='',
    host_boot_mode=''
    
    ):
    
    '''
   
    machine_name = os.getenv('HOSTNAME')
    #print machine_name
    if machine_name == 'fxhdvmh6iofst1':
        #host_boot('10.1.1.7', 'nbv12345', image_name('RHEL'), '\n\n', '~]', 'CDROM', 'Legacy')
        host_boot(
    
                  '10.1.1.7', 
                  'nbv12345',
                  image_name('RHEL'),
                  '\n\n',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  '\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
    else:
        host_boot(
    
                  '10.1.1.6', 
                  'nbv12345',
                  image_name('RHEL'),
                  '\n\n',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  '\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )

elif test_selection == "21":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        #host_boot('10.1.1.7', 'nbv12345', image_name('RHEL'), '\n\n', '~]', 'CDROM', 'Legacy')

        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('RHEL'),
                  'ckpcie -v -f\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  '\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
    else:
        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('RHEL'),
                  'ckpcie -v -f\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  '\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )


elif test_selection == "22":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':


        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('RHEL'),
                  'ckpcie -d -s qle8152\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  '\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
    else:
        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('RHEL'),
                  'ckpcie -d -s qle8152\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  '\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )

elif test_selection == "34":
    #HDD
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':

        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('RHEL'),
                  'storcli_showdrives.sh\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  '\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
    else:
        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('RHEL'),
                  'storcli_showdrives.sh\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  '\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )

elif test_selection == "36":
    #BBU
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':

        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('RHEL'),
                  './storcli64 /c0/cv show all\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /opt/MegaRAID/storcli/\r',
                  '\r',
                  '\r',
                  '#]',
                  '#]'
                  
                  )
    else:
        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('RHEL'),
                  './storcli64 /c0/cv show all\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /opt/MegaRAID/storcli/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
   
   
elif test_selection == "40":
    #CPU_TEMP
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':

        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('RHEL'),
                  './cputemp.sh\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /root/sysdiag/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
    else:
        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('RHEL'),
                  './cputemp.sh\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /root/sysdiag/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
        
        
elif test_selection == "41":
    #PMEM-m1-s0-l2
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':

                # post_prompt='', post_state='', first_command='', second_command='', third_command='', fourth_command='', first_test_prompt='', second_test_prompt='' 
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('RHEL'),
                  './pmem2run -m1 -s0 -l2\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /root/sysdiag/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
    else:
        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('RHEL'),
                  './pmem2run -m1 -s0 -l2\r',
                  'CDROM',
                  'Legacy',
                  'Initializing', 
                  'Linux Dependencies and Services', #post_state
                  '\r', #first_command
                  'cd /root/sysdiag/\r', #second_command
                  '\r', #third_command
                  '\r', #fourth_command
                  ']#', #first_test_prompt
                  ']#' #second_test_prompt
                  
                  )
        
        
elif test_selection == "42":
    #PMEM-m2-s0-l15
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':

        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('RHEL'),
                  './pmem2run -m2 -s0 -l15\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /root/sysdiag/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
    else:
        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('RHEL'),
                  './pmem2run -m2 -s0 -l15\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /root/sysdiag/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
        
elif test_selection == "43":
    #PMEM-m3-s0-l2
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':

        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('RHEL'),
                  './pmem2run -m3 -s0 -l2\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /root/sysdiag/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
    else:
        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('RHEL'),
                  './pmem2run -m3 -s0 -l2\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /root/sysdiag/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
  

elif test_selection == "44":
    #PMEM-m4-s0-l2
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':

        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('RHEL'),
                  './pmem2run -m4 -s0 -l2\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /root/sysdiag/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
    else:
        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('RHEL'),
                  './pmem2run -m4 -s0 -l2\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /root/sysdiag/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )


elif test_selection == "45":
    #PMEM-m2-s1-l2
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':

        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('RHEL'),
                  './pmem2run -m2 -s1 -l2\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /root/sysdiag/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )
    else:
        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('RHEL'),
                  './pmem2run -m2 -s1 -l2\r',
                  'CDROM',
                  'Legacy',
                  'Initializing',
                  'Linux Dependencies and Services',
                  '\r',
                  'cd /root/sysdiag/\r',
                  '\r',
                  '\r',
                  ']#',
                  ']#'
                  
                  )





    ''' 

        UEFI Section


    '''


                # post_prompt='', post_state='', first_command='', second_command='', third_command='', fourth_command='', first_test_prompt='', second_test_prompt='' 

elif test_selection == "23":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('UEFI'),
                  'cls\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
    else:

        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('UEFI'),
                  'cls\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )

elif test_selection == "24":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run cachex64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
    else:

        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run cachex64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )

elif test_selection == "25":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run cpux64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
    else:

        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run cpux64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )

elif test_selection == "26":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run diskx64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
    else:

        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run diskx64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
elif test_selection == "27":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run graphicx64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
    else:

        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run graphicx64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )

elif test_selection == "28":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run pchx64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
    else:

        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run pchx64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )

elif test_selection == "29":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run iiox64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
    else:

        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run iiox64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )

elif test_selection == "30":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run lpcx64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
    else:

        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run lpcx64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )

elif test_selection == "31":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run pcix64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
    else:

        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run pcix64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )

elif test_selection == "32":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run qpix64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
    else:

        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run qpix64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )

elif test_selection == "33":
    machine_name = os.getenv('HOSTNAME')
    if machine_name == 'fxhdvmh6iofst1':
        
        host_boot(

                  '10.1.1.7', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run usbx64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
    else:

        host_boot(

                  '10.1.1.6', 
                  'nbv12345',
                  image_name('UEFI'),
                  'run usbx64\r',
                  'EFI',
                  'Uefi',
                  'Shell>',
                  'UEFI Shell',
                  'fs0:\r',
                  'Dsh.efi\r',
                  'run selftest\r',
                  'saveconfig\r',
                  '\> ',
                  'SRV'
                  
                  )
