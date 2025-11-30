import os
import sys
import time
import shutil
import datetime
import subprocess
import smtplib
import random
from socket import gethostname
import inspect
import traceback
import configparser

from pathlib import Path

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.utils import COMMASPACE, formatdate
from email import encoders
#from email import Charset
import string

global verbose
global errorlog


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\u001b[34m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RED = '\u001b[31m'
    GREEN = '\u001b[32m'

def getNow():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def getNowFlat():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def error_log(msg):
    #print("*** ERROR : %s ***" % msg)
    errorlog.append("%s : %s" % (getNow(),msg)) 
    return

def print_log(msg, force=False):
    global verbose
    if force:
        print("%s : %s" % (getNow(), msg))
    elif verbose:
        print("%s : %s" % (getNow(), msg))        
    return

def getCurrentDir():
    curdir = "./"
    try:
        os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
        curdir = os.getcwd()
    except Exception as e:
        error_log("Unable to determine current directory: %s" % str(e))
        pass
    return curdir

def execOSCmdRetVal(cmdarray):
    returncode = 0
    outputlines = []
    try:
        p = subprocess.run(cmdarray, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) 
        returncode = p.returncode
        outputobj = p.stdout.split('\n')
        for thisline in outputobj:
            outputlines.append(thisline.replace('\\n','').replace("'",""))
    except Exception as e:
        error_log("Error running %s: %s" % (cmdarray, str(e)))
    return outputlines, returncode



def showBanner():
    banner = f"""{bcolors.HEADER}{bcolors.BOLD}  
                        8 .oPYo.               o8 
                        8     `8                8 
.oPYo..oPYo. odYo. .oPYo8    oP'ooYoYo. .oPYo.o88 
Yb..  8oooo8 8' `8 8    8 .oP'  8' 8  8 .oooo8 88 
  'Yb.8.     8   8 8    8 8'    8  8  8 8    8 88 
`YooP'`Yooo' 8   8 `YooP' 8ooooo8  8  8 `YooP8 88 
{bcolors.ENDC}{bcolors.OKBLUE}                                                                                                                                                          
 Written by Scav-engeR | HuRRiCaNe
 Tool to easily send mails straight from your cli-interface 
{bcolors.ENDC}"""
    print(banner)
    print("")
    return


def showSyntax(args):
    print (" Usage: %s [arguments]" % args[0])
    print ("")
    print (" Mandatory arguments:")
    print ("     -from '@emailaddress' ")
    print ("     -to '@emailaddress' (separate multiple addresses with a comma)")
    print ("")
    print (" Optional arguments:")
    print ("     -subject 'message'             Message subject")
    print ("     -body 'message'                Message body")
    print ("     -body_file 'file'              Read message body from file")
    print ("     -file 'file1,file2'            File(s) to attach")
    print ("     -host 'ip,ip,ip'               SMTP server(s) to use. Defaults to '127.0.0.1'")
    print ("     -port <number>                 SMTP port to use. Defauls to 25")
    print ("     -v                             verbose output")
    print ("     -html                          send body as HTML")
    print ("")
    return


def readFile(filename):
    thisfile = open(filename, 'r')
    alllines = []
    filecontents = thisfile.readlines()   
    for line in filecontents:
        thisline = line.strip()
        alllines.append(thisline)
    thisfile.close()
    return alllines


def sendEMail(mailOptions):
    
    global verbose

    sender = mailOptions["from"].strip()
    recipients = mailOptions["to"]
    mailsubject = mailOptions["subject"]
    mailbody = mailOptions["body"].split('\\n')
    mailbody_file = mailOptions["body_file"]
    mailhosts = mailOptions["host"]
    mailport = mailOptions["port"]

    for thisrecip in recipients:
        thisrecip = thisrecip.strip()

        print_log("[+] Sending Email From '%s' to '%s'" % (sender, thisrecip), True)
        print_log("    Subject: '%s'" % mailsubject, True)

        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] =  thisrecip
        msg['Subject'] = mailsubject

        msgbody = ""
        for bodyline in mailbody:
            msgbody += "%s\n" % bodyline

        if mailbody_file != "":
            msgbody += "\n"
            extrabody = readFile(mailbody_file)
            for extraline in extrabody:
                msgbody += "%s\n" % extraline

        if mailOptions["html"]:
            hmsgbody = msgbody.replace('\n', '<br>')

            htmlbody = u'<html><body>%s</body></html>' % hmsgbody
            textbody = u'%s' % msgbody

            #Charset.add_charset('utf-8', Charset.QP, Charset.QP, 'utf-8')

            htmlpart = MIMEText(htmlbody.encode('utf-8'), 'html', 'UTF-8')
            textpart = MIMEText(textbody.encode('utf-8'), 'plain', 'UTF-8')
            msg.attach(htmlpart)
            msg.attach(textpart)

        else:
            msg.attach(MIMEText(msgbody, 'plain')) 


        # do we have attachment(s)?

        if len(mailOptions["file"]) > 0:
            for thisfile in mailOptions["file"]:
                thisfile = thisfile.strip()
                if thisfile != "":
                    # see if file exists
                    if os.path.exists(thisfile):
                        print_log("    Attaching file '%s'" % thisfile, True)
                        part = MIMEBase('application', "octet-stream")
                        with open(thisfile, 'rb') as file:
                            part.set_payload(file.read())
                        encoders.encode_base64(part)
                        part.add_header('Content-Disposition',
                                        'attachment; filename="{}"'.format(Path(thisfile).name))
                        msg.attach(part)
                    else:
                        print_log("    ** Could Not Find '%s'" % thisfile)
                        error_log("Could Not Find '%s'" % thisfile)

        mailsentok = False
        attempts = 0
        while not mailsentok and attempts < len(mailhosts):
            mailhost = mailhosts[attempts]
            attempts += 1
            try:
                print_log("[+] Connecting to %s on port %d" % (mailhost, mailport), True)
                smtpObj = smtplib.SMTP(mailhost, mailport)
                if verbose:
                    smtpObj.set_debuglevel(1)
                smtpObj.command_encoding = 'utf-8'
                print_log("    Sending your Mail - in progress", True)
                smtpObj.sendmail(sender, thisrecip, msg.as_string())         
                print_log("    Email has been successfully sent to %s" % thisrecip, True)
                print_log("", True)
                mailsentok = True
            except smtplib.SMTPException as e:
                print_log('SMTP Error Occurred: ' + str(e))
                error_log("SMTP Error Occurred: " + str(e))
                continue
            except Exception as e:
                print_log("Error: Unable to send Mail to %s via host %s: %s" % (thisrecip, mailhost, str(e)))
                error_log("Error: Unable to send Mail to %s via host %s: %s" % (thisrecip, mailhost, str(e)))
                continue
        
    return


def processErrors():
    global errorlog
    if len(errorlog) > 0:
        print(f"{bcolors.FAIL}")
        print("=" * 80)
        print("Errors found:")
        for errorentry in errorlog:
            print("%s" % errorentry)
        print("=" * 80)
        print(f"{bcolors.ENDC}")
    return



if __name__ == "__main__":

    if sys.version_info <(3,0,0):
        sys.stderr.write("You need python3.0 or later to run this script\n")
        exit(1)

    showBanner()
    
    doupdate = True

    global errorlog
    errorlog = []

    global verbose
    verbose = False

    mailOptions = {}

    arguments = []
    if len(sys.argv) >= 2:
        arguments = sys.argv[1:]

    args = {}
    last = ""
    for word in arguments:
        if (word[0] == '-'):
            word = word.lstrip("-")
            args[word] = True
            last = word
        else:
            if (last != ""):
                if str(args[last]) == "True":
                    args[last] = word
                else:
                    args[last] = args[last] + " " + word

    if "h" in args or len(args) < 2 or not ("from" in args and "to" in args):
        showSyntax(sys.argv)
        sys.exit(0)

    if "to" in args:
        if type(args["to"]).__name__.lower() != "bool":
            mailOptions["to"] = args["to"].split(",")

    if "from" in args:
        if type(args["from"]).__name__.lower() != "bool":
            mailOptions["from"] = args["from"]

    if "subject" in args:
        if type(args["subject"]).__name__.lower() != "bool":
            mailOptions["subject"] = args["subject"]
    else:
        mailOptions["subject"] = ""

    if "body" in args:
        if type(args["body"]).__name__.lower() != "bool":
            mailOptions["body"] = args["body"]
    else:
        mailOptions["body"] = ""

    if "body_file" in args:
        if type(args["body_file"]).__name__.lower() != "bool":
            mailOptions["body_file"] = args["body_file"]
    else:
        mailOptions["body_file"] = ""

    if "host" in args:
        if type(args["host"]).__name__.lower() != "bool":
            mailOptions["host"] = args["host"].split(",")
    else:
        mailOptions["host"] = ["127.0.0.1"]

    if "port" in args:
        if type(args["port"]).__name__.lower() != "bool":
            mailOptions["port"] = int(args["port"])
    else:
        mailOptions["port"] = 25

    if "file" in args:
        if type(args["file"]).__name__.lower() != "bool":
            mailOptions["file"] = args["file"].split(",")
    else:
        mailOptions["file"] = [""]

    if "html" in args:
        mailOptions["html"] = True
    else:
        mailOptions["html"] = False

    if "v" in args:
        verbose = True
        
    if "noupdate" in args:
        doupdate = False
        
    if doupdate:
        updatecmd = ["git", "pull"]
        execOSCmdRetVal(updatecmd)
    
    sendEMail(mailOptions)
    processErrors()

    print_log("[+] Done.",True)
