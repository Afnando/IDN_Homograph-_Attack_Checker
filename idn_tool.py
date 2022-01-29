import json
import idna
import whois
import tldextract
from sys import exit,argv
from textwrap import dedent
from tld import is_tld,get_tld
from tldextract.tldextract import ExtractResult
from argparse import ArgumentParser, RawDescriptionHelpFormatter

white, red, yellow, green, END = '\33[;97m', '\33[1;91m', '\33[1;93m', '\33[1;32m', '\33[0m'

def banner():

    '''
    Show banner of tool 
    :return: banner
    '''

    msg = '''   
{3} _____ _____   _    _ {1}{2}       _                  _
{3}|_   _|     \ | \  | |{1}{2}      | |                | |  
{3}  | | |  __  \|  \ | |{1}{2}      | |                | | __
{3}  | | | |  \  |   \| |{1}{2}  ____| |__   ____  _____| |/ / 
{3}  | | | |__/  | |\   |{1}{2} / ___|  _ \ / _  \/  ___|   < 
{3} _| |_|      /| | \  |{1}{2}| (___| | | |  __ |  (___| |\ \ {1}
{3}|_____|_____/ |_|  \_|{1}{2} \____|_| |_|\____|\_____|_| \_\  
            
            {2}.. .*** < AFNAN > ***. ..{1}         
\n\n{2}Checking IDN Homograph Attack ... . {1}
    '''
    return msg.format(green,END,white,red)

def parseHandle():

    parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description="IDN Homograph Attack Detector.", epilog=dedent('''\
            Examples:
                python idn_tool.py --url google.com -c
                python idn_tool.py --url google.com -p
                python idn_tool.py --url_file urls.txt
                python idn_tool.py --url google.com || --url-list urls.txt '''.format(argv[0])))

    parser.add_argument("--url", dest= "url", action = "store", help= "Enter domain name to check homoglyph characters")
    parser.add_argument("--url_file", dest= "url_file", action ="store", help= "Import domains from a file and check them)")
    parser.add_argument("-p", dest="punycode", action ="store_true", help="Translate IDN to Punycode")
    parser.add_argument("-w", dest="whois",action = "store_true", help="Domain Information")
    parser.add_argument("-c", dest="check",action ="store_true", help="Check domain name")

    args = parser.parse_args()

    return args, parser

#open idnchar.json file that contains homoglyphs characters
with open("idnchar.json", encoding="utf-8") as homoglyph_file:
    data = json.load(homoglyph_file)

#check and extract URL
def checkInput(url):

    try:

        d = get_tld(url,fix_protocol = True)

        #Check if some tld is a valid tld
        if is_tld(d) == True:

            #extract subdomain,domain and suffix
            ext = tldextract.extract(url)

            #if subdomain empty
            if  not ext.subdomain: 
                domain_Name = ext.domain
                return domain_Name

            else:
                #join subdomain and domain
                domain_Name = ".".join(ext[:2])  
                return domain_Name

    except: 
        print("Invalid Domain Name!!!")
        exit()
    
#compare char in domain name
def checkHomoChar(domain_Name):

    value = []
    for c in domain_Name: #access each char in url
        for cha in data: #access each homogylyph char in idnchar.json
            if c in cha: #compare each char with json object
                value.append(c) #list contain matching char

    return value

#display for checkHomoChar()          
def getDisplay(value,url):

    #check value is empty or not
    if not value: 
        print("Domain Name: " +url)
        print("{0} *\n--------* No Homoglyph Characters Detected!!! *--------* {1}".format(green,END))      
        print("{0} *-------------* This Domain Name is Safe *------------* {1}".format(green,END)) 

    else:
        #access each char in list of value
        for out in value:
            print("\n{0}Homoglyph Character: {1}{2}{3}{1}".format(yellow,END,red,data[out]["char"])),
            print("{0}Name: {1}{2}{3}{1}".format(yellow,END,red,data[out]["name"])),
            print("{0}Codepoint: {1}{2}{3}{1}".format(yellow,END,red,data[out]["codepoint"])),
        print("\n{0} *--------* This Domain Name is Suspicious!!! *--------* {1}".format(red,END))

#read file 
def readFile(file):

    list_dm = []

    try:
        with open(file,encoding = "utf-8") as f:
            for line in f:
                # reading each word        
                for word in line.split():
                    list_dm.append(word)
                
        return list_dm

    except:
        print("File not found!!!") 

#check homoglyph character in file
def checkHomoCharFile(list_dm):

    w = dict()

    for words in list_dm:
        for cf in words: #access each char in url
            for cha in data: #access each homogylyph char in idnchar.json
                if cf in cha: #compare each char with json object
                    if words not in w:
                        w[words] = list()
                    w[words].extend(cf)
                        #w.update({words:[cf]})
    return w

#display for checkHomoCharFile()
def getDisplayFile(w):

        #access each domain name
        for words in w:
            print ("\n\nDomain Name: " +words)
            print ("---------------------------")
            #access each value/char of domain name in w dict
            for cf in w.get(words):
                print("\n{0}Homoglyph Character: {1}{2}{3}{1}".format(yellow,END,red,data[cf]["char"])),
                print("{0}Name: {1}{2}{3}{1}".format(yellow,END,red,data[cf]["name"])),
                print("{0}Codepoint: {1}{2}{3}{1}".format(yellow,END,red,data[cf]["codepoint"])),
            print("\n{0} *--------* This Domain Name is Suspicious!!! *--------* {1}".format(red,END))

#convert IDN to Punycode
def convertPuny(url):

    p = idna.encode(url)
    puny = p.decode("UTF-8")
    print("\n{0}Punycode: {1}{1}{2}{3}{1}".format(yellow,END,red,puny))


def getWhois(url):

    w = whois.whois(url)

    print("\n{0}*-----* WHOIS *-----*{1}".format(green,END))
    #print the name of registrar
    print("\nDomain Registrar: ",w.registrar)
    # print the WHOIS server
    print("WHOIS Server: ", w.whois_server)
    # Print the creation date
    print("Domain Creation Date: ",w.creation_date)
    #print the expiration date
    print("Expiration Date: ", w.expiration_date)


#define main function
def main():

    args = parseHandle()[0]
    parse = parseHandle()[1]

    print(banner())

    if len(argv) < 2:
        parse.print_help()
        exit(1)

    #display homoglyph character
    if args.url and args.check and not args.punycode and not args.whois:
        u = checkInput(args.url)
        dis = checkHomoChar(u)
        getDisplay(dis,args.url)
        l = len(data)
        print(l)
    
    #display punycode
    elif args.url and not args.check and args.punycode and not args.whois:
        u = checkInput(args.url)
        convertPuny(args.url)

    #display homoglyph character,punycode
    elif args.url and args.check and args.punycode and not args.whois:
        u = checkInput(args.url)
        dis = checkHomoChar(u)
        getDisplay(dis,args.url)
        convertPuny(args.url)

    #display whois
    elif args.url and not args.check and not args.punycode and args.whois:
        u = checkInput(args.url)
        getWhois(args.url)

    #display homoglyph character and whois
    elif args.url and args.check and not args.punycode and args.whois:
        u = checkInput(args.url)
        dis = checkHomoChar(u)
        getDisplay(dis,args.url)
        getWhois(args.url)
    
    #display homoglyph character,punycode and whois
    elif args.url and args.check and args.punycode and args.whois:
        u = checkInput(args.url)
        dis = checkHomoChar(u)
        getDisplay(dis,args.url)
        convertPuny(args.url)
        getWhois(args.url)

    #display homoglyph character in file
    if args.url_file:
        d= readFile(args.url_file)
        e=checkHomoCharFile(d)
        getDisplayFile(e)
    
if __name__ == "__main__":

    main()
