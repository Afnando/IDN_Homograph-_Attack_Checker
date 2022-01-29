import os
import json
import idna
import whois
import tldextract
from types import resolve_bases
from tld import is_tld,get_tld
from tldextract.tldextract import ExtractResult
from werkzeug.utils import secure_filename 
from werkzeug.exceptions import RequestHeaderFieldsTooLarge
from flask import Flask, render_template, request, redirect, flash, abort

app = Flask(__name__)
app.secret_key = 'super secret key'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024  # 1MB limit
UPLOAD_EXTENSIONS = 'txt'        # only accept .txt file

#open idnchar.json file that contains homoglyphs characters
with open("idnchar.json", encoding="utf-8") as homoglyph_file:
    data = json.load(homoglyph_file)

#check domain name
def checkInput(url):

    try:
        #Get TLD name, ignoring the missing protocol
        d = get_tld(url,fix_protocol = True)

        #Check if some tld is a valid tld
        if is_tld(d) == True:
            return True

    except:
        return False

#extract tld in url
def getExtractTLD(url):

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

#compare char in domain name with homograph char for IDN Checker
def checkHomoChar(domain_Name):

    value = []
    for c in domain_Name: #access each char in url
        for cha in data: #access each homogylyph char in idnchar.json
            if c in cha: #compare each char with json object
                value.append(c) #list contain matching char

    return value

#display for checkHomoChar()          
def getDataChar(value):

    list_Dict_Char = []
    #access each char in list of value
    for out in value:
        s = data[out]
        
        #insert the char info in list
        list_Dict_Char.append(s)
    
    return list_Dict_Char

# only accept .txt file
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in UPLOAD_EXTENSIONS

#read file 
def readFile(file):

    list_dm = []

    try:
        with open("Test Domain Name/" +file ,encoding = "utf-8") as f:
            for line in f:  
                # reading each word        
                for word in line.split():
                    list_dm.append(word)
                
        return list_dm

    except:
        return "File not found!!!" 

#compare char in domain name with homograph char for FIle IDN Checker
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

#convert punycode
def convertPuny(url):

    p = idna.encode(url)
    puny = p.decode("UTF-8")
    return puny

#get WHOIS
def getWhois(url):

    w = whois.whois(url)
    return w

# return index.html
@app.route('/', methods = ['GET','POST'] )
def index():

    if request.method == 'POST':       
        u = request.form['url']

        if not u:
            flash("There is no Input!!!")
            return redirect(request.url)
            
        else:
            # check domain name have .com
            if checkInput(u) == True:
                d = getExtractTLD(u)
                v = checkHomoChar(d)
                list_c = getDataChar(v)

                if not list_c:
                    flash("No Homoglyph Characters Detected !!!")
                    return redirect(request.url)

                else:    
                    flash("This Domain Name is Suspicous !!!")
                    return render_template("index.html", list_c = list_c, u = u)

            else:
                flash("Invalid URL !!!") 
                return redirect(request.url)
    else:
        return render_template("index.html")

# return file.html
@app.route('/file' , methods = ['GET','POST']  )
def goTo_File():
    return render_template("file.html")
        

# return display_file.html
@app.route('/result' , methods = ['GET','POST'] )
def goTo_Display_File_Result():

    if request.method == 'POST':
        file = request.files['myfile']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            f = readFile(filename)
            chf = checkHomoCharFile(f)

            if not chf:
                abort(400)

            else:
                print(chf)
                return render_template("display_file.html", chf = chf ,data = data)

        else:
            abort(400)
    else:
        return render_template("file.html")

# return puny.html
@app.route('/punycode', methods = ['GET','POST'] )
def Puny_func():

    if request.method == 'POST':
        pun = request.form['puny']
        
        if not pun:
            flash("No Input !!!") 
            return redirect(request.url)
        
        else:
            if checkInput(pun) == True:
                p = convertPuny(pun)  
                return render_template("puny.html" ,p=p)

            else:
                flash("Invalid URL !!!") 
                return redirect(request.url)

    else:        
        return render_template("puny.html")

#whois
@app.route('/whois',methods=['GET','POST'])
def goToWhois():

    if request.method == 'POST':
        w = request.form['who']

        if not w:
            flash("No Input !!!") 
            return redirect(request.url)

        else:
            if checkInput(w) == True:
                info_Who = getWhois(w) 
                return render_template("whois.html" ,info_Who = info_Who)

            else:
                flash("Invalid URL !!!") 
                return redirect(request.url)
    else:        
        return render_template("whois.html")

if __name__ =="__main__":
    app.run(debug = True)