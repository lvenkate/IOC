#! python2.7
# IndicatorsOfComprise IOC.py

import json, sys, re
import urllib
import urllib2

# Invalid if the program runs without argument
if len(sys.argv) < 2:
    print('Usage: No arguments')
    sys.exit()
arguments = sys.argv[1]
arg = arguments
list = sys.argv[1].split(",")
if len(list)> 4:
    print "More than allowed parameters : Please restrict the number between 1 to 4"
    sys.exit()
print("This is the list of input parameters")
i=0
for i in range(0,len(list)):
    print (list[i])
print ("##################################################")



# Function to retrieve the data using the APIs provided by VirusTotal
def callUrl(key, url, value):
    #API key to access the APIs offered by Virus
    virusTotalAPIkey = '230a0553d0df044d4bdb8f46fd6c2691abe9a6394646d641210fdc073525841d'

    if (key == 'ip' or key == 'domain'):
        parameters = {key: value, "apikey": virusTotalAPIkey}
        response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
        responseJSON = json.loads(response)
        return responseJSON

    if (key == 'url' or key == 'md5'):
        parameters = {"resource": value, "apikey": virusTotalAPIkey}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        responseJSON = response.read()
        jsonR = json.loads(responseJSON)
        return (jsonR)


# Identify a particular value in the data set of HoneyPot : This was written with the intention of extending the program but I have not used this function as of now
def find_values(id, obj):
    results = []

    def _find_values(id, obj):
        try:
            for key, value in obj.iteritems():
                if key == id:
                    results.append(value)
                elif not isinstance(value, basestring):
                    _find_values(id, value)
        except AttributeError:
            pass

        try:
            for item in obj:
                if not isinstance(item, basestring):
                    _find_values(id, item)
        except TypeError:
            pass

    if not isinstance(obj, basestring):
        _find_values(id, obj)
    return results

# Regular expression to identify the type of input parameter
MD5 = r"([A-F]|[0-9]){32}"
IPv4 = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|\[\.\])){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
uURL = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
Domain = r"[A-Z0-9\-\.\[\]]+(\.|\[\.\])(XN--CLCHC0EA0B2G2A9GCD|XN--HGBK6AJ7F53BBA|XN--HLCJ6AYA9ESC7A|XN--11B5BS3A9AJ6G|XN--MGBERP4A5D4AR|XN--XKC2DL3A5EE0H|XN--80AKHBYKNJ4F|XN--XKC2AL3HYE2A|XN--LGBBAT1AD8J|XN--MGBC0A9AZCG|XN--9T4B11YI5A|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBBH1A71E|XN--FPCRJ9C3D|XN--FZC2C9E2C|XN--YFRO4I67O|XN--YGBI2AMMX|XN--3E0B707E|XN--JXALPDLP|XN--KGBECHTV|XN--OGBPF8FL|XN--0ZWM56D|XN--45BRJ9C|XN--80AO21A|XN--DEBA0AD|XN--G6W251D|XN--GECRJ9C|XN--H2BRJ9C|XN--J6W193G|XN--KPRW13D|XN--KPRY57D|XN--PGBS0DH|XN--S9BRJ9C|XN--90A3AC|XN--FIQS8S|XN--FIQZ9S|XN--O3CW4H|XN--WGBH1C|XN--WGBL6A|XN--ZCKZAH|XN--P1AI|MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|PRO|TEL|XXX|AC|AD|AE|AF|AG|AI|AL|AM|AN|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BM|BN|BO|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)\b"


for i in range(0, len(list)):
    # Identifying the type of the parameter
    for m in re.finditer(Domain, list[i], re.IGNORECASE):
        key = 'domain'

    for m in re.finditer(IPv4, list[i], re.IGNORECASE):
        key = 'ip'

    for m in re.finditer(MD5, list[i], re.IGNORECASE):
        key = 'md5'

    for m in re.finditer(uURL, list[i], re.IGNORECASE):
        key = 'url'

    # This scan gives the details of the malware wrt to Domain
    if (key == 'domain'):

        urlDomain = 'https://www.virustotal.com/vtapi/v2/domain/report'
        response = callUrl(key, urlDomain, list[i])
        count = 0
        j = 0
        for j in range(1, len(response['detected_urls'])):
            if count < 10:
                print ("Victim IP:" + list[i])
                print ("Malware IP Address:" + response['detected_urls'][j]['url'])
                print ("Source : Virus Total")
                print ("TimeStamp :" + response['detected_urls'][j]['scan_date'])
                print ("--------------------------------------------------")
                count = count + 1

    # This scan indicates IP address IoC details from HoneyPot and Virus Total Sources
    if (key == 'ip'):

        ipAddress = list[i]
        urlIp = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        response = callUrl(key, urlIp, list[i])
        data = []
        # Opening the Honeypot file and read it into a List object
        with open(".\config\honeypot.json") as f:
            for line in f:
                data.append(json.loads(line))

        fileLength = len(data)
        output = []
        o = []
        j = 0
        count = 0
        for i in range(0, fileLength):
            if (ipAddress in data[i]['payload']):
                if (count < 3):
                    output = (data[i]['payload'])
                    o.append(json.loads(output))
                    print ("Victim IP:" + o[j]['victimIP'])
                    print ("Attacker IP:" + o[j]['attackerIP'])
                    print ("Connection Type:" + o[j]['connectionType'].title())
                    print ("Attacker Port:" + str(o[j]['attackerPort']))
                    print ("Source :HoneyPot")
                    print ("TimeStamp :" + data[i]['timestamp']['$date'].replace('T', ' ').replace('+0000', ' '))
                    j = j + 1
                    count = count + 1
                    print ("--------------------------------------------------")

        statusHoney = '1'
        statusVirus = '1'
        if output is None:
            statusHoney = '0'

        if response['verbose_msg'] == "Missing IP address":
            statusVirus = '0'
        else:
            j = 0
            count = 0
            for j in range(1, len(response['detected_urls'])):
                if count < 3:
                    print ("Victim IP:" + ipAddress)
                    print ("Malware IP Address:" + response['detected_urls'][j]['url'])
                    print ("Source : Virus Total")
                    print ("TimeStamp :" + response['detected_urls'][j]['scan_date'])
                    print ("--------------------------------------------------")
                    count = count + 1
        if statusVirus == '0' and statusHoney == '0':
            print "IP Address" + ipAddress + " not found in any source"

    # This scan indicates MD5 associated malware details from Virustotal
    if (key == 'md5'):

        urlMd5 = "https://www.virustotal.com/vtapi/v2/file/report"
        response = callUrl(key, urlMd5, list[i])
        count = 0
        j = 0
        sites = response['scans'].keys()
        for j in range(0, len(response['scans'].keys())):
            if count < 5:
                print (" MD5 Resource :" + list[i])
                print (" Scan Id :" + response['scan_id'])
                site = sites[j]
                print (" Scanned Database @ " + sites[j] + ' detected : ' + str(response['scans'][site]['detected']))
                print (" Source : Virus Total")
                print (" Scanned Date  :" + str(response['scan_date']))
                print (" Result declared: " + str(response['scans'][site]['result']).title())
                print ("--------------------------------------------------")
                count = count + 1

    # This scan indicates whether the given site with the URL is clean or affected site details from Virustotal
    if (key == 'url'):
        urlUrl = "https://www.virustotal.com/vtapi/v2/url/report"
        response = callUrl(key, urlUrl, list[i])
        count = 0
        j = 0
        sites = response['scans'].keys()
        for j in range(0, len(response['scans'].keys())):
                if count < 5:
                    site = sites[j]
                    print (" Web Address:" + list[i])
                    print (" Scanned Database @ :" + sites[j] + ' ' + str(response['scans'][site]['detected']))
                    print (" Source : Virus Total")
                    print (" Scanned Date  :" + str(response['scan_date']))
                    print (" Result : Declared " + str(response['scans'][site]['result']).title())
                    count = count +1
                    print ("--------------------------------------------------")