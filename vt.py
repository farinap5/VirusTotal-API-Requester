import requests
import json
import sys

argl = []
def bann():
    print("""
   Virus Total API Requester
   -------------------------
  Use this program to analyze 
    hash from programs and 
       possible malware.    
    """)
def help():
    print("""
   Virus Total API Requester
   -------------------------
  Use this program to analyze 
    hash from programs and 
       possible malware.
       
  Commands:
  
  -api=   Your API key.
  -sig=   The program's signature. 
          Recommended to use MD5. 
  -help   Help menu.
  
  Usage Example:
  
  python3
  vt.py sig=566d0c5a08d1c32a8d049794a33af5dc -api=yOuRK3Yfr0mv1Ru5t0Tal
    """)

try:
    if "-help" in sys.argv:
        help()
        exit()

    arg1 = sys.argv[1]
    arg2 = sys.argv[2]
    try:
        argl.append(arg1)
        argl.append(arg2)

        for ar in argl:
            chk = ["-api","-sig"]
            ar1 = ar.split("=")
            if ar1[0] not in chk:
                print("Error")
                break
                exit()

            if ar1[0] == "-api":
                apikey = ar1[1]
            if ar1[0] == "-sig":
                signature = ar1[1]
    except:
        print("Error. Type -help.")
        exit()
except:
    print("Error. Type -help")
    exit()


def requ(signature,apikey):
    try:
        header = {"x-apikey":apikey}
        url = "https://www.virustotal.com/api/v3/files/" + signature
        get = requests.get(url, headers=header).json()
        #print(get.text)
        print('[+]-Request Done.')

    except:
        print("[*]-Error")

    bann()

    cont = get["data"]
    attri = cont["attributes"]

    print("-Androguard-")
    andro = attri["androguard"]
    print("FILE:",andro["AndroidApplicationInfo"])


    print("\n-Info-")
    print("First Submission Date:",attri["first_submission_date"])
    print("Last Modification Date:",attri["last_modification_date"])

    print("\n-Analysis Results-")
    las = attri["last_analysis_stats"]
    print("Confirmed Timeout:",las["confirmed-timeout"])
    print("Failure:          ",las["failure"])
    print("Harmless:         ",las["harmless"])
    print("malicious:        ",las["malicious"])
    print("Suspicious:       ",las["suspicious"])
    print("Timeout:          ",las["timeout"])
    print("Type Unsupported: ",las["type-unsupported"])
    print("Undetected:       ",las["undetected"])

    print("File:",attri["magic"],"\n")
    print("MD5:",attri["md5"])
    print("Meaningful Name:",attri["meaningful_name"])
    print("Reputation:",attri["reputation"])
    print("SHA-1:",attri["sha1"])
    print("SHA-256:",attri["sha256"])
    print("Size:",attri["size"])
    print("ssdeep:",attri["ssdeep"])
    print("Times Submitted:",attri["times_submitted"])
    print("TLSH:",attri["tlsh"])
    #print("ID:",attri["id"])
    for nn in attri["tags"]:
        print("Tag:",nn)
    for n in attri["names"]:
        print("Name:",n)
    lar = attri["last_analysis_results"]


    lis = ["APEX","AVG","Acronis","Ad-Aware","AegisLab","AhnLab-V3","Alibaba","Antiy-AVL","Arcabit","Avast","Avast-Mobile",
           "Avira","Baidu","BitDefender","BitDefenderTheta","Bkav","CAT-QuickHeal","CMC","ClamAV","Comodo","CrowdStrike",
           "Cybereason","Cylance","Cynet","Cyren","DrWeb","ESET-NOD32","Elastic","Emsisoft","F-Secure","FireEye",
           "Fortinet","GData","Gridinsoft","Ikarus","Invincea","Jiangmin","K7AntiVirus","K7GW","Kaspersky","Kingsoft",
           "MAX","Malwarebytes","MaxSecure","McAfee","McAfee-GW-Edition","MicroWorld-eScan","Microsoft","SUPERAntiSpyware",
           ]

    print("\n-Anti-Virus-")
    for av in lis:
        avs = lar[av]
        if avs["category"] == "undetected":
            pass
        elif avs["category"] == "type-unsupported":
            pass
        else:
            print(av)
            print("Category:",avs["category"])
            print("result:",avs["result"])
            print("\n")

try:
    requ(signature,apikey)
except:
    print("[*] Fatal Error! Something went wrong during the request.")
    print("Recommended Actions: Review the signature or your apikey.")



