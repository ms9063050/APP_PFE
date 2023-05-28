import os, math, magic, pefile,re
import datetime
now = datetime.datetime.now()

def get_all_files():
    all_files = []
    #os.chdir('../../uploads')
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def load_and_read_exe_strings(filename):
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if ".exe" in i or ".dll" in i or "sys" in i:
            if filename in i:
                file_exe = i
                break
            else:
                print("error")
        if not ".txt" in i:
            if not ".json" in i :
                file_exe = i
                break
    string_file = file_exe.split("/")
    string_file = "strings_" + string_file[-1].split(".")[0] + ".txt"
    for i in get_files :
        if string_file in i:
            file_str = i
            break
    return file_exe, file_str

# Get some strings to analyisi by strings
#~ Encryption algorithmes ~ Narimene maybe can be changed

def algo_crypt(STRING_FILE,file_path_exe):
    #print("Strings Analysis ~ ")
    with open(STRING_FILE, "r") as f:
        strings = f.read().lower()
    total_chars = len(strings)
    #print(total_chars)
    
    libs_keywords = ["PyCrypto","cryptography","M2Crypto","PyNaCl","PyOpenSSL","Fernet","Simple\-crypt","PyCryptodome","Charm\-crypto","Keyczar","Pycrypto Plus","Bcrypt","SecureString","Cryptacular","Pyca","SecretStorage","Vault","OpenSSL","Libgcrypt","GnuTLS","Crypto\+\+","Botan","Libsodium","BouncyCastle","\.NETCryptography","CngKey"]
    encryption_keywords = ["encrypt", "key", "AES", "RSA", "blowfish","asymmetric","symmetric","ciphers","hashes","hash","key","public\-key","private\-key"]
    rate = 0

    # coefficient : 1 ~ encryptions
    encryption_regex = "(" + "|".join(encryption_keywords) + ")"
    encryption_matches = re.findall(encryption_regex, strings, re.IGNORECASE)
    if len(encryption_matches) > 0:
        rate += 1 

    # coefficient : 1 ~ libs
    encryption_ = "(" + "|".join(libs_keywords) + ")"
    encryption_m = re.findall(encryption_, strings, re.IGNORECASE)
    if len(encryption_m) > 0:
        rate += 1
    
    # coefficient : 2 ~ algorithms
    encryption_algorithms = ["AES-256", "RSA-2048", "blowfish","RC4","ChaCha20","Twofish","Triple DES","Serpent","Camellia"]
    for match in encryption_matches:
        for algorithm in encryption_algorithms:
            if algorithm.lower() in match.lower():
                rate += 2 
    
    # Calculate the probs "~" : sum of rates / (div) total of strings
    #print("rate : "+ str(rate))
    #print("probs : "+ str((rate / total_chars)*100))

    if rate < 10 : 
        return True
    else:
        return False        

# L'entropie

def entropy(file_path):
    with open(file_path, 'rb') as f:
        byte_freq = [0]*256
        byte_count = 0
        while True:
            byte = f.read(1)
            if not byte:
                break
            byte_count += 1
            byte_freq[ord(byte)] += 1
        entropy = 0
        for freq in byte_freq:
            if freq != 0:
                prob = freq / byte_count
                entropy += - prob * math.log2(prob)
        return entropy

def entropie_test(file_path):
    if entropy(file_path) < 6 :
        return False
    else:
        return True

# Anti-debugger  ~ Narimene
def fonction_antiDebugg(filepath):
    try :
        pe = pefile.PE(filepath)
        liste = ["CheckRemoteDebuggerPresent",
                "CheckRemoteDebuggerPresentEx",
                "CreateToolhelp32Snapshot",
                "DebugActiveProcess",
                "DebugActiveProcessStop",
                "DebugBreak",
                "DebugBreakProcess",
                "ContinueDebugEvent",
                "IsDebuggerPresent",
                "OutputDebugString",
                "Ptrace",
                "SetInformationThread",
                "SuspendThread",
                "WaitForDebugEvent",
                "Wow64SetThreadContext",
                "ZwSetInformationThread",
                "NtYieldExecution",
                "RtlAddVectoredExceptionHandler",
                "RtlAddVectoredContinueHandler",
                "RtlCaptureContext",
                "RtlDeleteFunctionTable",
                "RtlDeleteGrowableFunctionTable",
                "RtlInstallFunctionTableCallback",
                "RtlRemoveVectoredExceptionHandler",
                "RtlRestoreContext",
                "RtlUnwindEx",
                "RtlVirtualUnwind",
                "SymSetOptions",
                "SymInitialize",
                "SymCleanup",
                "SymGetOptions",
                "SymGetSearchPath",
                "SymGetModuleInfo",
                "SymGetModuleInfoEx",
                "SymGetModuleBase",
                "SymGetLineFromAddr",
                "SymGetLineFromAddr64",
                "SymGetLineFromName",
                "SymGetLineFromName64",
                "SymEnumSymbols",
                "SymEnumSymbolsForAddr",
                "SymFromAddr",
                "SymFromName",
                "SymFromToken",
                "SymLoadModuleEx",
                "SymUnloadModule",
                "SymUnDName",
                "SymSetParentWindow",
                "SymGetTypeInfo",
                "SymEnumTypes",
                "SymEnumTypesByName",
                "SymEnumTypesByIndex",
                "SymEnumSymbolsW",
                "SymEnumSymbolsEx",
                "SymEnumSourceFiles",
                "SymEnumProcesses",
                "SymGetSymbolFile",
                "SymGetSymbolFileW",
                "SymGetFileLineOffsets64",
                "SymGetLineNext",
                "SymGetLinePrev",
                "SymMatchString",
                "SymSearch",
                "SymLoadModule64",
                "SymGetSymFromAddr64",
                "SymGetSymFromName64",
                "SymGetLineFromAddrEx",
                "SymGetLineFromNameEx",
                "SymGetModuleInfoW",
                "SymGetSymbolInfo",
                "SymGetSymbolInfoW",
                "SymGetSymbol",
                "SymGetSymbolW",
                "SymGetTypeFromName",
                "SymGetTypeFromNameW",
                "SymEnumSourceFilesW",
                "SymEnumProcessesW",
                "SymSetSearchPath",
                "SymSetSearchPathW",
                "SymGetSearchPathW",
                "SymGetOptionsW",
                "SymGetLineFromAddr64W",
                "SymGetLineFromName64W",
                "SymGetModuleInfoExW",
                "SymFromAddrW",
                "SymFromNameW",
                "SymEnumSymbolsW64",
                "SymEnumSymbolsForAddrW",
                "SymEnumSourceFilesW64",
                "SymEnumTypesW",
                "SymEnumTypesW64",
                "SymLoadModuleExW",
                "SymLoadModuleW",
                "SymSetOptionsW",
                "SymSetParentWindowW",
                "SymSetContext",
                "SymSetContextW",
                "SymGetContext",
                "SymGetContextW",
                "SymSetScopeFromAddr",
                "SymSetScopeFromAddr"
            ]

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.lower() == "kernel32.dll":
                for imp in entry.imports:
                    for x in liste :
                        if imp.name is not None and imp.name.lower() == x.lower() :
                            return False
            else:
                return True
    except pefile.PEFormatError:
        return False
# Anti-vm  ~ Narimene
def fonction_vms(filepath):
    try :
        pe = pefile.PE(filepath)
        anti_vm_strings = ["VMWARE", "VIRTUALBOX", "VBOX", "QEMU", "XEN", "HYPER-V", "KVM", "EC2", "Proxmox VE", "XenServer", "AHV", "RHEV", "Bochs"]

        for string in anti_vm_strings:
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                for inp in dll.imports :
                    out = str(inp.name)
                    if string.lower() in out.lower():
                        return False
        return True
    except pefile.PEFormatError:
        return True

def Obsufuctions_Analysis(filename):
    os.chdir("/var/www/basic-flask-app/static/uploads")
    get_exe_ , get_strings_ = load_and_read_exe_strings(filename)
    print("["+str(now)+"]~ The Obsufuction of the file has been done successful!")
    return entropie_test(get_exe_),algo_crypt(get_strings_,get_exe_),fonction_antiDebugg(get_exe_),fonction_vms(get_exe_)
