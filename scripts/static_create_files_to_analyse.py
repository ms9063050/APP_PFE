import os
import binascii
import json
import datetime
import pefile
import hashlib
import string
import re

now = datetime.datetime.now()

def get_all_files():
    all_files = []
    os.chdir('/home/narimene/APP_PFE/static/uploads')
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def strings(filename, min=4):
    with open(filename, errors="ignore") as f:  # Python 3.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result

def extract_Strings_from_file (file_path):
    file_name = "strings_"+file_path.split("/")[-1].split(".")[0]+".txt"
    file = open(file_name,"w",encoding="utf-8")
    for s in strings(file_path):
        file.write(s)
        file.write("\n")
    file.close()
    print("["+str(now)+"]~ The Strings file has been created!")


def md5sum(file_path, blocksize=65536):
    hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()

def hash_file_if_is_not_a_file_system(file_path):
    
    hash_file = md5sum(file_path)
    return {"md5Hash" : hash_file}

def find_bitcoin (pe):
    
    # Find the section that contains the Bitcoin address
    section = pe.sections[-1] # assume the address is in the last section
    data = section.get_data()

    # Use regular expressions to find the Bitcoin address in the data
    pattern = re.compile(b'[13][a-km-zA-HJ-NP-Z0-9]{26,33}')
    match = pattern.search(data)

    if match:
        # Convert the Bitcoin address to a binary format
        address = match.group()
        binary_address = binascii.unhexlify(hashlib.new('ripemd160', 
            hashlib.sha256(binascii.unhexlify('00' + address)).digest()).hexdigest())

        return 1
    else:
        return 0

def get_debug_rva(pe):
    # Get the debug directory
    debug_dir_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].VirtualAddress
    debug_dir_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].Size

    # Check if the debug directory is valid
    if debug_dir_rva == 0 or debug_dir_size == 0:
        return 0
        print("No debug directory found.")
    else:
        # Get the debug directory entry
        debug_entry = pe.get_section_by_rva(debug_dir_rva)

        # Get the DebugRVA from the debug directory entry
        debug_rva = debug_entry.VirtualAddress

        #print("DebugRVA:", hex(debug_rva))
        return debug_rva

def get_IatVRA(pe):
    # Get the IAT directory
    iat_dir_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
    iat_dir_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size

    # Check if the IAT directory is valid
    if iat_dir_rva == 0 or iat_dir_size == 0:
        #print("No IAT directory found.")
        return 0
    else:
        # Get the IAT section
        iat_section = pe.get_section_by_rva(iat_dir_rva)

        # Get the IAT RVA from the section header
        iat_rva = iat_section.VirtualAddress

        #print("IAT RVA:", hex(iat_rva))
        return iat_rva

def extract_pe_info(file_path):
    with open(file_path, "rb") as file_content:
        pe= pefile.PE(data=file_content.read(), fast_load=True)
    pe.parse_data_directories()
    countf = 0
    countm = 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        countf += 1
        for imp in entry.imports:
            countm += 1
    function_exp = []
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            function_exp.append(exp.name)
    except Exception as e:
        pass
    pe_information = {
        "Machine" : pe.FILE_HEADER.Machine,
        "DebugSize" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size,
        "DebugRVA" : get_debug_rva(pe),
        #"VirtualAddress" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress,
        "MajorImageVersion" : pe.OPTIONAL_HEADER.MajorImageVersion,
        "MajorOSVersion" : pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        #"OSVersion" : pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        "ExportRVA" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress,
        "ExportSize" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size,
        "IatVRA": get_IatVRA(pe),
        #"IATRVA" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress,
        #"ResSize" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size,
        "MajorLinkerVersion" : pe.OPTIONAL_HEADER.MajorLinkerVersion,
        "MinorLinkerVersion" : pe.OPTIONAL_HEADER.MinorLinkerVersion,
        #"VirtualSize2" : pe.sections[1].Misc_VirtualSize,
        "NumberOfSections" : pe.FILE_HEADER.NumberOfSections,
        "StackReserveSize" : pe.OPTIONAL_HEADER.SizeOfStackReserve,
        "DllCharacteristics" : pe.OPTIONAL_HEADER.DllCharacteristics,
        "ResourceSize" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size,
        #"ImportFunctionCount" : countf,
        #"ImportFunctionMethodCount" : countm,
        #"ExportFunctions" : function_exp,
        "BitcoinAddresses" : find_bitcoin(pe),
        "md5Hash" : md5sum(file_path)}
    file_content.close()
    return(pe_information)

def create_Json_File (dict):
    dict_to_json = json.dumps(dict,indent=4)
    # Get the current local date and time
    now = datetime.datetime.now()
    # Extract the local date (year, month, day)
    local_date = now.date()
    file_path = "data_file"+"_"+str(local_date)+".json"
    with open(file_path,"w") as f:
        f.write(dict_to_json)
    print("["+str(now)+"]~ The JSON file has been created!")

def hexdump(file_path):
    file_name = "hexdump_"+file_path.split("/")[-1].split(".")[0]+".txt"
    file = open(file_name,"w")
    with open(file_path, 'rb') as f:
        data = f.read()
        hex_str = binascii.hexlify(data).decode('utf-8')
        for i in range(0, len(hex_str), 16):
            line = hex_str[i:i+16]
            liine = [line[j:j+2] + " " for j in range(0, len(line), 2)]
            for i in liine:
                file.write(i)
            file.write("   ")
            liiine = [chr(int(line[j:j+2], 16)) if 32 <= int(line[j:j+2], 16) <= 126 else "." for j in range(0, len(line), 2)]
            for i in liiine:
                file.write(i)
            file.write("\n")
    file.close()
    print("["+str(now)+"]~ The Hexdump file has been created!")

def is_executable(file_path):
    _, ext = os.path.splitext(file_path)
    if ext in ['.exe', '.dll', '.sys','.ocx','.pdb','.map','.res','.tlb','.manifest']:
        with open(file_path, 'rb') as f:
            header = f.read(2)
            if header == b'MZ':
                return True
    return False
def get_file_size(file_path):
    if os.path.isfile(file_path):
        return os.path.getsize(file_path) // 1024
    else:
        raise ValueError("File path is not valid.")
def Extract_informations(filename):
    files_paths = get_all_files()
    dataset = {}
    for file_path in files_paths:
        if is_executable(file_path) :
            if filename in file_path:
                try:
                    dataset.update({file_path : extract_pe_info(file_path)})
                except Exception as e:
                    pass
            else:
                print("error")
        else :
            dataset.update({file_path : hash_file_if_is_not_a_file_system(file_path)})
        hexdump(file_path)
        extract_Strings_from_file(file_path)
        if len(dataset) != 0:
            create_Json_File(dataset)
        hash_file = md5sum(file_path)
        file_size = get_file_size(file_path)
        extension = (file_path).split("/")[-1].split(".")[-1]
        return file_size, hash_file, extension
#Copyright 02-25-2023 ~ Boussoura Mohamed Cherif & Houanti Narimene