import os
import binascii
import json
import datetime
import pefile
import hashlib
import string

now = datetime.datetime.now()

def get_all_files():
    all_files = []
    os.chdir('.\\uploads')
    current_dir = os.getcwd()
    print(current_dir)
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
    print("["+str(now)+"]~ The Strings file has been created!")

def extract_Strings_from_file (file_path):
    file_name = "strings_"+file_path.split("\\")[-1].split(".")[0]+".txt"
    file = open(file_name,"w",encoding="utf-8")
    for s in strings(file_path):
        file.write(s)
        file.write("\n")
    file.close()


def md5sum(file_path, blocksize=65536):
    hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()

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
            print (e)
    pe_information = {"DATA_DIRECTORY" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size,
        "VirtualAddress" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress,
        "MajorImageVersion" : pe.OPTIONAL_HEADER.MajorImageVersion,
        "OSVersion" : pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        "ExportRVA" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress,
        "ExportSize" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size,
        "IATRVA" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress,
        "ResSize" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size,
        "LinkerVersion" : pe.OPTIONAL_HEADER.MajorLinkerVersion,
        "VirtualSize2" : pe.sections[1].Misc_VirtualSize,
        "NumberOfSections" : pe.FILE_HEADER.NumberOfSections,
        "StackReserveSize" : pe.OPTIONAL_HEADER.SizeOfStackReserve,
        "Dll" : pe.OPTIONAL_HEADER.SizeOfStackReserve,
        "ImportFunctionCount" : countf,
        "ImportFunctionMethodCount" : countm,
        "ExportFunctions" : function_exp,
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
    file_name = "hexdump_"+file_path.split("\\")[-1].split(".")[0]+".txt"
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
    if ext in ['.exe', '.dll', '.sys']:
        with open(file_path, 'rb') as f:
            header = f.read(2)
            if header == b'MZ':
                return True
    return False

def Extract_informations():
    files_paths = get_all_files()
    print(files_paths)
    dataset = {}
    for file_path in files_paths:
        if is_executable(file_path) :
            try:
                dataset.update({file_path : extract_pe_info(file_path)})
            except Exception as e:
                print (e)
        else :
            dataset.update({file_path : md5sum(file_path)})
        hexdump(file_path)
        extract_Strings_from_file(file_path)
        
        if len(dataset) != 0:
            create_Json_File(dataset)
            
