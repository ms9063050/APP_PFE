import pefile, json, binascii, re

def read_file(filename):
    lines = []
    with open(filename, 'r', encoding='utf-8') as file:
        for line in file:
            lines.append(line.strip())
    return lines

def get_apis_results(file_path):
    with open("/home/narimene/APP_PFE/static/static data/apis.txt", 'r') as f:
        list_of_apis_functions = [line.strip() for line in f]
    
    pe = pefile.PE(file_path)
    results = []
    
    for i in list_of_apis_functions:
        found = False
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                imported_function = imp.name.decode() if imp.name else ""
                if i == imported_function:
                    found = True
                    break
            if found:
                break
        
        if found:
            results.append(1)
        else:
            results.append(0)
    
    #print(len(results))
    return results

def get_drop_extensions_files(file_path):
    extensions = read_file("/home/narimene/APP_PFE/static/static data/dropped_ext.txt")
    # Read the file json
    with open(file_path) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # begin the infomation gathering
    results = []
    try:
        for i in extensions:
            flag = 0
            for j in dictionary["data"]["files_deleted"]:
                if i in j:
                    results.append(1)
                    flag = 1
                    break
            if flag == 0:
                results.append(0)
    except KeyError:
        for i in range(346):
            results.append(0)

    #print(len(results))
    return results

def get_reg_key (file_path):
    # Read the file json
    with open(file_path) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # Deleted Registry Key
    deleted_reg_key = read_file("/home/narimene/APP_PFE/static/static data/reg_key_delete.txt")
    deleted_reg_results = []

    # Opened Registry Key
    opened_reg_key = read_file("/home/narimene/APP_PFE/static/static data/reg_key_open.txt")
    opened_reg_results = []

    # Read Registry Key
    read_reg_key = read_file("/home/narimene/APP_PFE/static/static data/reg_key_read.txt")
    read_reg_results = []

    # Write Registry Key
    write_reg_key = read_file("/home/narimene/APP_PFE/static/static data/reg_key_written.txt")
    write_reg_results = []

    # Opened - Read - written
    try:
        for i in opened_reg_key:
            flag = 0
            for j in dictionary["data"]["registry_keys_opened"] :
                if i in j :
                    opened_reg_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                opened_reg_results.append(0)
            else:
                pass
        for i in read_reg_key:
            flag = 0
            for j in dictionary["data"]["registry_keys_opened"] :
                if i in j :
                    read_reg_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                read_reg_results.append(0)
            else:
                pass
        for i in write_reg_key:
            flag = 0
            for j in dictionary["data"]["registry_keys_opened"] :
                if i in j :
                    write_reg_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                write_reg_results.append(0)
    except KeyError:
        pass

    # Deleted - Read - written
    try:
        for i in deleted_reg_key:
            flag = 0
            for j in dictionary["data"]["registry_keys_deleted"]:
                if i in j:
                    deleted_reg_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                deleted_reg_results.append(0)
        if len(read_reg_results) == 0:
            for i in read_reg_key:
                flag = 0
                for j in dictionary["data"]["registry_keys_deleted"]:
                    if i in j:
                        read_reg_results.append(1)
                        flag = 1
                        break
                if flag == 0:
                    read_reg_results.append(0)
        if len(write_reg_results) == 0:
            for i in write_reg_key:
                flag = 0
                for j in dictionary["data"]["registry_keys_deleted"]:
                    if i in j:
                        write_reg_results.append(1)
                        flag = 1
                        break
                if flag == 0:
                    write_reg_results.append(0)
    except KeyError:
        pass
    # PUT THEM IN ONE VAR AND RETURN THE RESULTS
    all_in_one = []
    if len(deleted_reg_results) == 0 :
        for i in range(143):
            all_in_one.append(0)
    else:
        for i in deleted_reg_results:
            all_in_one.append(i)

    if len(opened_reg_results) == 0 :
        for i in range(2659):
            all_in_one.append(0)
    else:
        for i in opened_reg_results:
            all_in_one.append(i)

    if len(read_reg_results) == 0 :
        for i in range(2340):
            all_in_one.append(0)
    else:
        for i in read_reg_results:
            all_in_one.append(i)

    if len(write_reg_results) == 0 :
        for i in range(1480):
            all_in_one.append(0)
    else:
        for i in write_reg_results:
            all_in_one.append(i)
    
    return all_in_one

def get_file_and_dir_key (file_path):
    # Read the file json
    with open(file_path) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # Files // Files extensions : deleted - opened - read - write ~
    
    # Deleted Files
    deleted_files = read_file("/home/narimene/APP_PFE/static/static data/files_deleted.txt")
    files_ext_deleted = read_file("/home/narimene/APP_PFE/static/static data/files_exet_delete.txt")
    deleted_files_results = []
    files_ext_deleted_results = []

    # Opened Files
    opened_files = read_file("/home/narimene/APP_PFE/static/static data/files_opened.txt")
    files_ext_opened = read_file("/home/narimene/APP_PFE/static/static data/files_exet_open.txt")
    opened_files_results = []
    files_ext_opened_results = []

    # Read Files
    read_files = read_file("/home/narimene/APP_PFE/static/static data/files_read.txt")
    files_ext_read = read_file("/home/narimene/APP_PFE/static/static data/files_exet_read.txt")
    read_files_results = []
    files_ext_read_results = []

    # Write Files
    write_files_key = read_file("/home/narimene/APP_PFE/static/static data/files_write.txt")
    files_ext_write = read_file("/home/narimene/APP_PFE/static/static data/files_exet_write.txt")
    write_files_results = []
    files_ext_write_results = []

    # Folders // pathways
    created_folder = read_file("/home/narimene/APP_PFE/static/static data/dir_created.txt")
    enum_folder = read_file("/home/narimene/APP_PFE/static/static data/dir_enum.txt")
    created_folder_results_1 = []
    created_folder_results_2 = []
    created_folder_results_3 = []
    enum_folder_results_1 = []
    enum_folder_results_2 = []
    enum_folder_results_3 = []

    # Opened - Read
    try:
        for i in opened_files:
            flag = 0
            for j in dictionary["data"]["files_opened"] :
                if i in j :
                    opened_files_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                opened_files_results.append(0)
            else:
                pass
        for i in read_files:
            flag = 0
            for j in dictionary["data"]["files_opened"] :
                if i in j :
                    read_files_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                read_files_results.append(0)
            else:
                pass
        for i in files_ext_opened:
            flag = 0
            for j in dictionary["data"]["files_opened"]:
                if i in j:
                    files_ext_opened_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                files_ext_opened_results.append(0)
        for i in files_ext_read:
            flag = 0
            for j in dictionary["data"]["files_opened"]:
                if i in j:
                    files_ext_read_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                files_ext_read_results.append(0)
        for i in created_folder:
            flag = 0
            for j in dictionary["data"]["files_opened"]:
                if i in j:
                    created_folder_results_1.append(1)
                    flag = 1
                    break
            if flag == 0:
                created_folder_results_1.append(0)
        for i in enum_folder:
            flag = 0
            for j in dictionary["data"]["files_opened"]:
                if i in j:
                    enum_folder_results_1.append(1)
                    flag = 1
                    break
            if flag == 0:
                enum_folder_results_1.append(0)
    except KeyError:
        pass

    # Deleted 
    try:
        for i in deleted_files:
            flag = 0
            for j in dictionary["data"]["files_deleted"]:
                if i in j:
                    deleted_files_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                deleted_files_results.append(0)
        for i in files_ext_deleted:
            flag = 0
            for j in dictionary["data"]["files_deleted"]:
                if i in j:
                    files_ext_deleted_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                files_ext_deleted_results.append(0)
        for i in created_folder:
            flag = 0
            for j in dictionary["data"]["files_opened"]:
                if i in j:
                    created_folder_results_2.append(1)
                    flag = 1
                    break
            if flag == 0:
                created_folder_results_2.append(0)
        for i in enum_folder:
            flag = 0
            for j in dictionary["data"]["files_opened"]:
                if i in j:
                    enum_folder_results_2.append(1)
                    flag = 1
                    break
            if flag == 0:
                enum_folder_results_2.append(0)
    except KeyError:
        pass

    # Written
    try:
        for i in write_files_key:
            flag = 0
            for j in dictionary["data"]["files_written"]:
                if i in j:
                    write_files_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                write_files_results.append(0)
        for i in files_ext_write:
            flag = 0
            for j in dictionary["data"]["files_written"]:
                if i in j:
                    files_ext_write_results.append(1)
                    flag = 1
                    break
            if flag == 0:
                files_ext_write_results.append(0)
        for i in created_folder:
            flag = 0
            for j in dictionary["data"]["files_opened"]:
                if i in j:
                    created_folder_results_3.append(1)
                    flag = 1
                    break
            if flag == 0:
                created_folder_results_3.append(0)
        for i in enum_folder:
            flag = 0
            for j in dictionary["data"]["files_opened"]:
                if i in j:
                    enum_folder_results_3.append(1)
                    flag = 1
                    break
            if flag == 0:
                enum_folder_results_3.append(0)
    except KeyError:
        pass

    # PUT THEM IN ONE VAR AND RETURN THE RESULTS
    all_in_one = []
    if len(deleted_files_results) == 0 :
        for i in range(116):
            all_in_one.append(0)
    else:
        for i in deleted_files_results:
            all_in_one.append(i)

    if len(opened_files_results) == 0 :
        for i in range(1904):
            all_in_one.append(0)
    else:
        for i in opened_files_results:
            all_in_one.append(i)

    if len(read_files_results) == 0 :
        for i in range(449):
            all_in_one.append(0)
    else:
        for i in read_files_results:
            all_in_one.append(i)

    if len(write_files_results) == 0 :
        for i in range(1672):
            all_in_one.append(0)
    else:
        for i in write_files_results:
            all_in_one.append(i)
    
    # FILES EXTENSIONS
    if len(files_ext_deleted_results) == 0 :
        for i in range(56):
            all_in_one.append(0)
    else:
        for i in files_ext_deleted_results:
            all_in_one.append(i)

    if len(files_ext_opened_results) == 0 :
        for i in range(437):
            all_in_one.append(0)
    else:
        for i in files_ext_opened_results:
            all_in_one.append(i)

    if len(files_ext_read_results) == 0 :
        for i in range(117):
            all_in_one.append(0)
    else:
        for i in files_ext_read_results:
            all_in_one.append(i)

    if len(files_ext_write_results) == 0 :
        for i in range(325):
            all_in_one.append(0)
    else:
        for i in files_ext_write_results:
            all_in_one.append(i)
    
    # Directory and folders (create and enumuration)
    if len(created_folder_results_1) == 0:
        if len(created_folder_results_2) == 0:
            if len(created_folder_results_3) == 0:
                for i in range(718):
                    all_in_one.append(0)
            else :
                for i in created_folder_results_3:
                    all_in_one.append(i)
        else:
            if len(created_folder_results_3) == 0:
                for i in created_folder_results_2:
                    all_in_one.append(i)
            else :
                for i in range(len(created_folder_results_3)):
                    if (created_folder_results_3[i] == 1 and created_folder_results_2[i] == 0) or (created_folder_results_2[i] == 1 and created_folder_results_3[i] == 0) or (created_folder_results_2[i] == 1 and created_folder_results_3[i] == 1):
                        all_in_one.append(1)
                    else:
                        all_in_one.append(0)
    else:
        if len(created_folder_results_2) == 0:
            if len(created_folder_results_3) == 0:
                for i in created_folder_results_1:
                    all_in_one.append(i)
            else :
                for i in range(len(created_folder_results_3)):
                    if (created_folder_results_3[i] == 1 and created_folder_results_1[i] == 0) or (created_folder_results_1[i] == 1 and created_folder_results_3[i] == 0) or (created_folder_results_1[i] == 1 and created_folder_results_3[i] == 1):
                        all_in_one.append(1)
                    else:
                        all_in_one.append(0)
        else:
            if len(created_folder_results_3) == 0:
                for i in range(len(created_folder_results_2)):
                    if (created_folder_results_2[i] == 1 and created_folder_results_1[i] == 0) or (created_folder_results_1[i] == 1 and created_folder_results_2[i] == 0) or (created_folder_results_1[i] == 1 and created_folder_results_2[i] == 1):
                        all_in_one.append(1)
                    else:
                        all_in_one.append(0)
            else :
                for i in range(len(created_folder_results_3)):
                    if created_folder_results_1[i] == 0:
                        if created_folder_results_2[i] == 0:
                            if created_folder_results_3[i] == 0:
                                all_in_one.append(0)
                            else:
                                all_in_one.append(1)
                        else:
                            all_in_one.append(1)
                    else:
                        all_in_one.append(1)
    if len(enum_folder_results_1) == 0:
        if len(enum_folder_results_2) == 0:
            if len(enum_folder_results_3) == 0:
                for i in range(718):
                    all_in_one.append(0)
            else :
                for i in enum_folder_results_3:
                    all_in_one.append(i)
        else:
            if len(enum_folder_results_3) == 0:
                for i in enum_folder_results_2:
                    all_in_one.append(i)
            else :
                for i in range(len(enum_folder_results_3)):
                    if (enum_folder_results_3[i] == 1 and enum_folder_results_2[i] == 0) or (enum_folder_results_2[i] == 1 and enum_folder_results_3[i] == 0) or (enum_folder_results_2[i] == 1 and enum_folder_results_3[i] == 1):
                        all_in_one.append(1)
                    else:
                        all_in_one.append(0)
    else:
        if len(enum_folder_results_2) == 0:
            if len(enum_folder_results_3) == 0:
                for i in enum_folder_results_1:
                    all_in_one.append(i)
            else :
                for i in range(len(enum_folder_results_3)):
                    if (enum_folder_results_3[i] == 1 and enum_folder_results_1[i] == 0) or (enum_folder_results_1[i] == 1 and enum_folder_results_3[i] == 0) or (enum_folder_results_1[i] == 1 and enum_folder_results_3[i] == 1):
                        all_in_one.append(1)
                    else:
                        all_in_one.append(0)
        else:
            if len(enum_folder_results_3) == 0:
                for i in range(len(enum_folder_results_2)):
                    if (enum_folder_results_2[i] == 1 and enum_folder_results_1[i] == 0) or (enum_folder_results_1[i] == 1 and enum_folder_results_2[i] == 0) or (enum_folder_results_1[i] == 1 and enum_folder_results_2[i] == 1):
                        all_in_one.append(1)
                    else:
                        all_in_one.append(0)
            else :
                for i in range(len(enum_folder_results_3)):
                    if enum_folder_results_1[i] == 0:
                        if enum_folder_results_2[i] == 0:
                            if enum_folder_results_3[i] == 0:
                                all_in_one.append(0)
                            else:
                                all_in_one.append(1)
                        else:
                            all_in_one.append(1)
                    else:
                        all_in_one.append(1)
    
    # Return the results
    #print(len(all_in_one))
    return all_in_one

def get_str_from_str(str_file, text_file):

    # Read the hexdump file
    str1 = read_file(str_file)  # Target file to extract
    str2 = read_file(text_file) # From the datasets

    found_strings = []
    for i in str2 :
        flag = 0
        for j in str1:
            if j in i:
                flag = 1
                break
        found_strings.append(flag)

    #print(len(found_strings))
    return found_strings

def extracting_info_for_ml(file_path,json_files,str_file):

    _final_liste_results = []
    # API's
    found_apis = get_apis_results(file_path)
    for i in found_apis:
        _final_liste_results.append(i)
    #print("Found API's in pefile:",found_apis)

    # Extension of files droped
    found_extensions = get_drop_extensions_files(json_files)
    for i in found_extensions:
        _final_liste_results.append(i)
    #print("Found extensions in json file:", found_extensions)

    # Extraction of Registry key from json file
    found_regitry_key = get_reg_key(json_files)
    for i in found_regitry_key:
        _final_liste_results.append(i)

    # Extraction of Files and Pathways informations from json file
    found_files_and_folders = get_file_and_dir_key(json_files)
    for i in found_files_and_folders:
        _final_liste_results.append(i)
    
    # Extraction Strings files information using hexdump
    found_str = get_str_from_str(str_file,"/home/narimene/APP_PFE/static/static data/strings_files_static.txt")
    for i in found_str:
        _final_liste_results.append(i)
    
    #print(len(_final_liste_results))
    return _final_liste_results