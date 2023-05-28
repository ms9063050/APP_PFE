import pandas as pd
import json, os, datetime
now = datetime.datetime.now()

def get_all_files():
    all_files = []
    os.chdir('/var/www/basic-flask-app/static/uploads')
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def load_and_read_json():
    get_files = get_all_files()
    # get the json files
    for i in get_files :
        if ".json" in i and "data_file_" in i:
            file_json = i
            break
    with open(file_json, 'r') as f:
        data = json.load(f)
    return data

def Ransomware_Detection_Based_File_Family(file_path,file_hash):
    os.chdir('/var/www/basic-flask-app/static/datasets')
    all_files = []
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    df = pd.read_csv(all_files[0])
    
    result = df[df["MD5"] == file_hash ]
    if len(result) == 0 :
        return False
    else:
        return True

def start_signature_analysis():
    dic=load_and_read_json()
    for i in dic:
        print("["+str(now)+"]~ The Signature Analysis has been done successful!")

        if not Ransomware_Detection_Based_File_Family(i,dic[i]['md5Hash']):
            #print("The file analysed is not a Ransomware file!")
            a = True
        else:
            #print("The file analysed is a Ransomware file!")
            a = False
    os.chdir('//var/www/basic-flask-app/static/uploads')
    return a
#Copyright 02-25-2023 ~ Boussoura Mohamed Cherif & Houanti Narimene