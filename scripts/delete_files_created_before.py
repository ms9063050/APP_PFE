import os, datetime
now = datetime.datetime.now()
def get_all_files():
    all_files = []
    os.chdir('.\\uploads')
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def delete_all():
    get_all_ = get_all_files()
    #print(get_all_)
    for file in get_all_:
        try:
            os.remove(file)
        except FileNotFoundError:
            print(f'{file} does not exist.')
    print("["+str(now)+"]~ Done!!! - ALL FILES HAS BEEN DELETED")
    os.chdir('..')

#Copyright 02-25-2023 ~ Boussoura Mohamed Cherif & Houanti Narimene