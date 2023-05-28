import os, datetime, ctypes
now = datetime.datetime.now()

def get_all_files():
    all_files = []
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def delete_all(filename):
    os.chdir("/var/www/basic-flask-app/static/uploads")
    for file in get_all_files():
        try:
            if ".exe" in file:
                if filename in file:
                    os.remove(file)
                else:
                    print("error")
            else:
                os.remove(file)

        except OSError:
            # File is being used by another process, try to force deletion using ctypes
            try:
                os.system(f"DEL /F /Q {file}")
                
            except OSError as e:
                print(f'Error deleting {file}: {e.strerror}')
    print("["+str(now)+"]~ Done!!! - ALL FILES HAS BEEN DELETED")
    os.chdir('/var/www/basic-flask-app')

#Copyright 02-25-2023 ~ Boussoura Mohamed Cherif & Houanti Narimene