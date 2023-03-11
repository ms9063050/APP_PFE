import re, os, pefile

def get_all_files():
    all_files = []
    #os.chdir('..\\..\\uploads')
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def load_and_read_exe_strings():
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if ".exe" in i:
            file_exe = i
            break
    string_file = file_exe.split("\\")
    string_file = "strings_" + string_file[-1].split(".")[0] + ".txt"
    #print(string_file)
    for i in get_files :
        if string_file in i:
            file_str = i
            break
    return file_exe, file_str

# Get some strings to analyisi by strings
#~ Encryption algorithmes ~ Narimene

# L'entropie

def entropie(file_path):
    print("Randomness of file Analysis ~ ")
    with open(file_path, 'rb') as f:
        pe = pefile.PE(data=f.read())

    # Check for common code obfuscation techniques
    print(pe.sections[0].get_entropy())
    if pe.sections[0].Name.startswith(b'.text') and pe.sections[0].get_entropy() > 6:
        print('Code section may be obfuscated')
    else:
        print('Code section appears normal')

# Anti-debugger  ~ Narimene

# Anti-vm  ~ Narimene

def Obsufuctions_Analysis():
    get_exe_ , get_strings_ = load_and_read_exe_strings()
    print(get_exe_)
    print(get_strings_)
    entropie(get_exe_)
    os.chdir('..\\')
