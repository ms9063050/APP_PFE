import yara, os, datetime
now = datetime.datetime.now()

# Get all YARA rule files
def get_all_rules():
    return [os.path.join(root, file) for root, dirs, files in os.walk('/var/www/basic-flask-app/static/rules') for file in files if file.endswith('.yar')]


def analyse_with_yara(rule_path, file_path):
    # Compile the YARA rule
    rules = yara.compile(rule_path)

    # Scan the file with YARA
    matches = rules.match(file_path)

    # Print any matching rules
    if matches:
        #for match in matches:
        #    print(f"Matched rule: {match.rule}")
        return True
    else:
        #print("No matches found.")
        return False

def verify_yara_rules_end(rst):
    for i in rst:
        if i is True:
            return False
    return True

def Yara_analyse(file_path):
    _results_after = []
    all_rules = get_all_rules()

    # Scan each file with each YARA rule
    for rule_path in all_rules:
        try:
            _results_after.append(analyse_with_yara(rule_path, file_path))
        except yara.SyntaxError as e:
            pass

    # Verify if any rules matched
    result = verify_yara_rules_end(_results_after)
    #print(f"YARA analysis result: {result}")
    print("["+str(now)+"]~ The Signature Analysis by YARA-Rule has been done successful!")
    return result

def get_executable_to_analyse():
    return next(os.path.join(root, file) for root, dirs, files in os.walk('/var/www/basic-flask-app/static/uploads') for file in files if file.endswith('.exe'))