# Import the datasets

import pandas as pd, os
from sklearn.model_selection import train_test_split
import warnings
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import datetime
from scripts.extraction import extracting_info_for_ml
from multiprocessing import Pool


warnings.filterwarnings(action="ignore")

"""### Get Initial File"""
def get_all_files():
    all_files = []
    os.chdir('/var/www/basic-flask-app/static/uploads')
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def get_exec():
    all_file = get_all_files()
    for i in all_file:
        if not "hexdump" in i and not ".txt" in i:
            if not "strings" in i and not ".txt" in i:
                if not "data_file" in i and not ".json" in i :
                    if not "behaviour_summary_results.json" in i:
                        return i
    print("ERROR")

def get_behav_rpt():
    all_file = get_all_files()
    for i in all_file:
        if "behaviour_summary_results.json" in i:
            return i
    print("ERROR")

def get_strings():
    all_file = get_all_files()
    for i in all_file:
        if "strings_" in i and ".txt" in i:
            return i
    print("ERROR")

"""### Preprocessing"""
def preprocessing(df):
    # Delete the columns by their numerical positions:
    cols_to_drop = [0, 2]
    df = df.drop(df.columns[cols_to_drop], axis=1)

    # Delete all the duplicated rows:
    df = df.drop_duplicates(keep='last')

    # Display the dataframe and finally return the changed one
    #print(df.head())

    return df

"""### Add a new to test and see the results"""
def Test_new_feature(rf,y_pred,X_new):
    # Use the model to predict the classes of the new data
    y_pred = rf.predict(X_new)

    # Print the predicted classes of the new data
    X_new_new = X_new[0]
    #print(X_new_new)

    #print("Predicted classes of adding a new test:", y_pred)
    if 1 in y_pred:
        #print("Resultat d'analyse : The file is a ransomware file")
        a = False
        X_new_new.append(1)
    else:
        #print("Resultat d'analyse : The file is not a ransomware file")
        a = True
        X_new_new.append(0)
    #print(X_new_new)
    return X_new_new, a

def process_new_feature(args):
    rf, y_test, new_feature = args
    return Test_new_feature(rf, y_test, new_feature)

def dynamic_analysis():
    # Read the CSV file
    df = pd.read_csv("/var/www/basic-flask-app/static/datasets_ml/RansomwareData.csv") # Change me if u change the OS

    # Delete useless columns using the preprocessing function
    df = preprocessing(df)

    # Transform the data into arrays
    X = df.iloc[:, 1:].values
    Y = df.iloc[:, 0].values

    # Split data into training and testing sets
    # 20% testing and 80% train
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=0)

    # Create a Random Forest Classifier with 100 trees
    rf = RandomForestClassifier(n_estimators=1000, random_state=0)

    # Fit the Random Forest Classifier to the training data
    rf.fit(X_train, y_train)

    # Extraction the information from json rapport and get in list
    # Get all initial file
    exe_file = get_exec()
    behav_rapport = get_behav_rpt()
    hexdump_file = get_strings()

    # Create a list of new features
    new_features = [extracting_info_for_ml(exe_file, behav_rapport, hexdump_file)]

    # Perform parallel processing using multiple processes
    with Pool() as pool:
        results = pool.map(process_new_feature, [(rf, y_test, [new_feature]) for new_feature in new_features])

    # Print the results
    now = datetime.datetime.now()
    for result, new_feature in results:
        #print("[{}]~ The prediction for new feature {}".format(now, new_feature))
        print("["+str(now)+"]~ The prediction using machine learnig by Random-Forest in dynamic analysis has been done successful!")

    # Return the final results
    return results

#Copyright 02-25-2023 ~ Boussoura Mohamed Cherif & Houanti Narimene ~ Machine learning script for ransomware dynamic prediction and detection using random tree and open source datasets from Github : https://github.com/rissgrouphub/ransomwaredataset2016.git