# Import the datasets

import pandas as pd, os, json, csv
from sklearn.model_selection import train_test_split
import warnings
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
from mlxtend.plotting import plot_confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import plot_tree
from sklearn.model_selection import cross_val_score
import datetime
now = datetime.datetime.now()
warnings.filterwarnings(action="ignore")

"""### Preprocessing"""

def preprocessing():
    # open the datasets :
    os.chdir('/var/www/basic-flask-app/static/datasets_ml')
    all_files = []
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    df = pd.read_csv(all_files[0])

    # delete the useless columns :
    cols_to_drop = ["FileName","md5Hash"]
    df = df.drop(columns=cols_to_drop, axis=1)
    # replace the value repeated : MD5HASH - DebugSize - MajorOSVersion - BitcoinAddresses - NumberOfSections - SizeOfStackReserve
    columns = ["Machine"]
    for col in columns:
        df[col] = df[col].astype('category')
        df[col] = df[col].cat.codes
    
    # delete all the duplicated rows :
    df.drop_duplicates(keep='last')

    # save the new datasets into new csv file :
    #os.chdir('/var/www/basic-flask-app/static/datasets_ml')
    df.to_csv("/var/www/basic-flask-app/static/datasets_ml/df_clear.csv")

"""### Add a new to test and see the results"""
def add_new_test(rf,y_pred,X_new):
    # Use the model to predict the classes of the new data
    y_pred = rf.predict(X_new)

    # Print the predicted classes of the new data
    X_new_new = X_new[0]

    #print("Predicted classes of adding a new test:", y_pred)
    if 1 in y_pred:
        #print("The file is not a ransomware file")
        a = True
        X_new_new.append(1)
    else:
        #print("The file is a ransomware file")
        a = False
        X_new_new.append(0)
    return X_new_new, a

def get_all_files():
    all_files = []
    os.chdir('/var/www/basic-flask-app/static/uploads')
    current_dir = os.getcwd()
    #print(current_dir)
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

def get_data_from_json_file():
    dic = load_and_read_json()
    #print(dic)
    necessary_data = []
    columns = []
    for i in dic:
        for j in dic[i]:
            #print(dic[i][j])
            if j not in "md5Hash":
                columns.append(j)
                necessary_data.append(dic[i][j])
    #necessary_data = necessary_data[0:len(necessary_data)-1]
    #print(columns)
    #print(necessary_data)
    # traitement de la donnee avant l'entree de la fonction de machine learning 
    # Machine 
    if necessary_data[0] == 43620 :
        necessary_data[0] = 5
    elif necessary_data[0] == 34404 :
        necessary_data[0] = 4
    elif necessary_data[0] == 870 :
        necessary_data[0] = 3
    elif necessary_data[0] == 452 :
        necessary_data[0] = 2
    elif necessary_data[0] == 332:
        necessary_data[0] = 1
    else:
        necessary_data[0] = 0

    return necessary_data

def append_into_csv_file(nd):
    #if not check_contient(nd):
        # open the CSV file in append mode
    #os.chdir('/var/www/basic-flask-app/static/datasets_ml')
    with open("/var/www/basic-flask-app/static/datasets_ml/df_clear.csv", "r", newline="") as file:
        reader = csv.reader(file)
        last_row = list(reader)[-1]
    id = int(last_row[0]) + 1
    #print(id)
    new_list_to_append = []
    new_list_to_append.append(id)
    for i in nd:
        new_list_to_append.append(i)
    with open("/var/www/basic-flask-app/static/datasets_ml/df_clear.csv", "a", newline="") as file:
        # create a writer object
        writer = csv.writer(file)

        # append the new row to the CSV file
        writer.writerow(new_list_to_append)
    df = pd.read_csv("/var/www/basic-flask-app/static/datasets_ml/df_clear.csv")
    df = df.drop(df.columns[0], axis=1)
    # subset=["Machine","DebugSize","DebugRVA","MajorImageVersion","MajorOSVersion","ExportRVA","ExportSize","IatVRA","MajorLinkerVersion","MinorLinkerVersion","NumberOfSections","SizeOfStackReserve","DllCharacteristics","ResourceSize","BitcoinAddresses","Benign"],
    df = df.drop_duplicates(keep='last')
    df.to_csv("/var/www/basic-flask-app/static/datasets_ml/df_clear.csv")


def start_ml_analysis():
    """### Preprocessing"""
    #preprocessing()

    """### Prepare our dataset after preprocessing"""
    #os.chdir('/var/www/basic-flask-app/static/datasets_ml')
    df = pd.read_csv("/var/www/basic-flask-app/static/datasets_ml/df_clear.csv")
    
    # Transoform into List : 
    X = df.iloc[:, 1:-1].values
    Y = df.iloc[:,-1].values


    """### Random Forest Classifier"""
    # Generate random classification data
    #X, y = make_classification(n_samples=1000, n_features=15, n_classes=2,random_state=0)
    # Split data into training and testing sets
    # 50% testing and 50% train
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.5, random_state=0)
    # random state if we split for plusieur fois, ca ne sera pas changer : 
    # 80% of 1 and 20% if re-split maysrach lakhlate 

    # Create a Random Forest Classifier with 1000 trees
    rf = RandomForestClassifier(n_estimators=1000,random_state=0)

    # Fit the Random Forest Classifier to the training data
    rf.fit(X_train, y_train)

    # Predict the classes of the testing set
    y_pred = rf.predict(X_test)

    # Print the accuracy of the model
    #print("Accuracy:", rf.score(X_test, y_test))
    results_, s = add_new_test(rf,y_pred,[get_data_from_json_file()])
    
    # append the data into the csv file
    #append_into_csv_file(results_)
    print("["+str(now)+"]~ The prediction using machine learnig by Random-Forest has been done successful!")
    os.chdir('/var/www/basic-flask-app/static/uploads')
    return s

#Copyright 02-25-2023 ~ Boussoura Mohamed Cherif & Houanti Narimene ~ Machine learning script for ransomware prediction and detection using random tree and open source datasets from Kaggle : https://www.kaggle.com/datasets/amdj3dax/ransomware-detection-data-set
