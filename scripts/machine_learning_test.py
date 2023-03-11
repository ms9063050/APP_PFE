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
    os.chdir('..\\.\\static\\datasets_ml')
    all_files = []
    current_dir = os.getcwd()
    print(current_dir)
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
    os.chdir('..\\.\\static\\datasets_ml')
    df.to_csv("df_clear.csv")


"""### Add a new to test and see the results"""
def add_new_test(rf,y_pred,X_new):
    # Load new data for prediction
    #X_new = [[1, 1, 0, 0, 6, 2, 0, 8192, 8, 0, 3, 1048576, 34112, 672,0]]

    # Use the model to predict the classes of the new data
    y_pred = rf.predict(X_new)

    # Print the predicted classes of the new data
    X_new_new = X_new[0]
    #print(X_new_new)

    #print("Predicted classes of adding a new test:", y_pred)
    if 1 in y_pred:
        print("The file is not a ransomware file")
        X_new_new.append(1)
    else:
        print("The file is a ransomware file")
        X_new_new.append(0)
    #print(X_new_new)
    return X_new_new

"""### Evaluate its performance using different metrics"""
def matrics_of_performance(y_pred,rf,X_test,y_test):
    os.chdir('..\\.\\static\\datasets_ml')
    # Use the model to predict the classes of the testing set
    y_pred = rf.predict(X_test)

    # Print the confusion matrix and classification report
    print("Confusion Matrix:")
    cm=confusion_matrix(y_test, y_pred)
    print(cm)

    print("\n Classification Report:")
    print(classification_report(y_test, y_pred))

    fig, ax = plot_confusion_matrix(conf_mat=cm , figsize=(6, 6), cmap=plt.cm.Greens)
    plt.xlabel('Predictions', fontsize=18)
    plt.ylabel('Actuals', fontsize=18)
    plt.title('Confusion Matrix', fontsize=18)
    plt.savefig('Confusion_matrix.png', bbox_inches='tight')
    #plt.show()

"""
In the confusion matrix:
    - True Positive (TP): The model correctly predicted the positive class.
    - True Negative (TN): The model correctly predicted the negative class.
    - False Positive (FP): The model predicted the positive class, but it was actually negative (also known as a Type I error).
    - False Negative (FN): The model predicted the negative class, but it was actually positive (also known as a Type II error).



            Actual   Positive       Actual Negative
Predicted Positive       TP               FP
Predicted Negative       FN               TN
"""

"""### Cross-validation to estimate its performance on new data. """
def calculate_the_cross_validation(rf, X, y):
    # Calculate cross-validation scores for the model
    # cross-validation scores for a model : a way of evaluating the performance of the model on a given dataset.
    scores = cross_val_score(rf, X, y, cv=5)

    # Print the cross-validation scores
    print("Cross-Validation Scores:", scores)

    # Mean score refers to the average score obtained from a set of scores. (moyenne)
    print("Mean Score:", scores.mean())

"""### Show the features"""
def design_tree(rf,X,y):
    # Fit the classifier to the data
    rf.fit(X, y)
    # Plot the first tree in the forest
    plt.figure(figsize=(32, 32))
    plot_tree(rf.estimators_[0], filled=True)
    plt.savefig('Tree_of_predictions.png', bbox_inches='tight')
    #plt.show()

def get_all_files():
    all_files = []
    os.chdir('..\\..\\uploads')
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
        if ".json" in i:
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

"""def check_contient(nd):
    # open the CSV file
    with open(r".\df_clear.csv", newline="") as file:

        # create a reader object
        reader = csv.reader(file)

        # loop through each row
        for row in reader:

            # check if the search list is in the row
            if row[1:len(row)-1] == nd:
                print("heelow  "+str(row[1:len(row)-1]))
                print(f"{nd} is in the CSV file!")
                return True
            else:
                print("heelow  "+str(row[1:len(row)-1]))
                print(f"{nd} is not in the CSV file.")
                return False"""

def append_into_csv_file(nd):
    #if not check_contient(nd):
        # open the CSV file in append mode
    os.chdir('..\\.\\static\\datasets_ml')
    with open("df_clear.csv", "r", newline="") as file:
        reader = csv.reader(file)
        last_row = list(reader)[-1]
    id = int(last_row[0]) + 1
    #print(id)
    new_list_to_append = []
    new_list_to_append.append(id)
    for i in nd:
        new_list_to_append.append(i)
    with open("df_clear.csv", "a", newline="") as file:
        # create a writer object
        writer = csv.writer(file)

        # append the new row to the CSV file
        writer.writerow(new_list_to_append)
    df = pd.read_csv("df_clear.csv")
    df = df.drop(df.columns[0], axis=1)
    # subset=["Machine","DebugSize","DebugRVA","MajorImageVersion","MajorOSVersion","ExportRVA","ExportSize","IatVRA","MajorLinkerVersion","MinorLinkerVersion","NumberOfSections","SizeOfStackReserve","DllCharacteristics","ResourceSize","BitcoinAddresses","Benign"],
    df = df.drop_duplicates(keep='last')
    df.to_csv("df_clear.csv")


def start_ml_analysis():
    """### Preprocessing"""
    #preprocessing()

    """### Prepare our dataset after preprocessing"""
    os.chdir('..\\.\\static\\datasets_ml')
    df = pd.read_csv(r".\df_clear.csv")
    #df.head()

    # dataframe informations
    #df.info()

    # Transoform into List : 
    X = df.iloc[:, 1:-1].values
    Y = df.iloc[:,-1].values

    #print("The features (Machine ... Bitcoin@) : ")
    #print(X)
    #print("Target vecteur (Benign) : ")
    #print(Y)

    """### Random Forest Classifier"""
    # Generate random classification data
    #X, y = make_classification(n_samples=1000, n_features=15, n_classes=2,random_state=0)
    # Split data into training and testing sets
    # 20% testing and 80% train
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.5, random_state=0)
    # random state if we split for plusieur fois, ca ne sera pas changer : 
    # 80% of 1 and 20% if re-split maysrach lakhlate 

    # Create a Random Forest Classifier with 100 trees
    rf = RandomForestClassifier(n_estimators=1000,random_state=0)

    # Fit the Random Forest Classifier to the training data
    rf.fit(X_train, y_train)

    # Predict the classes of the testing set
    y_pred = rf.predict(X_test)

    # Print the accuracy of the model
    print("Accuracy:", rf.score(X_test, y_test))

    results_ = add_new_test(rf,y_pred,[get_data_from_json_file()])
    #matrics_of_performance(y_pred,rf,X_test,y_test)
    #calculate_the_cross_validation(rf, X, y)
    #design_tree(rf,X,y)
    # append the data into the csv file
    append_into_csv_file(results_)
    print("["+str(now)+"]~ The prediction using machine learnig by Random-Forest has been done successful!")
#Copyright 02-25-2023 ~ Boussoura Mohamed Cherif & Houanti Narimene ~ Machine learning script for ransomware prediction and detection using random tree and open source datasets from Kaggle : https://www.kaggle.com/datasets/amdj3dax/ransomware-detection-data-set
