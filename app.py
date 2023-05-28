from flask import Flask, render_template, request, send_file
from scripts.static_create_files_to_analyse import Extract_informations
from scripts.delete_files_created_before import delete_all
from scripts.signature_analysis import start_signature_analysis
from scripts.machine_learning_test import start_ml_analysis
from scripts.obsufuctions import Obsufuctions_Analysis
from scripts.solution_existante import solution_deja_existante
import os, datetime, threading
from scripts.behav import behav_analysis
from scripts.pdf import generate_report, get_pdf
from scripts.yara import get_executable_to_analyse, Yara_analyse
from scripts.dynamic_analysis_using_ml import dynamic_analysis
from scripts.behav import generate_json
import time

app = Flask(__name__)
UPLOAD_FOLDER = '/var/www/basic-flask-app/static/uploads' # Change me
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

#app.register_blueprint(app, url_prefix="/app")

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/results")
def results():
    return render_template("results.html")

@app.route("/full_scans")
def full_results():
    return render_template("full_scan.html")

@app.route("/download_report")
def full_scans():
    latest_file = get_pdf()
    return send_file(latest_file, as_attachment=True, download_name=os.path.basename(latest_file))

# Create a lock object
lock = threading.Lock()

@app.route('/upload', methods = ['POST'])  
def upload():
    # Acquire the lock to ensure mutual exclusion
    lock.acquire()
    try:
        data = []
        files = request.files.getlist("file")
        data = {}
        desc = {}
        details = []
        for f in files:
            filename = f.filename
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        # EXTRACT THE INFORMATIONS
        now = datetime.datetime.now()
        s = Extract_informations(filename) # extract the importante data
        time.sleep(5)
        generate_json(filename)   # generate the behavior report
        for i in s:
            details.append(i)
        details.append(str(now))
        time.sleep(5)
        # ANALYSIS
        # ANALYSE USING IA (MACHINE LEARNING) By the threading concept to gain some time
        def ml_analysis_task():
            try:
                data["ML"] = start_ml_analysis()
                desc["ML"] = "Detect the ransomware by machine learning using random forest with a datasets."
            except IndexError:
                data["ML"] = False
                desc["ML"] = "Error has been generated, the algortihme has been not run successfully"
        def dynamic_analysis_task():
            try:
                data["Behaviour Detection Using ML"] = dynamic_analysis()
                desc["Behaviour Detection Using ML"] = "Detect the ransomware by machine learning using random forest with a dynamic datasets."
            except IndexError:
                data["Behaviour Detection Using ML"] = False
                desc["Behaviour Detection Using ML"] = "Error has been generated, the algortihme has been not run successfully"
        threads = []
        ml_thread = threading.Thread(target=ml_analysis_task)
        ml_thread.start()
        threads.append(ml_thread)
        
        dynamic_thread = threading.Thread(target=dynamic_analysis_task)
        dynamic_thread.start()
        threads.append(dynamic_thread)

        # YARA RULES
        data["Yara-Rules"] = Yara_analyse(get_executable_to_analyse())
        desc["Yara-Rules"] = "Detect the ransomware by using yara rules in python"

        # Signature using dataset
        data["Signature"] = start_signature_analysis()
        desc["Signature"] = "Detect the ransomware by his signature in our datasets of ransomwares files"

        # obsufuctions
        data["Entropy"],data["Encryption Algorithmes"],data["Anti debugging detection"],data["Anti vms detection"] = Obsufuctions_Analysis(filename)
        desc["Entropy"] = "Detect the ransomware by entropy"
        desc["Encryption Algorithmes"] = "Detect the ransomware by Encryption Algorithmes"
        desc["Anti debugging detection"] = "Detect the ransomware by Anti debugging"
        desc["Anti vms detection"] = "Detect the ransomware by Anti Virtual Machines"

        # Behaviour analysis
        data["Behaviour Detection"], desc["Behaviour Detection"], familly = behav_analysis(filename)
        
        # Solution deja existe
        ss = []
        #data["Intezer API"], data["Scanii API"], ss = solution_deja_existante(filename)
        ss = solution_deja_existante(filename)
        try :
            if len(ss) == 2:
                for i in range(len(ss[0])):
                    data[ss[0][i]] = ss[1][i]
        except TypeError:
            data["Smart analysis"] = ss
        
        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        # Generate the report
        path_to_pdf = generate_report(data,s,familly,filename)
        # DELETE THE EXTRACT INFO + UPLOADS FILES
        delete_all(filename)
        send_file(path_to_pdf, as_attachment=True)
        return render_template("results.html", data=data, desc=desc, details=details, path_to_pdf=path_to_pdf)
        #return render_template("results.html", data=data, desc=desc, details=details)
    finally:
        # Release the lock to allow other threads to acquire it
        lock.release()

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True,port=8000)

#Copyright 02-25-2023 ~ Boussoura Mohamed Cherif 
