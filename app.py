from flask import Flask, render_template, Blueprint, request, current_app
from werkzeug.utils import secure_filename
from scripts.static_create_files_to_analyse import Extract_informations
from scripts.delete_files_created_before import delete_all
import os, time

app = Flask(__name__)
UPLOAD_FOLDER = '.\\uploads'
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
def full_scans():
    return render_template("full_scan.html")
	
@app.route('/upload', methods = ['POST'])  
def upload():
    files = request.files.getlist("file")
    print(files)
    data = []
    for f in files:
        filename = secure_filename(f.filename)
        print(filename)
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    # EXTRACT THE INFORMATIONS
    Extract_informations()
    # ANALYSIS
    
    # WRITE IN THE DATABASE THE RESULTS AND DISPLAY TO THE USER

    # DELETE THE EXTRACT INFO + UPLOADS FILES
    #delete_all()
    return render_template("results.html", file = data)
if __name__ == '__main__':
    app.run(debug=True,port=8000)