from flask import Flask, render_template, Blueprint, request, current_app
from werkzeug.utils import secure_filename
from scripts.search_path_file import search_path
from scripts.static_create_files_to_analyse import Extract_informations

views = Blueprint(__name__, "views")

@views.route("/")
def home():
    return render_template("index.html", name="Tim")

@views.route("/results")
def results():
    return render_template("results.html")

@views.route("/full_scans")
def full_scans():
    return render_template("full_scan.html")
	
@views.route('/upload', methods = ['POST'])  
def upload():
    files = request.files.getlist("file")
    print(files)
    data = []
    for f in files:
        filename = secure_filename(f.filename)
        print(filename)
        data.append(search_path(filename))
    print(data)
    for f in data:
        Extract_informations(f)
    return render_template("results.html", file = data)

