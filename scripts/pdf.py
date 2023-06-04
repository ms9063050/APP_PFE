from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from vt_graph_api import VTGraph
from PIL import Image
from selenium import webdriver
import time, json
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
import numpy as np
import datetime, os

now = datetime.datetime.now()

def get_all_files():
    all_files = []
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def load_and_read_json2():
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if "behaviour_summary_results.json" in i:
            return i
    print("ERROR !!!")



def draw_score_rate(data):
    # Define the labels for each value
    labels = ['Ransomware', 'Clean']

    # Define the custom color map
    colors = ['#ff6666', '#66b3ff']
    cmap = ListedColormap(colors)

    # Generate the colors as a list of RGBA tuples
    colors_rgba = cmap(np.linspace(0, 1, len(data)))

    # Explode the first slice
    explode = (0.1, 0)

    # Create the pie chart with shadow effect
    fig, ax = plt.subplots()
    ax.pie(data, labels=labels, explode=explode, colors=colors_rgba, shadow=True, autopct=lambda pct: '{:.1f}'.format(pct * 10 / 100), startangle=90)

    # Add a title and legend
    ax.set_title('Ransomware Detection')
    ax.legend(title='Results', loc='center right')

    # Adjust font and style
    plt.rcParams.update({'font.size': 12, 'font.family': 'Helvetica', 'text.color': 'black'})
    plt.tight_layout()

    # Save the plot as a PNG file
    plt.savefig('malware_scores.png')

def draw_graph(hash_file):
    try :
        API_KEY = "f18862dd85b0ec074530c0931faab8b9471df84513c521c282b1b3004ba0095d"  # Insert your VT API here.
        # Creates the graph.
        graph = VTGraph(API_KEY, private=False, name="")
        # Adds the node.
        graph.add_node(
            hash_file,
            "file", label="")
        # Expands the graph 1 level.
        graph.expand_n_level(level=1, max_nodes_per_relationship=5, max_nodes=100)
        # Saves the graph.
        graph.save_graph()
        # URL of graph

        url = f"https://www.virustotal.com/graph/embed/{str(graph.graph_id)}?theme=light"

        # Set the URL you want to screenshot
        _start = time.time()

        # Set up the Chrome webdriver
        options = webdriver.ChromeOptions()
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--disable-extensions')
        options.add_argument('--headless')
        options.add_argument('--window-size=1200,800')

        # Navigate to the URL and take a screenshot
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        driver.execute_script("document.body.style.zoom='121%'")
        time.sleep(20)
        driver.save_screenshot('/home/narimene/APP_PFE/static/uploads/screenshot.png')
        driver.quit()

        _end = time.time()

        # Open the image file
        image = Image.open('screenshot.png')

        # Define the cropping coordinates (left, upper, right, lower)
        box = (100, 100, 1200, 800)

        # Crop the image
        cropped_image = image.crop(box)

        # Save the cropped image
        cropped_image.save('example_cropped.png')
        return True
    except Exception:
        return False

def score_rate(data):
    # 80 + x : 5 *5 + 10:ML + 25:behav + 10*foreach api
    score = 0
    cpt = 0
    for i in data:
        if data[i] is False:
            if "Behaviour Detection" in i:
                score += 25
            if 'Signature' in i or 'Entropy' in i or 'Encryption Algorithmes' in i or 'Anti debugging detection' in i or 'Anti vms detection' in i:
                score += 5
            else:
                cpt += 1
                score += 10  
    total = 25 + 5 * 5 + cpt * 10
    return score, total
def get_name_of_file(filename):
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if ".exe" in i or ".dll" in i or "sys" in i:
            if filename in i:
                file_exe = i
                break
            else:
                print("error")
        if not ".txt" in i:
            if not ".json" in i :
                file_exe = i
                break
    string_file = file_exe.split("/")
    return string_file[-1].split(".")[0]
def get_png_of_graph():
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if "example_cropped.png" in i:
            return i
    print("error")

def get_pdf():
    directory = '/home/narimene/APP_PFE/archive'
    files = os.listdir(directory)
    paths = [os.path.join(directory, file) for file in files]
    last_updated_path = max(paths, key=os.path.getmtime)
    return last_updated_path

# Create a function that generates a PDF report
def generate_report(data,s,familly,filename):
    os.chdir("/home/narimene/APP_PFE/static/uploads")
    json_file = load_and_read_json2()
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # Create a new PDF file
    filename = "malware_analysis_report_"+get_name_of_file(filename)+"_%Y-%m-%d_%H-%M-%S"+".pdf"
    file_pdf = datetime.datetime.now().strftime(filename)
    pdf_file = canvas.Canvas(file_pdf, pagesize=letter)

    # Set the font and font size for the report
    pdf_file.setFont("Helvetica-Bold", 20)

    # Write the malware analysis report to the PDF file
    pdf_file.drawCentredString(300, 750, "Malware Analysis Report")
    pdf_file.setLineWidth(1)
    pdf_file.line(50, 745, 550, 745)
    pdf_file.setFont("Helvetica-Bold", 14)
    pdf_file.drawString(50, 700, "Overview:")
    pdf_file.setFont("Helvetica", 13)
    pdf_file.drawString(50, 675, "In this report, we analyzed a new strain of ransomware that has been spreading")
    ss = f"across corporate networks. The ransomware, known as '{familly}', is could be spread "
    pdf_file.drawString(50, 650, ss)
    pdf_file.drawString(50, 625, "through malicious emails containing a macro-enabled Word document.")
    # Score rate draw
    pdf_file.setFont("Helvetica-Bold", 14)
    pdf_file.drawString(50, 575, "Score rate:")
    score, total = score_rate(data)
    draw_score_rate([score,total-score])
    # Draw the PNG file on the PDF
    pdf_file.drawImage('/home/narimene/APP_PFE/static/uploads/malware_scores.png', 100, 320, 400, 250)
    # Informations about file
    pdf_file.setFont("Helvetica-Bold", 14)
    pdf_file.drawString(50, 270, "Information related about file")
    pdf_file.setFont("Helvetica", 13)
    pdf_file.drawString(50, 245, "size : "+str(s[0]))
    pdf_file.drawString(50, 220, "MD5 Hash :"+str(s[1]))
    pdf_file.drawString(50, 195, "Extension of file :"+str(s[2]))
    pdf_file.showPage()
    # Static analysis
    pdf_file.setFont("Helvetica-Bold", 14)
    pdf_file.drawString(50, 700, "Static Analysis")
    pdf_file.setFont("Helvetica", 13)
    for i in data:
        if data[i] is True:
            if i in "Signature":
                qq1 = "In Signature algorithme the file has been not detected in signature file"
            if i in "Entropy":
                qq2 = "In Entropy algorithme, the file could not be suspect"
            if i in "Encryption Algorithmes":
                qq3 = "In Encryption algorithme, the file analyzed could not detect the algorithmes"
            if i in "Anti debugging detection":
                qq4 = "In Anti debugging algorithme, the file analyzed could not detect the anti debugging functions"
            if i in "Anti vms detection":
                qq5 = "In Anti vm algorithme, the file analyzed could not detect the vms"
            if i in "ML":
                qq6 = "In Machine learning algorithme, the file analyzed could not be suspect of ransomwares"
        else:
            if i in "Signature":
                qq1 = "In Signature algorithme the file has been detected in signature file"
            if i in "Entropy":
                qq2 = "In Entropy algorithme, the file could be suspect"
            if i in "Encryption Algorithmes":
                qq3 = "In Encryption algorithme, the file analyzed could detect the algorithmes"
            if i in "Anti debugging detection":
                qq4 = "In Anti debugging algorithme, the file analyzed could detect the anti debugging functions"
            if i in "Anti vms detection":
                qq5 = "In Anti vm algorithme, the file analyzed could detect the vms"
            if i in "ML":
                qq6 = "In Machine learning algorithme, the file analyzed could be suspect of ransomwares"
    pdf_file.drawString(50, 675, qq1)
    pdf_file.drawString(50, 650, qq2)
    pdf_file.drawString(50, 625, qq3)
    pdf_file.drawString(50, 600, qq4)
    pdf_file.drawString(50, 575, qq5)
    pdf_file.drawString(50, 550, qq6)
    # Behaviour analysis
    if "error" in dictionary:
        pdf_file.setFont("Helvetica-Bold", 14)
        a = 475
        pdf_file.drawString(50, 500, "Indicators of Compromise (IOCs):")
        pdf_file.setFont("Helvetica", 13)
        try :
            if "ip_traffic" in dictionary["data"]:
                pdf_file.drawString(50, a, "IP Traffic: ")
                a -= 25
                for i in dictionary["data"]["ip_traffic"]:
                    if a == 0:
                        pdf_file.showPage()
                        a = 700
                    pdf_file.drawString(100, a, "- "+str(i))
                    a -= 25
        except KeyError:
            pass
        try:
            if "memory_pattern_urls" in dictionary["data"]:
                pdf_file.drawString(50, a, "Memory pattern urls :")
                a -= 25
                for i in dictionary["data"]["memory_pattern_urls"]:
                    if a == 0:
                        pdf_file.showPage()
                        a = 700
                    pdf_file.drawString(100, a, "- "+str(i))
                    a -= 25
        except KeyError:
            pass
        try:
            if "dns_lookups" in dictionary["data"]:
                pdf_file.drawString(50, a, "Dns lookup resolved : ")
                a -= 25
                for i in dictionary["data"]["dns_lookups"]:
                    if a == 0:
                        pdf_file.showPage()
                        a = 700
                    pdf_file.drawString(100, a, "- "+str(i["hostname"]))
                    a -= 25
        except KeyError:
            pass
        try:
            if "attack_techniques" in dictionary["data"]:
                pdf_file.drawString(50, a, "Mitre Att&ck Framework : ")
                a -= 25
                b = 100
                if len(dictionary["data"]["attack_techniques"]):
                    for i in dictionary["data"]["attack_techniques"]:
                        if b > 500:
                            b = 100
                            a -= 25
                            if a == 0:
                                pdf_file.showPage()
                                a = 700
                        pdf_file.drawString(b, a, "- "+str(i))
                        b += 75
        except KeyError:
            pass
    pdf_file.showPage()
    # Graph of all data
    pdf_file.setFont("Helvetica-Bold", 14)
    pdf_file.drawString(50, 700, "Graph:")
    if draw_graph(s[1]):
        img_reader = ImageReader(get_png_of_graph())
        width, height = letter
        # Rotate the canvas and draw the image horizontally
        pdf_file.saveState()
        pdf_file.rotate(90)
        pdf_file.drawImage(img_reader, -100, -width, width=height, height=width)
        pdf_file.showPage()
        pdf_file.setFont("Helvetica-Bold", 14)
        pdf_file.drawString(50, 700, "Recommendations:")
        pdf_file.setFont("Helvetica", 13)
        pdf_file.drawString(50, 675, f"To prevent future {familly} infections, we recommend implementing security best")
        pdf_file.drawString(50, 650, "practices such as : ")
        pdf_file.drawString(50, 625, "1. Isolate the infected system")
        pdf_file.drawString(50, 600, "2. Assess the scope of the attack")
        pdf_file.drawString(50, 575, "3. Determine the type of ransomware")
        pdf_file.drawString(50, 550, "4. Backup and restore")
        pdf_file.drawString(50, 525, "5. Consult with security experts")
        pdf_file.drawString(50, 500, "6. Do not pay the ransom beceause it does not guarantee that the data will be restored ")
        pdf_file.drawString(50, 475, "and may encourage further attacks.")
        pdf_file.drawString(50, 450, "7. Strengthen cybersecurity measures: ")
        pdf_file.drawString(100, 425, "- Updating software and systems.")
        pdf_file.drawString(100, 400, "- Implementing multi-factor authentication.")
        pdf_file.drawString(100, 375, "- Enforcing strong password policies.")
        pdf_file.drawString(100, 350, "- Educating employees on how to detect and report suspicious activity.")
    else:
        pass
    
    # Save the PDF file and close it
    os.chdir("../archive")
    pdf_file.save()
    print("["+str(now)+"]~ Done!!! - THE PDF HAS BEEN GENERATED")
    return get_pdf()
#################
# get exec file 
# get name
# serach in all of the list


