from vt_graph_api import VTGraph
from PIL import Image
from selenium import webdriver
import time



def desigh_graph():
    API_KEY = "f18862dd85b0ec074530c0931faab8b9471df84513c521c282b1b3004ba0095d"  # Insert your VT API here.
    # Creates the graph.
    graph = VTGraph(API_KEY, private=False, name="")
    # Adds the node.
    graph.add_node(
        "eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe",
        "file", label="")
    # Expands the graph 1 level.
    graph.expand_n_level(level=1, max_nodes_per_relationship=5, max_nodes=100)
    # Saves the graph.
    graph.save_graph()
    # URL of graph

    url = f"https://www.virustotal.com/graph/embed/{str(graph.graph_id)}?theme=light"
    print("Graph : "+url)

    """

    <iframe
        src="https://www.virustotal.com/graph/embed/gf90e12f1cedf4cb4bf600d24740deadb95b0d6d52d6849f98fd56bdab15bff8d?theme=light"
        width="700"
        height="400">
    </iframe>
            

    """

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
    driver.save_screenshot('screenshot.png')
    driver.quit()

    _end = time.time()
    print('Total time for non-headless {}'.format(_end - _start))

    # Open the image file
    image = Image.open('screenshot.png')

    # Define the cropping coordinates (left, upper, right, lower)
    box = (100, 100, 1200, 800)

    # Crop the image
    cropped_image = image.crop(box)

    # Save the cropped image
    cropped_image.save('example_cropped.png')
