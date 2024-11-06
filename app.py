from flask import Flask, request, redirect, render_template, send_from_directory, url_for, flash
import os
import hashlib
import requests

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Required for flash messages
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# VirusTotal API setup
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'  # Replace with your actual API key
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/files/'

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Function to check file safety with VirusTotal
def check_file_with_virustotal(file):
    # Calculate the file hash (SHA-256)
    file_hash = hashlib.sha256(file.read()).hexdigest()
    file.seek(0)  # Reset file pointer after reading for hashing

    # Set up the headers with the API key
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    # Check the file on VirusTotal
    response = requests.get(VIRUSTOTAL_URL + file_hash, headers=headers)

    # Parse the response
    if response.status_code == 200:
        data = response.json()
        # Check if the file is flagged as malicious
        if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            return False  # File is malicious
        else:
            return True  # File is safe
    elif response.status_code == 404:
        # File not found in VirusTotal, optionally handle it
        return "unknown"
    else:
        return None  # Error with the API


# Route for file upload and display
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Get the file from the form
        file = request.files['file']
        if file:
            # Check file with VirusTotal before saving
            safety_check = check_file_with_virustotal(file)

            if safety_check is None:
                flash("Error with VirusTotal API, please try again later.")
                return redirect(url_for('index'))
            elif safety_check == "unknown":
                flash("File has not been scanned by VirusTotal and cannot be verified.")
                return redirect(url_for('index'))
            elif safety_check:
                # File is safe, save it
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(file_path)
                flash("File uploaded successfully.")
                return redirect(url_for('index'))
            else:
                flash("File flagged as unsafe by VirusTotal, upload prohibited.")
                return redirect(url_for('index'))

    # List files for download
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template("index.html", files=files)


# Route to download file
@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == "__main__":
    app.run(debug=True)
