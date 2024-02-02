Automated Vulnerability Assessment Tool using ChatGPT and Google Bard API

Overview:

The provided Python script is designed to perform the following tasks:
The main components used in the main.py file are as below.
1. Imports:
The script imports various modules and libraries required for its functionality. These include threading, a custom nmap_scanner module, chatgpt, regular expressions (re), logging, requests, Bard from bardapi, time, and modules from reportlab for PDF generation. Additionally, matplotlib and numpy are imported for plotting.

2.Logging Setup:
Logging is configured using logging.basicConfig to record logs in a file named "app.log" with a specific format.

3. Initialization:
Two empty lists, response_time_bard and response_time_gpt, are initialized to store response times for Bard and ChatGPT, respectively.

4.Functions:
Several functions are defined to encapsulate specific functionalities:
•	extract_cve_info: Extracts Common Vulnerabilities and Exposures (CVE) information from a given scan result using regular expressions.
•	write_cve_to_file: Writes detected vulnerabilities for an IP address to a file.
•	send_cve_to_chatgpt: Sends CVE information to ChatGPT, creates a PDF report, and writes the information to a file.
•	scan_for_vuln: Scans a target host for vulnerabilities using the nmap_scanner module and extracts CVE information.
•	bard_api: Sends CVE information to the Bard API, creates a PDF report, and writes the information to a file.
•	create_a_pdf_bard and create_a_pdf_gpt: Generate PDF reports for Bard and ChatGPT responses, respectively.
•	plot_vs_graph: Plots response times for Bard and ChatGPT.

5.Main Execution:
•	The script prompts the user to input four IP addresses for vulnerability scanning.
•	For each scanned IP address, it creates two threads:
•	t1: Sends CVE information to ChatGPT using the send_cve_to_chatgpt function.
•	t2: Sends CVE information to the Bard API using the bard_api function.
•	The script waits for both threads to finish (t1.join() and t2.join()).
•	After scanning all IPs, it plots the response times for Bard and ChatGPT using the plot_vs_graph function.

The main components of the nmap_scanner.py are as below

1. Import Statements:
•	import subprocess: This imports the subprocess module, which allows the script to spawn new processes, connect to their input/output/error pipes, and obtain their return codes.
•	import logging: This imports the logging module, which provides a flexible framework for emitting log messages from applications.
2. scan_for_vulnerabilities Function: 
•	This function takes a target_host parameter, representing the host or IP address to be scanned for vulnerabilities.
3. Logging Configuration:
•	logging.basicConfig is used to configure the logging settings. It sets the log file to be "logs/scan.log," sets the logging level to INFO, and defines a log message format including the timestamp, log level, and the log message itself.
4.Nmap Scanning: 
•	The function constructs an Nmap command using a list (nmap_command) that includes the necessary parameters for a vulnerability scan (-sV for version detection, --script vuln for running vulnerability scripts).
•	subprocess.check_output is used to execute the Nmap command. This function runs the command and captures the output of the command as a string. The universal_newlines=True argument ensures that the output is returned as a string rather than bytes.
If the Nmap scan is successful, the scan result is returned. If there is an error (subprocess returns a non-zero exit code), the subprocess.CalledProcessError exception is caught, and an error message is logged using logging.error. The function then returns a message indicating that the Nmap scan failed.

5. __main__ Block: 
The script prompts the user to input the target host or IP address. It calls the scan_for_vulnerabilities function with the provided input and prints the scan result.

The main components used in the program chatgpt.py are as below.
1. Import Statements:
•	import openai: This imports the OpenAI Python library, which provides access to the GPT-3.5 API.
•	import logging: This imports the logging module, which provides a flexible framework for emitting log messages from applications.
2. API Key Configuration:
•	The API key for OpenAI is configured by setting the api_key variable to the appropriate value. This key is then set in openai.api_key to authorize requests to the OpenAI API.
3. get_fix_for_vulnerability Function:
•	This function takes two parameters: cve_code (the Common Vulnerabilities and Exposures code) and conversation (a list representing a conversation with ChatGPT).
4. Logging Configuration:
•	logging.basicConfig is used to configure the logging settings. It sets the log file to be "logs/chatgpt.log," sets the logging level to INFO, and defines a log message format including the timestamp, log level, and the log message itself.
5. ChatGPT Interaction:
•	A query is constructed using the provided CVE code to ask ChatGPT for fixes for the vulnerability.
•	The query is added to the conversation list, specifying the user's role and the content of the query.
•	The conversation is sent to ChatGPT using openai.ChatCompletion.create. The response from ChatGPT is then processed to extract the generated content of the message.
6. Exception Handling:
•	The script includes exception handling to catch any errors that might occur during the interaction with ChatGPT. If an exception is caught, an error message is logged using logging.error, and the function returns a default message indicating that it's unable to provide a fix at that time.

Instructions to run the code
1. Clone the Python program from GitHub repository
1.1	Open a terminal or command prompt on your computer.

1.2	Navigate to the directory where you want to clone the repository.
$ cd /path/to/your/directory

        1.3 Clone the GitHub repository using the following command:
	$ git clone https://github.com/aayush1108/NMAP-ChatGPT-Bard.git

2. Install the required dependencies 
•	Ensure that you have Python installed on your system. If not, download and install Python from www.python.org

•	Open a terminal or command prompt.

•	Navigate to the directory where you cloned the GitHub repository:
$ cd /path/to/your/cloned/repository

•	Install the required Python libraries by running the following commands:
pip install requests
pip install openai
pip install matplotlib
pip install numpy
pip install reportlab
pip install nmap
pip install Bard
These commands use the pip package manager to install the necessary dependencies.
Additionally, ensure that Nmap is installed on your system for vulnerability scanning. You can download it from nmap.org.

3. Generate ChatGPT and Google Bard API
Generating ChatGPT API Key
Step 1: Create a ChatGPT Account
•	Go to https://platform.openai.com and sign up for a free account.

Step 2: Access API Keys
•	Once logged in, click on your avatar in the top right corner and select "API" from the dropdown menu.

Step 3: Generate API Key
•	On the API page, click on the "New Key" button.
•	Provide a descriptive name for your API key and click on the "Create" button.

Step 4: Copy API Key
•	The generated API key will be displayed on the screen. Copy this key and save it securely for future use.

Generating Google Bard API
•	Sign up for a Google Cloud account if you don’t already have one. You can sign up for free here: https://cloud.google.com/free
•	Create a new project in the Google Cloud Console. Give your project a name and select a billing account to associate with the project.
•	Enable the Bard API for your project. To do this, go to the API Library in the Google Cloud Console and search for “Bard API”. Click on the API and then click the “Enable” button.
•	Create a new API key. To create an API key, go to the Credentials page in the Google Cloud Console and click the “Create credentials” button. Select “API key” from the dropdown menu and follow the prompts to create a new API key.
•	Copy your API key and store it securely. You will need to use this API key in your application to authenticate with the Google Bard API.

4.  Replace the ChatGPT API and Google Bard Session Cookie in the code

•	Open the main.py file in a text editor of your choice.
•	Locate the following section in the create_a_pdf_bard function:	

# In the create_a_pdf_bard function
token = " Your_Bard_Token"

Replace the placeholder value ("Your_Bard_Token") with your actual Google Bard session cookie.

•	Now, open the chatgpt.py file in the same text editor.
Locate the following section at the beginning of the file:
# In the chatgpt.py file
api_key = "-YOUR-ChatGPT-API"	

Replace the placeholder value ("YOUR-ChatGPT-API") with your actual ChatGPT API key.

•	4. Save the changes to both the main.py and chatgpt.py files.

Now, you have replaced the ChatGPT API key and Google Bard session cookie in the code. When you run the program, it will use the updated credentials for communication with ChatGPT and Google Bard APIs.

5. Run the program
•	Open a terminal or command prompt.
•	Navigate to the directory where the Python program is located using the cd command:
cd path/to/your/python/program

Replace path/to/your/python/program with the actual path to the directory where the main.py file is located.
•	Ensure that you have already completed Step 5 to replace the ChatGPT API key and Google Bard session cookie in the main.py file.
•	Run the main program by executing the following command:
python main.py

6. Enter IP Addresses
•	The program will prompt you to enter four IP addresses. Input the IP addresses as requested.

7. Execution and Concurrent Threads
•	The program will initiate scanning for vulnerabilities using Nmap.
•	It will interact with ChatGPT and call the Bard API concurrently using threads.
•	Wait for the program to finish its execution.

8. Generate Comparison Graphs
•	After completion, the program will generate comparison graphs and save them in the "graphs" directory.

9. Analyzing Results:
•	Check the app.log file for information about detected vulnerabilities.
•	Review query responses provided by Google Bard in the "bard" directory.
•	Examine query responses provided by ChatGPT in the "GPT" directory.


10. Debugging Information:

•	If there are any issues, errors, or unexpected behavior, review the app.log file for debugging information.
By following these steps, you can run the main program and analyze the results generated by interacting with ChatGPT and Google Bard APIs for vulnerability scanning and fix suggestions.
