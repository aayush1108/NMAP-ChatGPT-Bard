import threading
import nmap_scanner
import chatgpt
import re
import logging
import requests
from bardapi import SESSION_HEADERS
import time
from bardapi import Bard
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import os
import matplotlib.pyplot as plt
import numpy as np
import sys

# Set up logging
logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

response_time_bard = []
response_time_gpt = []


def extract_cve_info(scan_result):
    # Regular expression to match CVE IDs, PRION, and CNVD IDs along with their scores
    cve_pattern = re.compile(r'\b(?:CVE-\d{4}-\d+|PRION:[A-Za-z0-9-]+|CNVD-\d+-\d+)\s+\d+\.\d+')

    cve_info_list = []
    for line in scan_result.splitlines():
        matches = cve_pattern.findall(line)
        cve_info_list.extend(matches)

    return cve_info_list


def write_cve_to_file(ipaddr, cve_list):
    filename = os.path.join("scan result", f"{ipaddr}.txt")
    with open(filename, 'w') as file:
        file.write(f"Detected vulnerabilities for {ipaddr}:\n\n")
        for cve in cve_list:
            file.write(f"CVE: {cve}\n")
    logging.info(f"Detected vulnerabilities for {ipaddr} written to {filename}")


def send_cve_to_chatgpt(cves, ipaddr):
    logging.info(f"Sending CVEs to ChatGPT for {ipaddr}")
    create_a_pdf_gpt(cve_list=cves, chatgpt=chatgpt, filename=f"gpt_{ipaddr}")
    write_cve_to_file(ipaddr, cves)


def scan_for_vuln(target_host):
    logging.info(f"Scanning for vulnerabilities on {target_host}")
    try:
        scan_result = nmap_scanner.scan_for_vulnerabilities(target_host)
    except Exception as e:
        logging.error(f"Error during scanning for {target_host}: {str(e)}")
        raise Exception("Request took too long or issues")

    # Use the scan_result directly in your code
    cve_info_list = extract_cve_info(scan_result)
    logging.info(f"Vulnerabilities found on {target_host}: {cve_info_list}")
    return target_host, cve_info_list


def bard_api(cve_list, ipScanner="default"):
    logging.info(f"Sending CVEs to Bard API for {ipScanner}")
    create_a_pdf_bard(cve_list, filename=f"bard_{ipScanner}")
    write_cve_to_file(ipScanner, cve_list)


def create_a_pdf_bard(cve_list, filename="default"):
    token = "dQjVcFu3wDRvECej3fR1gSi8W3F_dQB4f9P8j1DmEyakTwHg9WuLuEBn0dXPM4OuUCsT5A."
    session = requests.Session()
    session.headers = SESSION_HEADERS
    session.cookies.set("__Secure-1PSID", token)
    bard = Bard(token=token, session=session)

    filename = os.path.join("bard", filename)
    pdf_file = filename + ".pdf"

    doc = SimpleDocTemplate(pdf_file, pagesize=letter)
    elements = []

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(name='TitleStyle', fontSize=16, alignment=1, textColor=colors.blue)
    title = Paragraph("Bard API Query Result", title_style)
    elements.append(title)

    subtitle_style = ParagraphStyle(name='SubtitleStyle', fontSize=12, alignment=1, textColor=colors.darkblue)
    subtitle = Paragraph("Query and Result", subtitle_style)
    elements.append(subtitle)

    elements.append(Spacer(1, 12))

    for cve in cve_list:
        cve = cve.strip()
        start = time.time()
        query = f"Hey Bard !!! Give me one line fix to the vulnerability ({cve})"
        result = bard.get_answer(query)['content']
        end = time.time()
        time_taken = (end - start)
        response_time_bard.append(time_taken)
        logging.info(f"Query to Bard API for {cve}: {query}")
        logging.info(f"Response from Bard API for {cve}: {result}")
        logging.info(f"Time taken for Bard API response: {time_taken} seconds")

        print(result)
        time.sleep(20)

        query_style = ParagraphStyle(name='QueryStyle', fontSize=12, textColor=colors.black)
        query_text = f"<b>Query:</b><br/>{query}<br/><br/>"
        query_paragraph = Paragraph(query_text, query_style)
        elements.append(query_paragraph)

        result_style = ParagraphStyle(name='ResultStyle', fontSize=12, textColor=colors.black)
        result_text = "<b>Result:</b><br/>" + result.replace('\n', '<br/>') + "<br/>"
        result_paragraph = Paragraph(result_text, result_style)
        elements.append(result_paragraph)

        elements.append(Spacer(1, 12))

    doc.build(elements)


def create_a_pdf_gpt(cve_list, chatgpt=chatgpt, filename="default"):
    filename = os.path.join("gpt", filename)
    pdf_file = filename + ".pdf"

    doc = SimpleDocTemplate(pdf_file, pagesize=letter)
    elements = []

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(name='TitleStyle', fontSize=16, alignment=1, textColor=colors.blue)
    title = Paragraph("ChatGPT API Query Result", title_style)
    elements.append(title)

    subtitle_style = ParagraphStyle(name='SubtitleStyle', fontSize=12, alignment=1, textColor=colors.darkblue)
    subtitle = Paragraph("Query and Result", subtitle_style)
    elements.append(subtitle)

    elements.append(Spacer(1, 12))

    for cve in cve_list:
        cve = cve.strip()
        try:
            start = time.time()
            query = f"Hey ChatGPT !!! Give me step by step instructions to fix the vulnerability ({cve})"
            result = chatgpt.get_fix_for_vulnerability(cve, [])
            end = time.time()
            response_time_gpt.append(end - start)
            logging.info(f"Query to ChatGPT for {cve}: {query}")
            logging.info(f"Response from ChatGPT for {cve}: {result}")
            logging.info(f"Time taken for ChatGPT response: {end - start} seconds")

            # Extract solution link (hypothetical code - adjust based on the actual response structure)
            solution_link = result.get("solution_link", "")

        except Exception as e:
            logging.error(f"Error processing CVE {cve}: {str(e)}")

        query_style = ParagraphStyle(name='QueryStyle', fontSize=12, textColor=colors.black)
        query_text = f"<b>Query:</b><br/>{query}<br/><br/>"
        query_paragraph = Paragraph(query_text, query_style)
        elements.append(query_paragraph)

        result_style = ParagraphStyle(name='ResultStyle', fontSize=12, textColor=colors.black)
        result_text = "<b>Result:</b><br/>" + result.replace('\n', '<br/>') + "<br/>"
        result_paragraph = Paragraph(result_text, result_style)
        elements.append(result_paragraph)

        elements.append(Spacer(1, 12))

    doc.build(elements)


def plot_vs_graph():
    plt.plot(response_time_gpt, 'g*', label='ChatGPT')
    plt.plot(response_time_bard, 'ro', label='Google Bard')
    plt.xlabel('Query Index')
    plt.ylabel('Time Taken (seconds)')
    plt.legend()
    plt.show()


if __name__ == "__main__":
    cves = []
    ips = []

    # Prompt the user to input four IP addresses
    ips = [input("Enter IP 1: "), input("Enter IP 2: "), input("Enter IP 3: "), input("Enter IP 4: ")]

    print("Scanning IPs:", ips)

    for i in range(len(ips)):
        try:
            target_ip, cve_info_list = scan_for_vuln(ips[i])
            write_cve_to_file(target_ip, cve_info_list)
            t1 = threading.Thread(target=send_cve_to_chatgpt, args=(cve_info_list, target_ip))
            t2 = threading.Thread(target=bard_api, args=(cve_info_list, target_ip))
            t2.start()
            t1.start()
        except:
            logging.error(f"Error while performing the scan for {ips[i]}")

    # Wait for threads to finish
    t1.join()
    t2.join()

    plot_vs_graph()
