import subprocess
import logging

def scan_for_vulnerabilities(target_host):
    # Configure logging
    logging.basicConfig(filename="logs/scan.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    try:
        # Construct the Nmap command
        nmap_command = ["nmap", "-sV", "--script", "vuln", target_host]

        # Run Nmap scan
        scan_result = subprocess.check_output(nmap_command, universal_newlines=True, stderr=subprocess.STDOUT)

        return scan_result

    except subprocess.CalledProcessError as e:
        logging.error(f"Error in Nmap scan: {e.output}")
        return "Nmap scan failed."

if __name__ == "__main__":
    target_host = input("Enter the target host or IP address: ")
    scan_result = scan_for_vulnerabilities(target_host)
    print(scan_result)
