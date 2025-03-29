#!/usr/bin/env python3
"""
Merged Activity Monitor, CVE Scanner, and Suspicious Activity Reporter using Gemma3 with Ulamma

This script performs one round of system monitoring:
  - Checks CPU, memory, and disk usage.
  - Scans for high-risk processes using a JSON file.
  - Retrieves CVE details using an external API.
  - Uses Gemma3 (with Ulamma) to analyze the results and report if any activity is suspicious.

File paths:
  - High-risk process list is expected at "Z3-Protocol/high_risk_processes.json"
  
Required packages are specified in requirements.txt (psutil, requests).
"""

import psutil
import requests
import json
import logging
import os

# --------------------------------------------------------------------
# Logging Configuration
# --------------------------------------------------------------------
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# --------------------------------------------------------------------
# Global Configurations and Thresholds
# --------------------------------------------------------------------
HIGH_RISK_FILE_PATH = "high_risk_processes.json"
CPU_THRESHOLD = 80       # CPU usage percentage threshold
MEMORY_THRESHOLD = 80    # Memory usage percentage threshold
DISK_THRESHOLD = 90      # Disk usage percentage threshold
CVE_TO_SCAN = "CVE-2021-44228"  # Example CVE for scanning

# --------------------------------------------------------------------
# Function: Load High-Risk Processes
# --------------------------------------------------------------------
def load_high_risk_processes(filepath=HIGH_RISK_FILE_PATH):
    """
    Loads the list of high-risk processes from a JSON file.
    """
    logging.info(f"Loading high-risk processes from '{filepath}'...")
    try:
        with open(filepath, 'r') as file:
            data = json.load(file)
        processes = data.get("high_risk_processes", [])
        logging.info(f"Loaded {len(processes)} high-risk process names.")
        return processes
    except Exception as e:
        logging.error(f"Error loading high-risk processes: {e}")
        return []

# --------------------------------------------------------------------
# Function: CPU Usage Scanner
# --------------------------------------------------------------------
def scan_cpu_usage(threshold=CPU_THRESHOLD):
    """
    Scans current CPU usage and logs a warning if it exceeds threshold.
    """
    cpu_usage = psutil.cpu_percent(interval=1)
    logging.info(f"Current CPU usage: {cpu_usage}%")
    if cpu_usage > threshold:
        logging.warning(f"High CPU usage: {cpu_usage}% (Threshold: {threshold}%)")
    return cpu_usage

# --------------------------------------------------------------------
# Function: Memory Usage Scanner
# --------------------------------------------------------------------
def scan_memory_usage(threshold=MEMORY_THRESHOLD):
    """
    Scans current memory usage and logs a warning if it exceeds threshold.
    """
    mem = psutil.virtual_memory()
    memory_usage = mem.percent
    logging.info(f"Current Memory usage: {memory_usage}%")
    if memory_usage > threshold:
        logging.warning(f"High Memory usage: {memory_usage}% (Threshold: {threshold}%)")
    return memory_usage

# --------------------------------------------------------------------
# Function: Disk Usage Scanner
# --------------------------------------------------------------------
def scan_disk_usage(threshold=DISK_THRESHOLD, path="/"):
    """
    Scans disk usage for the specified path and logs a warning if it exceeds the threshold.
    """
    try:
        disk = psutil.disk_usage(path)
        disk_usage = disk.percent
        logging.info(f"Current Disk usage on '{path}': {disk_usage}%")
        if disk_usage > threshold:
            logging.warning(f"High Disk usage: {disk_usage}% (Threshold: {threshold}%)")
        return disk_usage
    except Exception as e:
        logging.error(f"Error scanning disk usage on '{path}': {e}")
        return None

# --------------------------------------------------------------------
# Function: Process Scanner
# --------------------------------------------------------------------
def scan_processes(high_risk_list):
    """
    Scans running processes for names that match those in the high-risk list.
    """
    logging.info("Scanning for high-risk processes...")
    found_processes = []
    high_risk_set = {proc.lower() for proc in high_risk_list}
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            proc_name = proc.info['name']
            if proc_name and proc_name.lower() in high_risk_set:
                info = (proc.info['pid'], proc_name, proc.info.get('username', 'N/A'))
                logging.warning(f"High-risk process detected: PID={info[0]}, Name={info[1]}, User={info[2]}")
                found_processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    logging.info(f"Total high-risk processes found: {len(found_processes)}")
    return found_processes

# --------------------------------------------------------------------
# Function: CVE Scanner
# --------------------------------------------------------------------
def scan_cve(cve_id=CVE_TO_SCAN):
    """
    Scans and retrieves details of a specified CVE using an external API.
    """
    logging.info(f"Scanning for CVE details for '{cve_id}'...")
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            cve_data = response.json()
            summary = cve_data.get("summary", "No summary available")
            logging.info(f"CVE {cve_id} summary: {summary}")
            return cve_data
        else:
            logging.error(f"Failed to fetch CVE details for {cve_id}. Status code: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Exception while fetching CVE details for {cve_id}: {e}")
        return None

# --------------------------------------------------------------------
# Function: Gemma3 and Ulamma Analysis
# --------------------------------------------------------------------
def ulamma(value, threshold, metric_name):
    """
    Ulamma evaluates a numeric metric against its threshold.
    """
    if value is None:
        return None
    if value > threshold:
        return f"Suspicious {metric_name}: {value}% exceeds threshold {threshold}%."
    return None

def gemma3(cpu_usage, memory_usage, disk_usage, processes_found, cve_data):
    """
    Gemma3 aggregates scan results and uses Ulamma to analyze them.
    Returns a list of suspicious activity report messages.
    """
    report = []
    cpu_report = ulamma(cpu_usage, CPU_THRESHOLD, "CPU usage")
    if cpu_report:
        report.append(cpu_report)
    mem_report = ulamma(memory_usage, MEMORY_THRESHOLD, "Memory usage")
    if mem_report:
        report.append(mem_report)
    disk_report = ulamma(disk_usage, DISK_THRESHOLD, "Disk usage")
    if disk_report:
        report.append(disk_report)
    if processes_found:
        report.append(f"Suspicious: {len(processes_found)} high-risk process(es) detected.")
    if cve_data:
        summary = cve_data.get("summary", "")
        if summary:
            report.append(f"CVE {CVE_TO_SCAN} reported: {summary}")
    return report

def report_suspicious_activity(report):
    """
    Reports suspicious activity if any is found.
    """
    if report:
        logging.warning("Suspicious activity detected:")
        for item in report:
            logging.warning(item)
    else:
        logging.info("No suspicious activity detected.")

# --------------------------------------------------------------------
# Main Function (Single Cycle)
# --------------------------------------------------------------------
def main():
    """
    Runs one cycle of system monitoring and analysis.
    """
    logging.info("Starting system activity monitor, CVE scanner, and suspicious activity analysis (one cycle)...")
    
    # Load high-risk processes.
    high_risk_list = load_high_risk_processes()
    
    # Perform one cycle of scans.
    cpu_usage = scan_cpu_usage()
    memory_usage = scan_memory_usage()
    disk_usage = scan_disk_usage()
    processes_found = scan_processes(high_risk_list)
    cve_data = scan_cve()
    
    # Analyze the results using Gemma3 with Ulamma.
    suspicious_report = gemma3(cpu_usage, memory_usage, disk_usage, processes_found, cve_data)
    report_suspicious_activity(suspicious_report)
    
    logging.info("Monitoring cycle completed.")

if __name__ == "__main__":
    main()