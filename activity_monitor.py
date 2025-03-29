import os
import psutil
import json
import requests
import time
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor

cpu_threshold = 5

script_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.dirname(script_dir)

possible_paths = [
    os.path.join(script_dir, "high_risk_processes.json"),
    os.path.join(base_dir, "scsp-agi", "high_risk_processes.json"),
    "scsp-agi/high_risk_processes.json"
]

high_risk_file_path = next((p for p in possible_paths if os.path.exists(p)), None)
if high_risk_file_path:
    print(f"✅ Found high-risk processes file at: {high_risk_file_path}")
try:
    if high_risk_file_path:
        with open(high_risk_file_path, "r") as file:
            data = json.load(file)
            high_risk_processes = data.get("high_risk_processes", [])
        print(f"✅ Loaded {len(high_risk_processes)} high-risk processes")
    else:
        raise FileNotFoundError("Could not find high_risk_processes.json")
except Exception as e:
    print(f"⚠️ {e} — using default list.")
    high_risk_processes = [
        "svchost.exe", "cmd.exe", "powershell.exe", "wmic.exe", "rundll32.exe", 
        "mimikatz.exe", "osascript", "bash", "python", "ruby", "perl", 
        "ssh", "curl", "wget", "netcat", "nc", "ftp", "chrome", "firefox", 
        "chatgpt", "openai"
    ]

# Gemma integration removed

def get_process_info(proc):
    try:
        p = psutil.Process(proc.pid)
        
        # Non-blocking CPU measurement (first call just initializes it)
        p.cpu_percent()
        
        # Get command line and other details
        try:
            name = p.name().lower() if p.name() else ''
            cmdline = ' '.join(p.cmdline()).lower() if p.cmdline() else ''
            memory_percent = p.memory_percent()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
            
        return {
            'name': name,
            'pid': p.pid,
            'cmdline': cmdline,
            'memory_percent': memory_percent
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def save_results(results):
    with open("results.txt", "w") as file:
        file.write("Detected High-CPU Processes:\n")
        for r in results:
            file.write(f"\nProcess Name: {r['name']}\nPID: {r['pid']}\nCPU Usage: {r['cpu_usage']}%\n")
            file.write(f"Memory Usage: {r['memory_percent']}%\nCommand Line: {r['cmdline']}\n")
            file.write("-" * 60 + "\n")
    print("✅ Results saved to results.txt")

def run_top_comparison():
    try:
        # Save both top and ps output for comparison
        top_result = subprocess.run(["top", "-l", "1", "-stats", "pid,command,cpu,state"], capture_output=True, text=True, check=True)
        ps_result = subprocess.run(["ps", "-arcwwwxo", "pid,%cpu,command"], capture_output=True, text=True, check=True)
        
        with open("top_output.txt", "w") as f:
            f.write(top_result.stdout)
            
        with open("ps_output.txt", "w") as f:
            f.write(ps_result.stdout)
            
        print("✅ Process monitoring output saved to files")
    except Exception as e:
        print(f"❌ Could not run process monitoring commands: {e}")

def compare_with_top():
    try:
        # Use ps output for comparison instead of top
        ps_output = subprocess.run(["ps", "-arcwwwxo", "pid,%cpu,command"], capture_output=True, text=True).stdout
        ps_lines = ps_output.strip().split('\n')
        
        with open("results.txt") as results_file:
            results_data = results_file.readlines()

        print("\n🔍 Comparing with ps output:")
        for line in results_data:
            if "Process Name:" in line:
                name = line.split(":")[1].strip()
                # Extract pid from the next line
                pid_line_idx = results_data.index(line) + 1
                if pid_line_idx < len(results_data) and "PID:" in results_data[pid_line_idx]:
                    pid = results_data[pid_line_idx].split(":")[1].strip()
                    # Look for matching process by PID first
                    match = next((l for l in ps_lines if l.strip().startswith(pid + " ")), None)
                    if match:
                        parts = match.strip().split(None, 2)
                        cpu_info = f" - PS shows CPU: {parts[1]}%" if len(parts) > 1 else ""
                        print(f"✅ Found in ps by PID: {name}{cpu_info}")
                    else:
                        # Try to find by name if PID not found
                        match = next((l for l in ps_lines if name.lower() in l.lower()), None)
                        if match:
                            parts = match.strip().split(None, 2)
                            cpu_info = f" - PS shows CPU: {parts[1]}%" if len(parts) > 1 else ""
                            print(f"✅ Found in ps by name: {name}{cpu_info}")
                        else:
                            print(f"❓ Not found in ps: {name}")
    except Exception as e:
        print(f"❌ Error comparing with ps: {e}")

def main():
    print(f"🚀 Starting high-CPU process check (Threshold: {cpu_threshold}%)...")
    
    # First pass: collect all processes and initialize CPU monitoring
    processes_info = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            p = psutil.Process(proc.pid)
            # Initialize CPU monitoring (first call just initializes it)
            p.cpu_percent()
            processes_info.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
            
    # Run ps command to get more accurate system-wide CPU usage
    # This is similar to what Activity Monitor uses
    top_processes = {}
    try:
        # Use ps with custom format to get CPU usage similar to Activity Monitor
        ps_output = subprocess.run(["ps", "-arcwwwxo", "pid,%cpu,command"], capture_output=True, text=True).stdout
        lines = ps_output.strip().split('\n')
        for i, line in enumerate(lines):
            if i == 0:  # Skip header
                continue
            parts = line.strip().split(None, 2)  # Split on whitespace, max 3 parts
            if len(parts) >= 3 and parts[0].isdigit():
                try:
                    pid = int(parts[0])
                    cpu = float(parts[1])  # %CPU column
                    name = parts[2].split()[0].split('/')[-1]  # Extract process name
                    top_processes[pid] = {'name': name, 'cpu': cpu}
                    # Store the full command line separately
                    top_processes[pid]['cmdline'] = parts[2]
                except (ValueError, IndexError) as e:
                    pass
    except Exception as e:
        print(f"⚠️ Could not get PS data: {e}")
    
    print(f"📊 Monitoring {len(processes_info)} processes...")
    
    # Wait a short time for CPU measurement to be meaningful
    time.sleep(0.5)
    
    # Second pass: check CPU usage and collect info for high-CPU processes
    results = []
    high_cpu_count = 0
    
    for p in processes_info:
        try:
            pid = p.pid
            
            # Try to get a more accurate CPU % from the ps command for all processes
            if pid in top_processes:
                cpu_usage = top_processes[pid]['cpu']
                # For processes not showing up properly in psutil, use the name from ps
                if p.name() == "" or p.name() is None:
                    try:
                        name = top_processes[pid]['name']
                    except:
                        pass
            else:
                # Fall back to psutil for processes not found in ps
                cpu_usage = p.cpu_percent()
            
            # Skip if below threshold
            if cpu_usage < cpu_threshold:
                continue
                
            high_cpu_count += 1
            
            # Get process details
            try:
                name = p.name()
                cmdline = ' '.join(p.cmdline()) if p.cmdline() else ''
                memory_percent = p.memory_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
            # Create process info dictionary
            info = {
                'name': name,
                'pid': pid,
                'cmdline': cmdline,
                'cpu_usage': cpu_usage,
                'memory_percent': memory_percent
            }
            
            # Improved detection for high-risk processes to better handle process names with parentheses
            is_risky = False
            for risk in high_risk_processes:
                if risk.lower() in name.lower() or name.lower() in risk.lower():
                    is_risky = True
                    break
                    
            if is_risky:
                print(f"\n⚠️ Suspicious High-CPU Process: {name} (PID: {pid}) - CPU: {cpu_usage:.1f}%")
            else:
                print(f"\nℹ️ High-CPU Process: {name} (PID: {pid}) - CPU: {cpu_usage:.1f}%")
                
            results.append(info)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    print(f"\n📈 Processes checked: {len(processes_info)}, High-CPU processes detected: {high_cpu_count}")

    if results:
        save_results(results)
        run_top_comparison()
        compare_with_top()
    else:
        print(f"✅ No high-CPU processes detected above {cpu_threshold}% threshold.")

if __name__ == "__main__":
    main()