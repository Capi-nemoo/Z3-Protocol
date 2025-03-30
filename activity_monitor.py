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

high_risk_file_path = os.path.join(base_dir, "Z3-Protocol", "high_risk_processes.json")
if os.path.exists(high_risk_file_path):
    print(f"✅ Found high-risk processes file at: {high_risk_file_path}")
try:
    if os.path.exists(high_risk_file_path):
        with open(high_risk_file_path, "r") as file:
            data = json.load(file)
            high_risk_processes = data.get("high_risk_processes", [])
        print(f"✅ Loaded {len(high_risk_processes)} high-risk processes")
    else:
        raise FileNotFoundError("Could not find high_risk_processes.json")
except Exception as e:
    print(f"⚠️ {e} — using empty list.")
    high_risk_processes = []

def get_process_info(proc):
    try:
        p = psutil.Process(proc.pid)
        p.cpu_percent()
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
        ps_output = subprocess.run(["ps", "-arcwwwxo", "pid,%cpu,command"], capture_output=True, text=True).stdout
        ps_lines = ps_output.strip().split('\n')
        with open("results.txt") as results_file:
            results_data = results_file.readlines()
        print("\n🔍 Comparing with ps output:")
        for line in results_data:
            if "Process Name:" in line:
                name = line.split(":")[1].strip()
                pid_line_idx = results_data.index(line) + 1
                if pid_line_idx < len(results_data) and "PID:" in results_data[pid_line_idx]:
                    pid = results_data[pid_line_idx].split(":")[1].strip()
                    match = next((l for l in ps_lines if l.strip().startswith(pid + " ")), None)
                    if match:
                        parts = match.strip().split(None, 2)
                        cpu_info = f" - PS shows CPU: {parts[1]}%" if len(parts) > 1 else ""
                        print(f"✅ Found in ps by PID: {name}{cpu_info}")
                    else:
                        match = next((l for l in ps_lines if name.lower() in l.lower()), None)
                        if match:
                            parts = match.strip().split(None, 2)
                            cpu_info = f" - PS shows CPU: {parts[1]}%" if len(parts) > 1 else ""
                            print(f"✅ Found in ps by name: {name}{cpu_info}")
                        else:
                            print(f"❓ Not found in ps: {name}")
    except Exception as e:
        print(f"❌ Error comparing with ps: {e}")

def check_with_gemma(process_list):
    if not process_list:
        print("⚠️ No processes to analyze with Gemma.")
        return

    prompt_lines = ["Classify each process below as 'normal' or 'issue'. Provide a short reason and include CPU usage:"]
    for proc in process_list:
        prompt_lines.append(f"Name: {proc['name']}, PID: {proc['pid']}, CPU: {proc['cpu_usage']}%, CMD: {proc['cmdline']}")
    prompt_lines.append("Name: chrome, PID: 9999, CPU: 3.2%, CMD: /Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    prompt = '\n'.join(prompt_lines)

    try:
        print("🤖 Asking Gemma to analyze processes...")
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={
                "model": "gemma3",
                "prompt": prompt,
                "stream": False
            }
        )
        if response.status_code == 200:
            reply = response.json()["response"]
            print("\n🧠 Gemma's Classification:\n")
            print(reply.strip())
        else:
            print(f"❌ Gemma response error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"❌ Failed to connect to Gemma: {e}")

def main():
    print(f"🚀 Starting high-CPU process check (Threshold: {cpu_threshold}%)...")
    processes_info = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            p = psutil.Process(proc.pid)
            p.cpu_percent()
            processes_info.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    top_processes = {}
    try:
        ps_output = subprocess.run(["ps", "-arcwwwxo", "pid,%cpu,command"], capture_output=True, text=True).stdout
        lines = ps_output.strip().split('\n')
        for i, line in enumerate(lines):
            if i == 0:
                continue
            parts = line.strip().split(None, 2)
            if len(parts) >= 3 and parts[0].isdigit():
                try:
                    pid = int(parts[0])
                    cpu = float(parts[1])
                    name = parts[2].split()[0].split('/')[-1]
                    top_processes[pid] = {'name': name, 'cpu': cpu}
                    top_processes[pid]['cmdline'] = parts[2]
                except (ValueError, IndexError):
                    pass
    except Exception as e:
        print(f"⚠️ Could not get PS data: {e}")

    print(f"📊 Monitoring {len(processes_info)} processes...")
    time.sleep(0.5)

    results = []
    high_cpu_count = 0

    for p in processes_info:
        try:
            pid = p.pid
            if pid in top_processes:
                cpu_usage = top_processes[pid]['cpu']
                if p.name() == "" or p.name() is None:
                    try:
                        name = top_processes[pid]['name']
                    except:
                        pass
            else:
                cpu_usage = p.cpu_percent()

            if cpu_usage < cpu_threshold:
                continue

            high_cpu_count += 1
            try:
                name = p.name()
                cmdline = ' '.join(p.cmdline()) if p.cmdline() else ''
                memory_percent = p.memory_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            info = {
                'name': name,
                'pid': pid,
                'cmdline': cmdline,
                'cpu_usage': cpu_usage,
                'memory_percent': memory_percent
            }

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
        check_with_gemma(results)
    else:
        print(f"✅ No high-CPU processes detected above {cpu_threshold}% threshold.")

if __name__ == "__main__":
    main()