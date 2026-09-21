import os
import sys
import subprocess
import time

def kill_port(port):
    try:
        # Mac/Linux cross-platform port killing
        cmd = f"lsof -ti:{port} | xargs kill -9"
        subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(1)
    except:
        pass

if __name__ == "__main__":
    print("--- Starting DESAS Investigation Workstation ---")
    
    # 1. Kill potentially stuck processes on port 8675
    kill_port(8675)
    
    # 2. Set PYTHONPATH
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.environ["PYTHONPATH"] = project_root
    
    # 3. Launch App
    print("Launching backend...")
    try:
        subprocess.run([sys.executable, "app/eel_main.py"])
    except KeyboardInterrupt:
        print("\nWorkstation stopped.")
