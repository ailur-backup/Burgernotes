import time
import subprocess

def run_init_db():
    # Run the init_db.py script using subprocess
    try:
        subprocess.run(["python", "init_db"])
    except Exception as e:
        print("Error:", e)

def main():
    while True:
        # Run init_db.py
        run_init_db()
        
        # Wait for 5 minutes before running again
        time.sleep(300)  # 300 seconds = 5 minutes

if __name__ == "__main__":
    main()
