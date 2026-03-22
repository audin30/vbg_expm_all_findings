import subprocess
import sys
import logging
import time

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("sync_all.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def run_script(script_name):
    """Runs a python script and logs its output."""
    logger.info(f"--- Starting {script_name} ---")
    start_time = time.time()
    try:
        # Using sys.executable to ensure we use the same python interpreter
        result = subprocess.run([sys.executable, script_name], check=True, capture_output=False)
        duration = time.time() - start_time
        logger.info(f"--- Finished {script_name} successfully in {duration:.2f}s ---")
        return True
    except subprocess.CalledProcessError as e:
        duration = time.time() - start_time
        logger.error(f"--- Error running {script_name} (Failed after {duration:.2f}s) ---")
        logger.error(f"Exit code: {e.returncode}")
        return False
    except Exception as e:
        logger.error(f"--- Unexpected error running {script_name}: {e} ---")
        return False

def main():
    scripts = [
        "cisa_kev_sync.py",
        "tenable_sync.py",
        "tenable_asm_sync.py",
        "wiz_sync.py"
    ]
    
    logger.info("Starting Master Sync Process...")
    overall_start_time = time.time()
    
    results = {}
    for script in scripts:
        success = run_script(script)
        results[script] = "SUCCESS" if success else "FAILED"
    
    overall_duration = time.time() - overall_start_time
    logger.info("=== Sync Summary ===")
    for script, status in results.items():
        logger.info(f"{script}: {status}")
    logger.info(f"Total duration: {overall_duration:.2f}s")
    logger.info("====================")

if __name__ == "__main__":
    main()
