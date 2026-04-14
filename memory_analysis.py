import tracemalloc
from analyzer import analyze_qr_data


def run_memory_profile():
    print("Starting Memory Profiler...")

    # 1. Start tracking RAM usage
    tracemalloc.start()

    # 2. Record the 'Baseline' memory (Idle state)
    current_idle, peak_idle = tracemalloc.get_traced_memory()
    idle_mb = current_idle / 10 ** 6
    print(f"[BASELINE] Idle Memory Usage: {idle_mb:.2f} MB")

    # 3. Execute the 'Worst-Case' payload to force all threads to spin up
    print("Executing concurrent threat analysis...")
    worst_case_payload = "https://bit.ly/3xZqy8v"
    result = analyze_qr_data(worst_case_payload)

    # 4. Record the 'Peak' memory during execution
    current_exec, peak_exec = tracemalloc.get_traced_memory()
    peak_mb = peak_exec / 10 ** 6
    print(f"[PEAK] Maximum Memory Allocated: {peak_mb:.2f} MB")

    # 5. Stop tracking and force Garbage Collection
    tracemalloc.stop()

    # Calculate the variance (The GC drop)
    variance = peak_mb - idle_mb
    print("-" * 40)
    print(f"Memory Variance (Thread Overhead): {variance:.2f} MB")
    print(f"Final Threat Result: {result.status}")


if __name__ == "__main__":
    # Hide the standard logging so the terminal is clean
    import logging

    logging.getLogger("QRSecurityEngine").setLevel(logging.CRITICAL)

    run_memory_profile()