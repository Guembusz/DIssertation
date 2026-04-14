import time
import statistics
from analyzer import analyze_qr_data


def run_multi_benchmark(iterations: int = 30):
    # The 3 Execution Paths being tested
    test_cases = {
        "Best-Case (Safe URL)": "https://www.bbc.co.uk",
        "Mid-Case (DGA Threat)": "https://www.secure-login.com/x8f92j3b9a8f7d6c5e4f3a2b1c0d9e8f7a6b5c4d3",
        "Worst-Case (Obfuscated API Threat)": "https://bit.ly/3xZqy8v"
    }

    print(f"Starting Multi-Path Benchmark: {iterations} iterations per payload...\n")
    print("-" * 60)

    results_summary = {}

    for case_name, url in test_cases.items():
        execution_times = []

        # Verify functionality on the very first run of this category
        first_result = analyze_qr_data(url)
        print(f"Testing: {case_name}")
        print(f"Target : {url}")
        print(f"Result : {first_result.level.name} ({first_result.message})\n")

        # Run the 30 iterations
        for i in range(iterations):
            start_time = time.perf_counter()
            analyze_qr_data(url)  # Discard the output, we only care about speed
            end_time = time.perf_counter()

            execution_times.append((end_time - start_time) * 1000)

        # Calculate statistics
        results_summary[case_name] = {
            "Min": min(execution_times),
            "Max": max(execution_times),
            "Mean": statistics.mean(execution_times)
        }
        print("-" * 60)

    # Print the Final Academic Table
    print("\nFINAL EXECUTION PATH BENCHMARKS")
    print(f"{'Payload Category':<35} | {'Min (ms)':<8} | {'Max (ms)':<8} | {'Mean (ms)':<8}")
    print("=" * 66)
    for name, stats in results_summary.items():
        print(f"{name:<35} | {stats['Min']:<8.2f} | {stats['Max']:<8.2f} | {stats['Mean']:<8.2f}")
    print("=" * 66)


if __name__ == "__main__":
    run_multi_benchmark(30)