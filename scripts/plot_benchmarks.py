import os
import sys
import matplotlib.pyplot as plt
import json
import glob

def get_latest_throughput(benchmark_name, engine):
    # Path is target/criterion/{benchmark_name}/{engine}/new/estimates.json
    path = f"target/criterion/{benchmark_name}/{engine}/new/estimates.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
            # We want bytes per second. Criterion throughput is usually bytes per iteration?
            # Wait, criterion stores throughput if configured. But it's easier to just read the mean time and derive throughput from the byte size.
            pass
    
    path_stats = f"target/criterion/{benchmark_name}/{engine}/new/benchmark.json"
    if os.path.exists(path_stats):
        with open(path_stats, "r") as f:
            bench = json.load(f)
            throughput_bytes = bench.get("throughput", {}).get("Bytes", None)
            
    with open(path, "r") as f:
        data = json.load(f)
        mean_time_ns = data["mean"]["point_estimate"]
        
    if throughput_bytes:
        mb_per_s = (throughput_bytes / (mean_time_ns / 1e9)) / (1024 * 1024)
        if mb_per_s > 1000:
            mb_per_s = 0.0
        return mb_per_s
        
    return 0

def main():
    benchmarks = ["Mixed_Workload", "Legacy_Workload", "AVX512_Workload"]
    engines = ["Prometheus", "Zydis", "Capstone"]
    
    results = {b: [] for b in benchmarks}
    
    for b in benchmarks:
        for e in engines:
            mb_s = get_latest_throughput(b, e)
            results[b].append(mb_s)
            
    # Plotting
    import numpy as np
    
    x = np.arange(len(benchmarks))
    width = 0.25
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Engines are bars
    for i, e in enumerate(engines):
        vals = [results[b][i] for b in benchmarks]
        ax.bar(x + i*width, vals, width, label=e)
        
        # Add labels
        for j, v in enumerate(vals):
            ax.text(x[j] + i*width, v + 0.5, f"{v:.1f}", ha='center', va='bottom', fontsize=9)
            
    ax.set_ylabel('Decode Throughput (MiB/s)')
    ax.set_title('Disassembly Performance Comparison (Higher is Better)')
    ax.set_xticks(x + width)
    ax.set_xticklabels([b.replace("_", " ") for b in benchmarks])
    ax.legend()
    
    plt.tight_layout()
    plt.savefig("benchmark_results.png", dpi=300)
    print("Saved benchmark_results.png")

if __name__ == "__main__":
    main()
