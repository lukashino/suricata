#!/usr/bin/env python3
"""
plot-fpga-errbars.py

This script reads a CSV file containing benchmarking results and generates a boxplot
(with error bars) of the elapsed time distribution for each variant (eval vs baseline).

Usage: ./plot-fpga-errbars.py <csv_file>
"""
import sys
import pandas as pd
import matplotlib.pyplot as plt

if len(sys.argv) != 2:
    print("Usage: {} <csv_file>".format(sys.argv[0]))
    sys.exit(1)

csv_file = sys.argv[1]
df = pd.read_csv(csv_file)

# Ensure the 'Elapsed_Time' column is float.
df['Elapsed_Time'] = pd.to_numeric(df['Elapsed_Time'], errors='coerce')

# Create a boxplot for elapsed time grouped by variant.
fig, ax = plt.subplots(figsize=(8, 6))

data = []
labels = []
for variant in df['Variant'].unique():
    variant_data = df[df['Variant'] == variant]['Elapsed_Time'].dropna()
    data.append(variant_data)
    labels.append(variant)

ax.boxplot(data, showmeans=True, meanline=True)
ax.set_xticklabels(labels)
ax.set_ylabel("Elapsed Time (seconds)")
ax.set_title(f"Elapsed Time Distribution for {csv_file}")

# Add error bars using the standard deviation.
for i, variant in enumerate(labels):
    variant_data = df[df['Variant'] == variant]['Elapsed_Time'].dropna()
    mean = variant_data.mean()
    std = variant_data.std()
    ax.errorbar(i+1, mean, yerr=std, fmt='o', color='red', capsize=5)

plt.tight_layout()
plt.savefig(f"{csv_file}.png")
plt.show()
