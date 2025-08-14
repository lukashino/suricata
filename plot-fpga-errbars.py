#!/usr/bin/env python3
"""
plot-fpga-errbars.py

This script reads a CSV file containing benchmarking results and generates a single, color-coded
boxplot figure covering all Offload & HS_Pattern_IDs combinations—comparing variants side-by-side—
with granular Y‑ticks and soft grid guidelines to improve readability. Saves as a wide PDF.

Usage: ./plot-fpga-errbars.py <csv_file>
"""
import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib.patches as mpatches

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <csv_file>")
    sys.exit(1)

csv_file = sys.argv[1]
if not os.path.isfile(csv_file):
    print(f"Error: file '{csv_file}' not found.")
    sys.exit(1)

# Read and clean data
df = pd.read_csv(csv_file)
df['Elapsed_Time'] = pd.to_numeric(df['Elapsed_Time'], errors='coerce')
deficit = df[['Variant', 'Offload', 'HS_Pattern_IDs', 'Elapsed_Time']].dropna()

# Human-readable mappings
variant_map = {'eval': 'FPGA', 'baseline': 'Suri'}
offload_map = {'pktpayload': 'Payload', 'pktpayload-stream': 'Payload&Stream'}
# Colors per variant
type_colors = {'eval': '#4C72B0', 'baseline': '#55A868'}  # blue & green

# Unique variants and combos
variants = sorted(deficit['Variant'].unique())
combos = sorted(deficit[['Offload', 'HS_Pattern_IDs']]
                .drop_duplicates().values.tolist(), key=lambda x: (x[0], int(x[1])))

# Collect boxplot data & positions
data = []
positions = []
labels = []
n_vars = len(variants)

for i, (offload, pats) in enumerate(combos):
    for j, variant in enumerate(variants):
        series = deficit[(deficit['Offload']==offload) &
                         (deficit['HS_Pattern_IDs']==pats) &
                         (deficit['Variant']==variant)]['Elapsed_Time']
        data.append(series if not series.empty else [])
        positions.append(i * (n_vars + 1) + j)
    labels.append(f"{offload_map.get(offload, offload)} MPM {int(pats)} {'Patterns' if int(pats)!=1 else 'Pattern'}")

# Tick positions at center of each combo
tick_pos = [i * (n_vars + 1) + (n_vars - 1) / 2 for i in range(len(combos))]

# Create plot
fig_width = max(10, len(positions) * 0.35)
fig, ax = plt.subplots(figsize=(fig_width, 6))
box = ax.boxplot(data, positions=positions, widths=0.6,
                 showmeans=True, meanline=True,
                 patch_artist=True)  # allow coloring

# Color boxes by variant
for idx, box_patch in enumerate(box['boxes']):
    var = variants[idx % n_vars]
    c = type_colors.get(var, 'gray')
    box_patch.set_facecolor(c)
    box_patch.set_alpha(0.6)
    # also color median and mean markers
    box['medians'][idx].set(color='black', linewidth=1.5)
    box['means'][idx].set(markerfacecolor='white', markeredgecolor='red', marker='D')

# Add error bars for standard deviation
for idx, series in enumerate(data):
    if len(series) > 0:
        m, s = series.mean(), series.std()
        ax.errorbar(positions[idx], m, yerr=s, fmt='none', ecolor='red', capsize=4)

# Simple Y-axis with 10 evenly spaced ticks
y_min, y_max = ax.get_ylim()
# Create 10 evenly spaced ticks from min to max
y_ticks = [y_min + i * (y_max - y_min) / 9 for i in range(10)]
ax.set_yticks(y_ticks)
ax.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.1f'))

# Simple grid
ax.grid(True, alpha=0.3)

# X-axis labels
ax.set_xticks(tick_pos)
ax.set_xticklabels(labels, rotation=30, ha='right')
ax.set_ylabel('Elapsed Time (seconds)')
ax.set_title(f"Elapsed Time Distribution for {os.path.basename(csv_file)}")

# Legend for variants
legend_handles = [mpatches.Patch(color=type_colors[v], label=variant_map.get(v, v))
                  for v in variants]
ax.legend(handles=legend_handles, title='Variant')

plt.tight_layout()

# Save wide PDF
base, _ = os.path.splitext(os.path.basename(csv_file))
pdf_name = f"{base}_boxplots_all.pdf"
fig.savefig(pdf_name, bbox_inches='tight')
print(f"Saved combined boxplot to '{pdf_name}'")

