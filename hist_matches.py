import argparse
import csv
import os
import re
import sys
import unittest

# Change the default input file location.
DEFAULT_INPUT_FILE = '/mnt/ssd4tb/xsismi01/fpga-pattern-match/logs/suri.out'

def process_log_file(log_file, csv_file):
    """
    Process the given log file and write the aggregated CSV to csv_file.
    Uses a histogram to compute the median without storing every buffer length,
    and prints progress updates as the file is processed.
    """
    stats = {}
    # Pattern captures: MPM, matched value, and bufferlength.
    pattern = re.compile(r'Notice:\s+detect:\s+(\w+):\s+matched\s+(\d+)\s+bufferlength\s+(\d+)')
    
    # Get total file size in bytes (for progress reporting).
    total_size = os.path.getsize(log_file)
    current_progress = -1  # initialize to -1 so that 0% prints

    with open(log_file, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break

            # Update progress if at least 1% more of the file is processed.
            pos = f.tell()
            new_progress = int(pos / total_size * 100)
            if new_progress > current_progress:
                current_progress = new_progress
                print(f"Processing [{current_progress}%]")

            m = pattern.search(line)
            if not m:
                continue
            mpm = m.group(1)
            matched_val = int(m.group(2))
            buf_len = int(m.group(3))
            
            if mpm not in stats:
                stats[mpm] = {
                    'scans': 0,
                    'buffer_sum': 0,
                    'buffer_min': None,
                    'buffer_max': None,
                    # Instead of storing all values, we keep a histogram:
                    'buffer_hist': {},
                    'matched_sum': 0,
                    'matched_counts': {i: 0 for i in range(17)}
                }
            s = stats[mpm]
            s['scans'] += 1
            s['buffer_sum'] += buf_len
            s['buffer_min'] = buf_len if s['buffer_min'] is None else min(s['buffer_min'], buf_len)
            s['buffer_max'] = buf_len if s['buffer_max'] is None else max(s['buffer_max'], buf_len)
            s['buffer_hist'][buf_len] = s['buffer_hist'].get(buf_len, 0) + 1
            
            s['matched_sum'] += matched_val
            if matched_val >= 16:
                s['matched_counts'][16] += 1
            else:
                s['matched_counts'][matched_val] += 1

    # Compute the median for each MPM using its histogram.
    for s in stats.values():
        total = s['scans']
        mid = total // 2
        cumulative = 0
        median_val = None
        for buf_value in sorted(s['buffer_hist'].keys()):
            cumulative += s['buffer_hist'][buf_value]
            if cumulative > mid:
                median_val = buf_value
                break
        s['buffer_median'] = median_val

    # Prepare CSV header.
    fieldnames = [
        'MPM',
        'scans',
        'bytes_total',
        'bytes_average',
        'bytes_median',
        'bytes_min',
        'bytes_max',
        'matched'
    ] + [f'matched{i}' for i in range(17)]
    
    with open(csv_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for mpm, s in stats.items():
            row = {
                'MPM': mpm,
                'scans': s['scans'],
                'bytes_total': s['buffer_sum'],
                'bytes_average': round(s['buffer_sum'] / s['scans'], 2),
                'bytes_median': s['buffer_median'],
                'bytes_min': s['buffer_min'],
                'bytes_max': s['buffer_max'],
                'matched': s['matched_sum']
            }
            for i in range(17):
                row[f'matched{i}'] = s['matched_counts'][i]
            writer.writerow(row)
    print("Processing complete.")

# --- Unit tests ---

class TestProcessLogFile(unittest.TestCase):
    def test_process_log_file(self):
        # A small sample log for testing purposes.
        log_content = (
            "Notice: detect: StreamMpmFunc: matched 3 bufferlength 179 [info]\n"
            "Notice: detect: StreamMpmFunc: matched 0 bufferlength 945 [info]\n"
            "Notice: detect: StreamMpmFunc: matched 0 bufferlength 594 [info]\n"
            "Notice: detect: StreamMpmFunc: matched 0 bufferlength 75 [info]\n"
            "Notice: detect: StreamMpmFunc: matched 1 bufferlength 279 [info]\n"
            "Notice: detect: StreamMpmFunc: matched 0 bufferlength 705 [info]\n"
            "Notice: detect: StreamMpmFunc: matched 2 bufferlength 2718 [info]\n"
            "Notice: detect: StreamMpmFunc: matched 4 bufferlength 517 [info]\n"
            "Notice: detect: StreamMpmFunc: matched 0 bufferlength 264 [info]\n"
            "Notice: detect: PayloadMpmFunc: matched 0 bufferlength 264 [info]\n"
        )
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_in:
            tmp_in.write(log_content)
            tmp_in_name = tmp_in.name

        with tempfile.NamedTemporaryFile(mode='r+', delete=False) as tmp_out:
            tmp_out_name = tmp_out.name

        try:
            process_log_file(tmp_in_name, tmp_out_name)
            with open(tmp_out_name, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
            self.assertEqual(len(rows), 2)
            stream_row = next((r for r in rows if r['MPM'] == 'StreamMpmFunc'), None)
            payload_row = next((r for r in rows if r['MPM'] == 'PayloadMpmFunc'), None)
            self.assertIsNotNone(stream_row)
            self.assertIsNotNone(payload_row)
            # Validate some statistics for StreamMpmFunc.
            self.assertEqual(int(stream_row['scans']), 9)
            self.assertEqual(int(stream_row['bytes_total']), 6276)
            self.assertAlmostEqual(float(stream_row['bytes_average']), 697.33, places=2)
            self.assertEqual(int(stream_row['bytes_median']), 517)
            self.assertEqual(int(stream_row['bytes_min']), 75)
            self.assertEqual(int(stream_row['bytes_max']), 2718)
            self.assertEqual(int(stream_row['matched']), 10)
        finally:
            os.remove(tmp_in_name)
            os.remove(tmp_out_name)

# --- Main entry point ---

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Process a log file and generate aggregated CSV data. '
                    'If --unittests is provided, run internal tests instead.'
    )
    parser.add_argument('--unittests', action='store_true',
                        help='Run internal unittests and exit.')
    parser.add_argument('input_file', nargs='?', default=DEFAULT_INPUT_FILE,
                        help=f'Path to the input log file (default: {DEFAULT_INPUT_FILE}).')
    parser.add_argument('--output_file', type=str, default=None,
                        help='Path and filename for the output CSV file. '
                             'If not provided, the output file will be derived '
                             'from the input filename (e.g. input.log -> input.csv).')
    args = parser.parse_args()
    
    if args.unittests:
        unittest.main(argv=[sys.argv[0]])
    else:
        if args.output_file:
            output_file = args.output_file
        else:
            base, _ = os.path.splitext(args.input_file)
            output_file = base + '.csv'
        try:
            process_log_file(args.input_file, output_file)
            print(f'CSV file generated: {output_file}')
        except Exception as e:
            print(f"Error processing file: {e}")
            sys.exit(1)
