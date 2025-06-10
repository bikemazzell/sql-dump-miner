# ⚒️ SQLMiner ⚒️ 

A fast, simple utility to scan SQL dump files for sensitive data like email addresses and IP addresses, extracting the relevant data rows into a clean CSV format.

## Key Features

- **Fast & Efficient**: Scans large files line-by-line without loading the entire file into memory.
- **High Performance**: Optimized with fast pre-filtering to skip irrelevant lines, processing millions of lines per minute.
- **Batch Processing**: Process a single `.sql` file or an entire directory of them.
- **Real-time Progress**: Shows detailed progress statistics including processing speed and records found when using `--verbose`.
- **Flexible Output**:
    - For a directory, create one `.csv` per `.sql` file.
    - For a directory, combine all results into a single output file.
- **Data Cleaning**: Automatically remove common noise (e.g., `null`, `true`, `false`, empty values) from the results with the `--clean` flag.
- **Smart Naming**: Automatically generates clean, lowercase filenames from input files (e.g., `My Data.sql` -> `mydata.csv`).

## Usage

```bash
usage: sqlminer.py [-h] -i INPUT [-o OUTPUT] [--chunk-size CHUNK_SIZE] [-v] [--clean]
```

## Options
```
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to input SQL file or directory of .sql files.
  -o OUTPUT, --output OUTPUT
                        Path to output file or directory. For batch processing,
                        specifies an output directory or a single file for combined
                        results.
  --chunk-size CHUNK_SIZE
                        Number of records to process before writing (default: 1000)
  -v, --verbose         Enable verbose logging with real-time progress statistics.
  --clean               Clean the output file to remove noise.
```

## Examples

**1. Process a single file:**
This will create `my_data.csv` in the same directory.
```bash
python sqlminer.py -i /path/to/my_data.sql
```

**2. Process a single file and clean the output:**
```bash
python sqlminer.py -i my_data.sql --clean
```

**3. Process a directory of .sql files:**
This will create a corresponding `.csv` for each `.sql` file inside `/path/to/dumps/`.
```bash
python sqlminer.py -i /path/to/dumps/
```

**4. Process a directory and save results to another directory:**
```bash
python sqlminer.py -i /path/to/dumps/ -o /path/to/results/
```

**5. Process a directory and combine all results into a single file:**
```bash
python sqlminer.py -i /path/to/dumps/ -o /path/to/all_results.csv --clean
```

**6. Process a large file with real-time progress monitoring:**
```bash
python sqlminer.py -i large_dump.sql --verbose --clean
```
This will show detailed progress output like:
```
Progress: 45.2% | Lines: 2,847,391 (185,420/sec) | Found: 12,543 | Rate: 125.3 MB/s
```

## Performance

SQLMiner is optimized for processing very large SQL dump files efficiently:

- **Fast pre-filtering**: Quickly skips lines without sensitive data using string operations before regex
- **Optimized regex patterns**: Uses efficient patterns that avoid catastrophic backtracking
- **Large I/O buffers**: 8MB read buffers and 64KB write buffers for maximum throughput
- **Typical performance**: 100,000+ lines per second, processing 2GB+ files in seonds