# ⚒️ SQLMiner ⚒️ 
by @shoewind1997

Extract sensitive data from SQL dumps into CSV

## Usage

`usage: sqlminer.py [-h] [-c CONFIG] -i INPUT [-o OUTPUT] [--chunk-size CHUNK_SIZE]`

## Options
```
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to config file (default: config.json)
  -i INPUT, --input INPUT
                        Path to input SQL file
  -o OUTPUT, --output OUTPUT
                        Path to output file (default: sensitive_data.txt)
  --chunk-size CHUNK_SIZE
                        Number of records to process before writing (default: 1000)
```