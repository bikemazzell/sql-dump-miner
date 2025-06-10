import sys
import os
import argparse
import re
import logging
from pathlib import Path
from typing import Set
import time

class SQLSensitiveDataExtractor:
    """
    A class to extract sensitive data from SQL dump files based on regex patterns.
    """
    
    def __init__(self, chunk_size: int = 1000, clean_output: bool = False, verbose: bool = False):
        """
        Initialize the extractor.
        
        Args:
            chunk_size: Number of records to process before writing to file
            clean_output: Whether to clean the results in-memory.
            verbose: Whether to show detailed progress information
        """
        self.chunk_size = chunk_size
        self.logger = logging.getLogger(__name__)
        self.clean_output = clean_output
        self.verbose = verbose
        
        # Pre-compile simple, efficient regex patterns
        # Email: must have @ and domain
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        # IP: exactly 4 groups of 1-3 digits
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        # Pattern to extract tuple contents efficiently
        self.tuple_pattern = re.compile(r'\(([^)]+)\)')
        
        if self.clean_output:
            self.noise_values = {'0', '1', 'true', 'false', '', 'null'}

    def _process_line(self, line: str) -> list:
        """
        Process a single line and return extracted sensitive data.
        """
        results = []
        
        # Super fast pre-check - skip lines without @ or multiple dots
        if '@' not in line and line.count('.') < 3:
            return results
        
        # Find all tuples in the line
        for match in self.tuple_pattern.finditer(line):
            tuple_content = match.group(1)
            
            # Check for sensitive data
            has_email = '@' in tuple_content and '.' in tuple_content
            has_potential_ip = tuple_content.count('.') >= 3 and any(c.isdigit() for c in tuple_content)
            
            if not has_email and not has_potential_ip:
                continue
            
            # Now check with regex
            found_sensitive = False
            if has_email and self.email_pattern.search(tuple_content):
                found_sensitive = True
            elif has_potential_ip and self.ip_pattern.search(tuple_content):
                found_sensitive = True
            
            if found_sensitive:
                # Clean the content
                cleaned = tuple_content.replace("'", "").replace('"', '').replace('`', '')
                
                if self.clean_output:
                    parts = [p.strip() for p in cleaned.split(',') 
                            if p.strip() and p.strip().lower() not in self.noise_values]
                    if parts:
                        results.append(','.join(parts))
                else:
                    results.append(cleaned)
        
        return results

    def _write_records(self, records: Set[str], output_path: Path) -> None:
        """
        Appends records to the output file, one record per line.
        """
        with open(output_path, 'a', encoding='utf-8', buffering=64*1024) as f:
            # Write all at once for better performance
            f.write('\n'.join(sorted(records)) + '\n')

    def process_file(self, input_path: Path, output_path: Path, append_mode: bool = False) -> None:
        """
        Scans a file line-by-line for sensitive data patterns and extracts the
        containing data row. This is a fast, single-pass approach.

        Args:
            input_path: The SQL file to process.
            output_path: The file to write results to.
            append_mode: If True, appends to output_path directly.
                         If False, uses a temporary file for safety.
        """
        self.logger.info(f"Starting fast scan for sensitive data in: {input_path}")
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        # Use a temporary file for atomic writes unless we are appending to a combined file
        write_path = output_path if append_mode else output_path.with_suffix(output_path.suffix + '.tmp')
        if not append_mode and write_path.exists():
            write_path.unlink()
            
        # Get file size for progress tracking
        file_size = input_path.stat().st_size
        
        total_records = 0
        batch = set()
        encodings = ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']
        file_processed = False
        
        # Progress tracking variables
        total_lines = 0
        lines_with_data = 0
        start_time = time.time()
        last_report_time = start_time
        bytes_read = 0

        for encoding in encodings:
            try:
                # Use large buffer for fast I/O
                with open(input_path, 'r', encoding=encoding, errors='replace', buffering=8*1024*1024) as f:
                    for line in f:
                        total_lines += 1
                        bytes_read += len(line)
                        
                        # Process line with optimized method
                        sensitive_data = self._process_line(line)
                        if sensitive_data:
                            lines_with_data += 1
                            batch.update(sensitive_data)
                            total_records += len(sensitive_data)
                        
                        # Check batch size
                        if len(batch) >= self.chunk_size:
                            self._write_records(batch, write_path)
                            batch.clear()
                        
                        # Progress report every 2 seconds in verbose mode
                        if self.verbose:
                            current_time = time.time()
                            if current_time - last_report_time >= 2:
                                elapsed = current_time - start_time
                                progress = (bytes_read / file_size) * 100 if file_size > 0 else 0
                                rate = bytes_read / elapsed / 1024 / 1024 if elapsed > 0 else 0
                                lines_per_sec = total_lines / elapsed if elapsed > 0 else 0
                                
                                self.logger.info(
                                    f"Progress: {progress:.1f}% | "
                                    f"Lines: {total_lines:,} ({lines_per_sec:.0f}/sec) | "
                                    f"Found: {total_records:,} | "
                                    f"Rate: {rate:.1f} MB/s"
                                )
                                last_report_time = current_time

                self.logger.info(f"Successfully processed file with encoding '{encoding}'.")
                file_processed = True
                break
            except UnicodeDecodeError:
                self.logger.debug(f"Failed to decode with {encoding}, trying next.")
                # Reset counters for next encoding attempt
                total_lines = 0
                total_records = 0
                lines_with_data = 0
                bytes_read = 0
                batch.clear()
                continue
            except Exception as e:
                self.logger.error(f"Error reading file {input_path} with encoding {encoding}: {e}")
                raise

        if not file_processed:
            raise UnicodeError(f"Failed to decode file {input_path} with any supported encodings.")

        if batch:
            self._write_records(batch, write_path)
            
        if not append_mode and write_path.exists():
            write_path.replace(output_path)
        
        # Final statistics
        elapsed = time.time() - start_time
        if self.verbose:
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Processing complete in {elapsed:.1f} seconds")
            self.logger.info(f"Total lines processed: {total_lines:,}")
            self.logger.info(f"Lines with sensitive data: {lines_with_data:,}")
            self.logger.info(f"Total records extracted: {total_records:,}")
            if elapsed > 0:
                self.logger.info(f"Average speed: {total_lines/elapsed:.0f} lines/sec, {file_size/elapsed/1024/1024:.1f} MB/s")
            self.logger.info(f"{'='*60}")
        else:
            if total_records > 0:
                self.logger.info(f"Success! Found {total_records} sensitive data segments. Output written.")
            else:
                self.logger.info("No sensitive data found.")

def sanitize_filename(name: str) -> str:
    """Sanitizes a string to be used as a valid filename component."""
    # Convert to lowercase and remove non-alphanumeric characters (except underscore)
    return re.sub(r'[^a-z0-9_]', '', name.lower())

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description='⚒️ SQLMiner ⚒️ by @shoewind1997 : Extract sensitive data from SQL dumps')
    parser.add_argument('-i', '--input', required=True,
                      help='Path to input SQL file or directory of .sql files.')
    parser.add_argument('-o', '--output',
                      help='Path to output file or directory. For batch processing, specifies an output directory or a single file for combined results.')
    parser.add_argument('--chunk-size', type=int, default=1000,
                      help='Number of records to process before writing (default: 1000)')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose logging for debugging.')
    parser.add_argument('--clean', action='store_true',
                      help='Clean the output file to remove noise.')
    
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    logger = logging.getLogger(__name__)
    input_path = Path(args.input)

    try:
        extractor = SQLSensitiveDataExtractor(chunk_size=args.chunk_size, clean_output=args.clean, verbose=args.verbose)

        if input_path.is_dir():
            # --- Batch processing for a directory ---
            sql_files = sorted(list(input_path.glob('*.sql')))
            if not sql_files:
                logger.info(f"No .sql files found in directory: {input_path}")
                sys.exit(0)
            
            logger.info(f"Found {len(sql_files)} .sql files to process.")
            
            output_dest = Path(args.output) if args.output else None
            is_dir_output = (output_dest and output_dest.is_dir()) or \
                            (output_dest and not output_dest.exists() and not output_dest.suffix)

            # --- Case 1: Output to a directory (or default next to input) ---
            if not output_dest or is_dir_output:
                output_dir = output_dest if output_dest else input_path
                if not output_dir.exists():
                    logger.info(f"Creating output directory: {output_dir}")
                    output_dir.mkdir(parents=True, exist_ok=True)
                
                logger.info(f"Batch processing. Output will be saved to directory: {output_dir}")
                success_count, failure_count = 0, 0
                for file_path in sql_files:
                    try:
                        logger.info(f"--- Processing {file_path.name} ---")
                        sanitized_name = sanitize_filename(file_path.stem)
                        output_file = output_dir / f"{sanitized_name}.csv"
                        extractor.process_file(file_path, output_file)
                        success_count += 1
                    except Exception as e:
                        logger.error(f"Failed to process file {file_path.name}: {e}", exc_info=args.verbose)
                        failure_count += 1
                logger.info("--- Batch processing complete ---")
                logger.info(f"Successfully processed: {success_count} files")
                logger.info(f"Failed to process: {failure_count} files")
            
            # --- Case 2: Combine all results into a single file ---
            else:
                logger.info(f"Batch processing. Results will be combined into: {output_dest}")
                if output_dest.exists():
                    output_dest.unlink()
                
                for file_path in sql_files:
                    logger.info(f"--- Processing {file_path.name} ---")
                    try:
                        extractor.process_file(file_path, output_dest, append_mode=True)
                    except Exception as e:
                        logger.error(f"Failed to process file {file_path.name}: {e}", exc_info=args.verbose)
                
                logger.info(f"--- All results combined in {output_dest} ---")

        elif input_path.is_file():
            # --- Single file processing ---
            if args.output:
                output_path = Path(args.output)
            else:
                sanitized_name = sanitize_filename(input_path.stem)
                output_path = input_path.with_name(f"{sanitized_name}.csv")
            
            extractor.process_file(input_path, output_path)

        else:
            logger.error(f"Input path '{input_path}' is not a valid file or directory.")
            sys.exit(1)

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=args.verbose)
        sys.exit(1)