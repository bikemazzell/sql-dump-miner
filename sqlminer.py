import sys
import os
import argparse
import re
import logging
from pathlib import Path
from typing import Set

class SQLSensitiveDataExtractor:
    """
    A class to extract sensitive data from SQL dump files based on regex patterns.
    """
    
    def __init__(self, chunk_size: int = 1000):
        """
        Initialize the extractor.
        
        Args:
            chunk_size: Number of records to process before writing to file
        """
        self.chunk_size = chunk_size
        self.logger = logging.getLogger(__name__)
        
        # Regex for common sensitive data
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        self.sensitive_pattern = re.compile(f'({email_pattern})|({ip_pattern})', re.IGNORECASE)

    def _write_records(self, records: Set[str], output_path: Path) -> None:
        """
        Appends records to the output file, one record per line.
        """
        with open(output_path, 'a', encoding='utf-8') as f:
            # Sort for deterministic output per batch
            for record in sorted(records):
                f.write(f"{record}\n")

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
            
        total_records = 0
        batch = set()
        encodings = ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']
        file_processed = False

        for encoding in encodings:
            try:
                with open(input_path, 'r', encoding=encoding) as f:
                    for line in f:
                        # Use more robust parsing to handle multiple statements per line
                        if 'insert into' in line.lower() and self.sensitive_pattern.search(line):
                            # Split by `INSERT INTO` to handle multiple statements on one line
                            statements = re.split(r'INSERT INTO', line, flags=re.IGNORECASE)
                            for statement_part in statements[1:]: # First element is before the first insert
                                try:
                                    # For each statement, isolate the part after VALUES
                                    upper_part = statement_part.upper()
                                    if 'VALUES' not in upper_part:
                                        continue
                                    
                                    values_section = statement_part[upper_part.index('VALUES') + len('VALUES'):]
                                    
                                    # Find all individual value tuples, e.g., (...)
                                    value_tuples = re.findall(r'\((.*?)\)', values_section)

                                    for v_tuple in value_tuples:
                                        # Check the specific tuple for sensitive data before adding
                                        if self.sensitive_pattern.search(v_tuple):
                                            cleaned_values = v_tuple.replace("'", "").replace('`', '').replace('"', '')
                                            batch.add(cleaned_values)
                                            total_records += 1
                                            
                                    if len(batch) >= self.chunk_size:
                                        self._write_records(batch, write_path)
                                        batch.clear()
                                            
                                except Exception as e:
                                    self.logger.debug(f"Could not parse values from line snippet: {statement_part[:100]}. Error: {e}")
                                    continue

                self.logger.info(f"Successfully processed file with encoding '{encoding}'.")
                file_processed = True
                break
            except UnicodeDecodeError:
                self.logger.debug(f"Failed to decode with {encoding}, trying next.")
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
            
        if total_records > 0:
            self.logger.info(f"Success! Found {total_records} sensitive data segments. Output written.")
        else:
            self.logger.info("No sensitive data found.")

    def clean_output_file(self, output_path: Path):
        """
        Cleans the output file by removing noise like repeated commas and
        common placeholder values (0, 1, true, false). This is done in-place.
        """
        if not output_path.exists() or output_path.stat().st_size == 0:
            self.logger.warning(f"Output file {output_path} not found or is empty, skipping cleanup.")
            return

        self.logger.info(f"Cleaning output file: {output_path}")
        cleaned_temp_path = output_path.with_suffix(output_path.suffix + '.tmp')
        
        lines_written = 0
        try:
            with open(output_path, 'r', encoding='utf-8') as f_in, \
                 open(cleaned_temp_path, 'w', encoding='utf-8') as f_out:
                for line in f_in:
                    # Split by comma, filter unwanted values, and also filter empty strings
                    # that result from repeated commas.
                    parts = [p for p in line.strip().split(',') if p.strip().lower() not in ['0', '1', 'true', 'false', '', 'null']]
                    if parts:
                        f_out.write(','.join(parts) + '\n')
                        lines_written += 1
            
            if lines_written > 0:
                cleaned_temp_path.replace(output_path)
                self.logger.info(f"Success! Output file cleaned and updated at: {output_path}")
            else:
                self.logger.info("Output contained only noise. Final file removed.")
                output_path.unlink() # Remove original as it's now empty of data
                
        except Exception as e:
            self.logger.error(f"Failed to clean output file: {e}")
            raise
        finally:
            if cleaned_temp_path.exists():
                cleaned_temp_path.unlink()

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
        extractor = SQLSensitiveDataExtractor(chunk_size=args.chunk_size)

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
                        if args.clean:
                            extractor.clean_output_file(output_file)
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
                
                if args.clean:
                    extractor.clean_output_file(output_dest)
                logger.info(f"--- All results combined in {output_dest} ---")

        elif input_path.is_file():
            # --- Single file processing ---
            if args.output:
                output_path = Path(args.output)
            else:
                sanitized_name = sanitize_filename(input_path.stem)
                output_path = input_path.with_name(f"{sanitized_name}.csv")
            
            extractor.process_file(input_path, output_path)

            if args.clean:
                extractor.clean_output_file(output_path)
        else:
            logger.error(f"Input path '{input_path}' is not a valid file or directory.")
            sys.exit(1)

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=args.verbose)
        sys.exit(1)