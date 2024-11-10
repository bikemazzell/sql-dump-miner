import sys
import os
import argparse
import re
import json
import logging
from pathlib import Path
from typing import Set, List, Dict, Generator, Optional

class SQLSensitiveDataExtractor:
    """
    A class to extract sensitive data from SQL dump files.
    """
    
    def __init__(self, config_path: Path, chunk_size: int = 1000):
        """
        Initialize the extractor with configuration.
        
        Args:
            config_path: Path to JSON configuration file
            chunk_size: Number of records to process before writing to file
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If config file format is invalid
        """
        self.chunk_size = chunk_size
        self.logger = logging.getLogger(__name__)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
            
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        self._validate_config(config)
            
        self.sensitive_tables = {table.lower() for table in config.get('sensitive_tables', [])}
        self.sensitive_fields = {field.lower() for field in config.get('sensitive_fields', [])}
        
        # Compile regex patterns
        self.create_table_pattern = re.compile(
            r'CREATE\s+TABLE\s+[`"]?(\w+)[`"]?\s*\((.*?)\);',
            re.IGNORECASE | re.DOTALL
        )
        self.insert_pattern = re.compile(
            r'INSERT INTO\s+[`"]?(\w+)[`"]?',
            re.IGNORECASE
        )
        self.column_pattern = re.compile(r'[`"]?(\w+)[`"]?\s+.*')
        
        self.missing_schema_warnings = set()
        
    def _validate_config(self, config: dict) -> None:
        """
        Validate configuration file format.
        
        Args:
            config: Dictionary containing configuration
            
        Raises:
            ValueError: If config format is invalid
        """
        required_fields = ['sensitive_tables', 'sensitive_fields']
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required field in config: {field}")
            if not isinstance(config[field], list):
                raise ValueError(f"Field {field} must be a list")
            if not all(isinstance(item, str) for item in config[field]):
                raise ValueError(f"All items in {field} must be strings")

    def _read_file_chunks(self, file_path: Path, chunk_size: int = 1024*1024*10) -> Generator[str, None, None]:
        """Optimized chunk reading with larger buffer"""
        buffer = ""
        # Use a context manager for encodings
        with open(file_path, 'rb') as f:
            raw_content = f.read()
        
        for encoding in ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']:
            try:
                content = raw_content.decode(encoding)
                statements = re.split(r';(?=(?:[^\']*\'[^\']*\')*[^\']*$)', content)
                for statement in statements:
                    if statement.strip():
                        yield self._normalize_statement(statement + ';')
                return
            except UnicodeDecodeError:
                continue
        
        raise UnicodeError(f"Failed to decode file with any supported encoding")

    def _normalize_statement(self, statement: str) -> str:
        """
        Normalize statement by removing comments and extra whitespace.
        
        Args:
            statement: SQL statement to normalize
            
        Returns:
            Normalized SQL statement
        """
        # Remove inline comments
        statement = re.sub(r'--.*$', '', statement, flags=re.MULTILINE)
        # Remove multi-line comments
        statement = re.sub(r'/\*.*?\*/', '', statement, flags=re.DOTALL)
        # Normalize whitespace
        return ' '.join(statement.split())
    
    def _write_records(self, records: Set[str], output_path: Path, mode: str = 'w') -> None:
        """
        Write records to output file, each record on its own line.
        
        Args:
            records: Set of records to write
            output_path: Path to output file
            mode: File opening mode ('w' for write, 'a' for append)
        """
        sorted_records = sorted(records)
        
        if mode == 'w':
            # For write mode, write records directly
            with open(output_path, mode, encoding='utf-8') as f:
                for record in sorted_records:
                    f.write(f"{record}\n")
        else:
            # For append mode
            if not output_path.exists() or output_path.stat().st_size == 0:
                # If file doesn't exist or is empty, write normally
                with open(output_path, 'w', encoding='utf-8') as f:
                    for record in sorted_records:
                        f.write(f"{record}\n")
            else:
                # If file exists and has content
                with open(output_path, 'a', encoding='utf-8') as f:
                    for record in sorted_records:
                        f.write(f"{record}\n")

    def _is_date(self, value: str) -> bool:
        """
        Check if a value appears to be a date or timestamp.
        
        Args:
            value: String value to check
            
        Returns:
            True if value appears to be a date, False otherwise
        """
        # Check if value is a Unix timestamp
        if value.isdigit() and len(value) == 10:
            return True
            
        # Common date formats
        date_patterns = [
            r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
            r'\d{2}/\d{2}/\d{4}',  # MM/DD/YYYY
            r'\d{4}/\d{2}/\d{2}',  # YYYY/MM/DD
            r'\d{2}-\d{2}-\d{4}'   # MM-DD-YYYY
        ]
        
        for pattern in date_patterns:
            if re.match(pattern, value):
                return True
                
        return False

    def _split_values(self, values_str: str) -> List[str]:
        """More robust value splitting with proper escaping"""
        values = []
        value_buffer = []
        in_string = False
        escape_next = False
        quote_char = None
        
        for char in values_str:
            if escape_next:
                value_buffer.append(char)
                escape_next = False
                continue
                
            if char == '\\':
                escape_next = True
                value_buffer.append(char)
                continue
                
            if char in ['"', "'"] and not escape_next:
                if not in_string:
                    in_string = True
                    quote_char = char
                elif char == quote_char:
                    in_string = False
                    quote_char = None
                value_buffer.append(char)
            elif char == ',' and not in_string:
                value = ''.join(value_buffer).strip()
                values.append(value if value.upper() != 'NULL' else 'NULL')
                value_buffer = []
            else:
                value_buffer.append(char)
        
        if value_buffer:
            value = ''.join(value_buffer).strip()
            values.append(value if value.upper() != 'NULL' else 'NULL')
        
        return values

    def _is_table_match(self, table_name: str) -> bool:
        """Check if table name contains any of the sensitive table patterns."""
        table_name = table_name.lower()
        return any(pattern in table_name for pattern in self.sensitive_tables)

    def _is_field_match(self, field_name: str) -> bool:
        """Check if field name contains any of the sensitive field patterns."""
        field_name = field_name.lower()
        return any(pattern in field_name for pattern in self.sensitive_fields)

    def _extract_table_schema(self, statement: str) -> Dict[str, List[str]]:
        """
        Extract table schema from CREATE TABLE statement with debug logging.
        """
        self.logger.debug(f"Attempting to extract schema from: {statement[:100]}...")
        
        # Extract table name
        table_match = re.match(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?(\w+)[`"]?\s*\(', statement, re.IGNORECASE)
        if not table_match:
            self.logger.debug("Failed to match table name pattern")
            return {}
        
        table_name = table_match.group(1)
        self.logger.debug(f"Found table name: {table_name}")
        
        # Extract column definitions
        columns = []
        # Find the content between the first ( and the last )
        content_match = re.search(r'\((.*)\)(?:\s*ENGINE.*)?$', statement, re.DOTALL | re.IGNORECASE)
        if not content_match:
            self.logger.debug("Failed to match column definitions")
            return {}
        
        content = content_match.group(1)
        self.logger.debug(f"Column definition content: {content[:100]}...")
        
        # Split by comma but not inside parentheses
        for column_def in re.split(r',(?![^(]*\))', content):
            column_def = column_def.strip()
            if 'PRIMARY KEY' in column_def.upper() or 'KEY' in column_def.upper():
                continue
                
            column_match = re.match(r'[`"]?(\w+)[`"]?\s+\w+', column_def)
            if column_match:
                columns.append(column_match.group(1))
                self.logger.debug(f"Found column: {column_match.group(1)}")
        
        if columns:
            self.logger.debug(f"Extracted schema for {table_name}: {columns}")
            return {table_name: columns}
        
        self.logger.debug("No columns extracted")
        return {}

    
    def _extract_sensitive_data(self, statement: str, table_schemas: Dict[str, List[str]]) -> Set[str]:
        """
        Extract sensitive data from an SQL INSERT statement.
        
        Args:
            statement: A complete SQL INSERT statement
            table_schemas: Dictionary mapping table names to their column names
            
        Returns:
            Set of sensitive values found in the statement
        """
        table_match = self.insert_pattern.search(statement)
        if not table_match:
            self.logger.debug("No table match found in statement")
            return set()

        table_name = table_match.group(1).lower()
        if table_name not in table_schemas:
            self.logger.warning(f"No schema found for table {table_name} when processing INSERT")
            self.logger.debug(f"Available schemas: {list(table_schemas.keys())}")

        self.logger.debug(f"Processing table: {table_name}")
        self.logger.debug(f"Available schemas: {list(table_schemas.keys())}")
        if not self._is_table_match(table_name):
            self.logger.debug(f"Table {table_name} not in monitored tables: {self.sensitive_tables}")
            return set()

        sensitive_data = set()

        try:
            # Check if this is a full INSERT with column names or just VALUES
            if '(' in statement and ') VALUES' in statement.upper():
                columns = re.findall(r'INSERT INTO\s+[`"]?\w+[`"]?\s*\((.*?)\)\s*VALUES', 
                                statement, re.IGNORECASE | re.DOTALL)
                if not columns:
                    return set()
                column_names = [col.strip('`" ').lower() for col in columns[0].split(',')]
            else:
                if table_name not in table_schemas:
                    # Only log warning if we haven't warned about this table before
                    if table_name not in self.missing_schema_warnings:
                        self.logger.warning(f"No schema found for table {table_name}")
                        self.missing_schema_warnings.add(table_name)
                    return set()
                column_names = table_schemas[table_name]

            # First find everything between VALUES and the end
            values_pattern = r'VALUES\s*(.*?)$'
            values_match = re.search(values_pattern, statement, re.IGNORECASE | re.DOTALL)

            if values_match:
                values_section = values_match.group(1)
                # Then extract each parenthesized group from the values section
                values_matches = re.findall(r'\((.*?)\)', values_section)
            
            if not values_matches:
                return set()

            for values_str in values_matches:
                row_sensitive_data = []
                values = self._split_values(values_str)
                
                # Handle column count mismatch
                if len(values) < len(column_names):
                    self.logger.warning(
                        f"Column count ({len(column_names)}) doesn't match "
                        f"values count ({len(values)}) for table {table_name}. "
                        "Padding with NULL values."
                    )
                    # Pad with NULL values
                    values.extend(['NULL'] * (len(column_names) - len(values)))
                elif len(values) > len(column_names):
                    self.logger.warning(
                        f"More values ({len(values)}) than columns ({len(column_names)}) "
                        f"for table {table_name}. Truncating excess values."
                    )
                    # Truncate excess values
                    values = values[:len(column_names)]
                    
                for col, val in zip(column_names, values):
                    if self._is_field_match(col):
                        clean_val = val.strip("' \"")
                        if clean_val != 'NULL' and clean_val and not self._is_date(clean_val):
                            row_sensitive_data.append(clean_val)
                
                if row_sensitive_data:
                    sensitive_data.add(','.join(row_sensitive_data))

        except Exception as e:
            self.logger.debug(f"Error processing statement: {e}")
            return set()

        return sensitive_data

    def process_file(self, input_path: Path, output_path: Path) -> None:
        """
        Memory efficient file processing with enhanced debug logging.
        """
        self.logger.info(f"Processing file: {input_path}")
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        temp_output = output_path.with_suffix('.tmp')
        table_schemas = {}
        processed_size = 0
        file_size = input_path.stat().st_size
        total_records = 0
        
        try:
            # First pass: collect all CREATE TABLE statements
            self.logger.debug("First pass: collecting CREATE TABLE statements")
            for statement in self._read_file_chunks(input_path):
                if 'CREATE TABLE' in statement.upper():
                    self.logger.debug(f"Found CREATE TABLE statement: {statement[:100]}...")
                    schema = self._extract_table_schema(statement)
                    if schema:
                        self.logger.debug(f"Extracted schema: {schema}")
                        table_schemas.update(schema)
                    else:
                        self.logger.warning(f"Failed to extract schema from CREATE TABLE statement")
                    self.logger.debug(f"Current table_schemas: {table_schemas}")
            
            # Second pass: process INSERT statements
            self.logger.debug("Second pass: processing INSERT statements")
            batch = set()
            for statement in self._read_file_chunks(input_path):
                if 'INSERT INTO' in statement.upper():
                    self.logger.debug(f"Processing INSERT statement: {statement[:100]}...")

                    # Check if INSERT statement includes column names
                    insert_part = statement[:statement.upper().find('VALUES')].strip()
                    has_explicit_columns = '(' in insert_part and ')' in insert_part

                    if has_explicit_columns:
                        self.logger.debug("Processing INSERT with explicit columns")
                        new_records = self._extract_sensitive_data(statement, {})
                    else:
                        self.logger.debug("Processing INSERT using schema from CREATE TABLE")
                        new_records = self._extract_sensitive_data(statement, table_schemas)
                    
                    batch.update(new_records)
                    total_records += len(new_records)
                    
                    if len(batch) >= self.chunk_size:
                        self.logger.info(f"Writing {len(batch)} records...")
                        self._write_records(batch, temp_output, mode='a')
                        batch.clear()
                
                processed_size += len(statement.encode())
                if processed_size % (1024*1024) == 0:
                    self.logger.info(f"Processed {processed_size/file_size*100:.1f}% of file")
            
            # Write remaining records
            if batch:
                self._write_records(batch, temp_output, 
                                mode='a' if total_records > self.chunk_size else 'w')
            
            # Rename temp file to final output
            if temp_output.exists():
                temp_output.replace(output_path)
                
            # Log final results
            if total_records > 0:
                self.logger.info(f"Found {total_records} sensitive segments. Output written to {output_path}")
            else:
                self.logger.info("No sensitive data found.")
                
        except Exception as e:
            self.logger.error(f"Error processing file: {str(e)}")
            if temp_output.exists():
                temp_output.unlink()
            raise e
            
    def cleanup(self):
        """Clean up any temporary files or resources."""
        self.missing_schema_warnings.clear()

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Set up argument parser
    parser = argparse.ArgumentParser(description='⚒️ SQLMiner ⚒️ by @shoewind1997 : Extract sensitive data from SQL dumps')
    parser.add_argument('-c', '--config', default='config.json',
                      help='Path to config file (default: config.json)')
    parser.add_argument('-i', '--input', required=True,
                      help='Path to input SQL file')
    parser.add_argument('-o', '--output',
                      help='Path to output file (default: input_filename_out.csv)')
    parser.add_argument('--chunk-size', type=int, default=1000,
                      help='Number of records to process before writing (default: 1000)')
    
    args = parser.parse_args()

    # Convert relative paths to absolute paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = Path(os.path.join(script_dir, args.config))
    input_path = Path(os.path.join(os.getcwd(), args.input))
    if args.output is None:
        args.output = input_path.stem + "_out.csv"
    output_path = Path(os.path.join(os.getcwd(), args.output))

    try:
        extractor = SQLSensitiveDataExtractor(config_path, chunk_size=args.chunk_size)
        extractor.process_file(input_path, output_path)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
    finally:
        extractor.cleanup()