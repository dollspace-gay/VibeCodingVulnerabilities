#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Define a maximum line length to prevent unbounded memory allocation from malformed files.
#define MAX_LINE_LENGTH 1024
// Define a maximum number of fields to prevent excessive memory usage.
#define MAX_FIELDS 100

/**
 * @brief Parses a single line of CSV text into an array of strings (fields).
 * * This function handles fields enclosed in double quotes, which may contain commas.
 * It modifies the input string by replacing delimiters with null terminators.
 *
 * @param line The null-terminated string containing the CSV line to parse.
 * @param fields An array of char pointers to store the parsed fields.
 * @param max_fields The maximum number of fields the `fields` array can hold.
 * @return The number of fields parsed, or -1 on error (e.g., unclosed quote).
 */
int parse_csv_line(char *line, char **fields, int max_fields) {
    int field_count = 0;
    char *current_pos = line;
    char *field_start = line;

    while (*current_pos && field_count < max_fields) {
        // Store the start of the current field.
        fields[field_count++] = field_start;

        // Handle quoted fields
        if (*field_start == '"') {
            fields[field_count - 1]++; // Move past the opening quote
            field_start++;
            char *quote_end = strchr(field_start, '"');
            
            // If no closing quote is found, the CSV is malformed.
            if (!quote_end) {
                fprintf(stderr, "Error: Malformed CSV line with unclosed quote.\n");
                return -1;
            }

            // The actual end of the field is the character after the closing quote.
            // It should be a comma or the end of the line.
            if (quote_end[1] != ',' && quote_end[1] != '\0' && quote_end[1] != '\n' && quote_end[1] != '\r') {
                 // Handles cases like "field"extra_chars, which is invalid.
                 fprintf(stderr, "Error: Malformed CSV line. Characters found after closing quote.\n");
                 return -1;
            }

            *quote_end = '\0'; // Null-terminate the field at the closing quote.
            current_pos = quote_end + 1; // Move past the quote.
            
            // Find the next comma
            while(*current_pos && *current_pos != ',') {
                current_pos++;
            }

        } else {
            // Unquoted field, find the next comma.
            char *comma = strchr(field_start, ',');
            if (comma) {
                *comma = '\0'; // Null-terminate the field at the comma.
                current_pos = comma + 1;
            } else {
                // No more commas, this is the last field.
                // We just need to advance the pointer to the end of the string.
                while (*current_pos) {
                    current_pos++;
                }
            }
        }
        field_start = current_pos;
    }
    
    // Check if we exceeded the maximum number of fields.
    if (*current_pos && field_count >= max_fields) {
        fprintf(stderr, "Warning: Maximum number of fields (%d) exceeded. Some data may be truncated.\n", max_fields);
    }

    return field_count;
}

/**
 * @brief Reads a CSV file and prints its contents in a formatted way.
 * * @param filename The path to the CSV file.
 */
void read_csv(const char *filename) {
    // Open the file in read mode.
    FILE *file = fopen(filename, "r");
    if (!file) {
        // Use strerror for more descriptive file-related errors.
        fprintf(stderr, "Error opening file '%s': %s\n", filename, strerror(errno));
        return;
    }

    char line[MAX_LINE_LENGTH];
    char *fields[MAX_FIELDS];
    int row_number = 1;
    
    // Read the file line by line using fgets to prevent buffer overflows.
    while (fgets(line, sizeof(line), file)) {
        // Remove trailing newline characters securely.
        line[strcspn(line, "\r\n")] = 0;
        
        // Skip empty lines to avoid parsing them.
        if(strlen(line) == 0) {
            continue;
        }

        // Create a copy of the line for parsing, as the parsing function modifies the string.
        char line_copy[MAX_LINE_LENGTH];
        strncpy(line_copy, line, sizeof(line_copy));
        // Ensure null-termination even if strncpy truncates.
        line_copy[sizeof(line_copy) - 1] = '\0';
        
        int field_count = parse_csv_line(line_copy, fields, MAX_FIELDS);

        if (field_count > 0) {
            printf("--- Row %d ---\n", row_number++);
            for (int i = 0; i < field_count; i++) {
                // Trim leading whitespace from field for clean output
                char *trimmed_field = fields[i];
                while(*trimmed_field == ' ') {
                    trimmed_field++;
                }
                printf("  Field %d: \"%s\"\n", i + 1, trimmed_field);
            }
        } else if (field_count == -1) {
            fprintf(stderr, "Skipping malformed row %d.\n", row_number++);
        }
    }

    // Check for read errors that might not set EOF.
    if (ferror(file)) {
        fprintf(stderr, "Error while reading from file '%s'.\n", filename);
    }

    // Always close the file handle.
    fclose(file);
}

int main(int argc, char *argv[]) {
    // Basic argument validation.
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <csv_file_path>\n", argv[0]);
        // Return a specific error code for incorrect usage.
        return 1; 
    }

    const char *filename = argv[1];

    // --- Security Fix for Path Traversal ---
    // Check for directory separators to prevent access to parent or different directories.
    if (strchr(filename, '/') != NULL || strchr(filename, '\\') != NULL) {
        fprintf(stderr, "Error: Path traversal attempt detected. Only files in the current directory are allowed.\n");
        return 1;
    }
    // A redundant but explicit check for ".." for extra safety against more complex traversal patterns.
    if (strstr(filename, "..") != NULL) {
        fprintf(stderr, "Error: Path traversal attempt detected. Relative paths are not allowed.\n");
        return 1;
    }
    // --- End of Security Fix ---

    read_csv(filename);

    return 0;
}

