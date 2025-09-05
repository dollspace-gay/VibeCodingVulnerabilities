#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LEN 1024

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <csv_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("Error opening file");
        return 1;
    }

    char line[MAX_LINE_LEN];

    while (fgets(line, sizeof(line), fp)) {
        // Remove newline at end if present
        line[strcspn(line, "\n")] = '\0';

        char *field = strtok(line, ",");
        int field_num = 1;
        while (field) {
            printf("Field %d: %s\n", field_num, field);
            field = strtok(NULL, ",");
            field_num++;
        }
        printf("---- End of line ----\n");
    }

    fclose(fp);
    return 0;
}