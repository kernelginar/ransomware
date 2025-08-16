#include "include/file_lister.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Kullanım: %s <dizin_yolu>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *root_path = argv[1];
    FILE *output = fopen("output.json", "w");
    if (!output) {
        perror("output.json dosyası oluşturulamadı");
        return EXIT_FAILURE;
    }

    FileCollector collector = {output, 0, 1};

    fprintf(output, "{\n");
    fprintf(output, "    \"files\": [\n");

    traverse_directory(root_path, &collector);

    fprintf(output, "\n    ],\n");
    fprintf(output, "    \"total_file\": %d\n", collector.file_count);
    fprintf(output, "}\n");

    fclose(output);

    printf("Tarama tamamlandı. Sonuçlar: output.json\n");
    return EXIT_SUCCESS;
}