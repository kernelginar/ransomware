#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#define PATH_MAX_LEN 4096

typedef struct {
	FILE *output;
	int file_count;
	int first_file;
} FileCollector;

void escape_json_string(const char *input, char *output)
{
	while (*input)
	{
		if (*input == '\"' || *input == '\\')
		{
			*output++ = '\\';
		}
		*output++ = *input++;
	}
	*output = '\0';
}

void traverse_directory(const char *base_path, FileCollector *collector)
{
	DIR *dir = opendir(base_path);
	if (dir == NULL)
	{
		return;
	}

	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL)
	{
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
		{
			continue;
		}

		char full_path[PATH_MAX_LEN];
		snprintf(full_path, sizeof(full_path), "%s/%s", base_path, entry->d_name);

		struct stat path_stat;
		if (stat(full_path, &path_stat) == -1)
		{
			continue;
		}

		if (S_ISDIR(path_stat.st_mode))
		{
			traverse_directory(full_path, collector);
		}
		else if (S_ISREG(path_stat.st_mode) && access(full_path, R_OK | W_OK) == 0)
		{
			char escaped_path[PATH_MAX_LEN * 2];
			escape_json_string(full_path, escaped_path);

			if (!collector->first_file)
			{
				fprintf(collector->output, ",\n");
			}
			collector->first_file = 0;

			fprintf(collector->output,
					"        {\n"
					"            \"path\": \"%s\",\n"
					"            \"file_size\": %ld\n"
					"        }",
					escaped_path,
					(long)path_stat.st_size);
			collector->file_count++;
		}
	}

	closedir(dir);
}