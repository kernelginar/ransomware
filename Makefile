all:
	@echo "Building src/file_lister.c..."
	@gcc -o build/file_lister src/file_lister.c -static
	@echo "Building src/ransomware.c..."
	@gcc -o build/ransomware src/ransomware.c src/include/cjson/cJSON.c -lssl -lcrypto -lws2_32 -lcrypt32 -static
clean:
	@rm.exe -rfv build/ransomware build/file_lister