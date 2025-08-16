#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define AES_KEYLEN 16
#define AES_BLOCKLEN 16

const unsigned char aes_key[AES_KEYLEN] = "0123456789abcdef";

char *base64_encode(const unsigned char *input, int length);
unsigned char *base64_decode(const char *input, int *out_len);
void *encrypt_file(const char *path);
void decrypt_file(const char *path);

void *encrypt_file(const char *path)
{
	FILE *file = fopen(path, "rw");
	if (!file)
	{
		perror("Cannot open file");
		return NULL;
	}

	fseek(file, 0, SEEK_END);
	long in_len = ftell(file);
	rewind(file);

	unsigned char *plaintext = malloc(in_len);
	fread(plaintext, 1, in_len, file);
	fclose(file);

	// Prepare encryption context
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[AES_BLOCKLEN];
	RAND_bytes(iv, AES_BLOCKLEN);

	unsigned char *ciphertext = malloc(in_len + AES_BLOCKLEN);
	int len, ciphertext_len = 0;

	EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, iv);
	EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, in_len);
	ciphertext_len += len;
	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	free(plaintext);

	unsigned char *output = malloc(ciphertext_len + AES_BLOCKLEN);
	memcpy(output, iv, AES_BLOCKLEN);
	memcpy(output + AES_BLOCKLEN, ciphertext, ciphertext_len);

	char *encoded = base64_encode(output, ciphertext_len + AES_BLOCKLEN);
	free(output);
	free(ciphertext);

	file = fopen(path, "w");
	fprintf(file, "%s", encoded);
	fclose(file);
	free(encoded);

	printf("Encrypted and saved to %s\n", path);
}

void decrypt_file(const char *path)
{
	FILE *file = fopen(path, "rb");
	if (!file)
	{
		perror("Cannot open file");
		exit(EXIT_FAILURE);
	}

	fseek(file, 0, SEEK_END);
	long in_len = ftell(file);
	rewind(file);

	char *base64_input = malloc(in_len + 1);
	fread(base64_input, 1, in_len, file);
	base64_input[in_len] = '\0';
	fclose(file);

	int decoded_len;
	unsigned char *decoded = base64_decode(base64_input, &decoded_len);
	free(base64_input);

	unsigned char iv[AES_BLOCKLEN];
	memcpy(iv, decoded, AES_BLOCKLEN);

	unsigned char *ciphertext = decoded + AES_BLOCKLEN;
	int ciphertext_len = decoded_len - AES_BLOCKLEN;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char *plaintext = malloc(ciphertext_len);
	int len, plaintext_len = 0;

	EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, iv);
	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
	plaintext_len += len;
	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	free(decoded);

	file = fopen(path, "w");
	fwrite(plaintext, 1, plaintext_len, file);
	fclose(file);
	free(plaintext);

	printf("Decrypted and saved to %s\n", path);
}

char *base64_encode(const unsigned char *input, int length)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newline
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);

	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buff = malloc(bptr->length + 1);
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = '\0';

	BIO_free_all(b64);
	return buff;
}

unsigned char *base64_decode(const char *input, int *out_len)
{
	BIO *b64, *bmem;
	int input_len = strlen(input);
	unsigned char *buffer = malloc(input_len);

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new_mem_buf(input, input_len);
	bmem = BIO_push(b64, bmem);

	*out_len = BIO_read(bmem, buffer, input_len);
	BIO_free_all(bmem);
	return buffer;
}