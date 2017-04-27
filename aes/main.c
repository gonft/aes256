//
//  main.c
//  aes
//
//  Created by Jaeyong Han on 2017. 4. 26..
//  Copyright © 2017년 LECLE Corp. All rights reserved.
//

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "aes.h"

#define MAX_LEN (2*1024*1024)
#define ENCRYPT 0
#define DECRYPT 1
#define AES_KEY_SIZE 256
#define READ_LEN 10

#define DIM(x) (sizeof(x)/sizeof(*(x)))

static const char     *sizes[]   = { "EiB", "PiB", "TiB", "GiB", "MiB", "KiB", "B" };
static const uint64_t  exbibytes = 1024ULL * 1024ULL * 1024ULL *
1024ULL * 1024ULL * 1024ULL;

//AES_IV
static unsigned char AES_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
//AES_KEY
static unsigned char AES_KEY[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

static long len = 0;

char* calculateSize(uint64_t size)
{
    char     *result = (char *) malloc(sizeof(char) * 20);
    uint64_t  multiplier = exbibytes;
    int i;
    
    for (i = 0; i < DIM(sizes); i++, multiplier /= 1024)
    {
        if (size < multiplier)
            continue;
        if (size % multiplier == 0)
            sprintf(result, "%" PRIu64 " %s", size / multiplier, sizes[i]);
        else
            sprintf(result, "%.1f %s", (float) size / multiplier, sizes[i]);
        return result;
    }
    strcpy(result, "0");
    return result;
}

unsigned char* load_file(const char* filename){
    FILE *fp;
    fp= fopen(filename, "rb");
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    printf("file size : %s\n", calculateSize(len));
    rewind(fp);
    unsigned char *file_data= (unsigned char *)malloc((len+1)*sizeof(unsigned char));
    fread(file_data, len, 1, fp);
    return file_data;
}

int main(int argc, const char * argv[]) {
    int mode;
    unsigned char *data;
    unsigned char *output;
    
    if( argc < 4 ){
        printf("Failed agument count small");
        return -1;
    }
    
    mode = atoi(argv[1]);
    data = load_file(argv[2]);
    
    unsigned int rest_len = len % AES_BLOCK_SIZE;
    unsigned int padding_len = ((ENCRYPT == mode) ? (AES_BLOCK_SIZE - rest_len) : 0);
    unsigned int src_len = len + padding_len;
    printf("src_len size : %s\n", calculateSize(src_len));
    
    unsigned char *input = (unsigned char *) malloc((src_len+1)*sizeof(char)); // Enough memory for file + \0
    memset(input, 0, src_len);
    memcpy(input, data, len);
    if (padding_len > 0) {
        memset(input + len, (unsigned char) padding_len, padding_len);
    }
    
    output = (unsigned char*) malloc((src_len+1)*sizeof(char)); // Enough memory for file + \0
    if (!output) {
        free(input);
        return -1;
    }
    memset(output, src_len, 0);
    
    //set key & iv
    unsigned int key_schedule[AES_BLOCK_SIZE * 4] = { 0 };
    aes_key_setup(AES_KEY, key_schedule, AES_KEY_SIZE);
    
    if( mode == ENCRYPT ){
        aes_encrypt_cbc(input, src_len, output, key_schedule, AES_KEY_SIZE, AES_IV);
    } else {
        aes_decrypt_cbc(input, src_len, output, key_schedule, AES_KEY_SIZE, AES_IV);
    }
    
    FILE *file = fopen(argv[3], "w+");
    
    fwrite(output, src_len, 1, file);
    
    fclose(file);
    free(input);
    free(output);
    
    return 0;
    
}
