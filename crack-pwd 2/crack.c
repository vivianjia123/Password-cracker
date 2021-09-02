#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "sha256.h"

#define MAX_PWD_SIZE 32

//#define DEBUG

// size will be set to the count of hash strings in given hash files
// return all hash bytes from given files.
BYTE *read_hashes(int *size) {
    // hash file names
    char pwd4hashfile[] = {"pwd4sha256"};
    char pwd6hashfile[] = {"pwd6sha256"};

    // first file, pointing to pwd4hashfile
    FILE *file1 = NULL;
    int file1size = 0;
    if ((file1 = fopen(pwd4hashfile, "r")) != NULL) {
        // check length of file 
        fseek(file1, 0, SEEK_END);
        file1size = ftell(file1);
        // recover to head
        fseek(file1, 0, SEEK_SET);
    } else {
        return NULL;
    }

    // second file, pointing to pwd6hashfile
    FILE *file2 = NULL;
    int file2size = 0;
    if ((file2 = fopen(pwd6hashfile, "r")) != NULL) {
        // check length of file 
        fseek(file2, 0, SEEK_END);
        file2size = ftell(file2);
        // recover to head
        fseek(file2, 0, SEEK_SET);
    }

    *size = file1size + file2size;
#ifdef DEBUG
    printf("Size of hash bytes ------ %d\n", *size);
#endif
    // malloc a space to save hash strings
    BYTE *hash_bytes = (BYTE *)malloc(*size);
    memset(hash_bytes, 0, *size);
    // read data from file1 and file2
    if (fread(hash_bytes, 1, file1size, file1) != file1size) {
        free(hash_bytes);
        return NULL;
    }
    if (file2 && fread(hash_bytes + file1size, 1, file2size, file2) != file2size) {
        free(hash_bytes);
        return NULL;
    }

    // ending
    fclose(file1);
    if (file2)
        fclose(file2);

    // convert to count of hash strings
    *size = *size/SHA256_BLOCK_SIZE;
    return hash_bytes;
}

// read hash_bytes from a given hashfile
// NULL means fail
BYTE *read_given_hashfile(char *hashfile, int *size) {
    FILE *file = NULL;
    if ((file = fopen(hashfile, "r")) == NULL) {
        return NULL;
    }
    // check length of file 
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    // recover to head
    fseek(file, 0, SEEK_SET);
    // malloc a space to save hash strings
    BYTE *hash_bytes = (BYTE *)malloc(*size);
    memset(hash_bytes, 0, *size);
    // read data from file
    if (fread(hash_bytes, 1, *size, file) != *size) {
        free(hash_bytes);
        return NULL;
    }
    fclose(file);
    // convert to count of hash strings
    *size = *size/SHA256_BLOCK_SIZE;
    return hash_bytes;
}


// return the id of hash string, matches with pwd, and stored in hash_bytes
// return -1 if no hash string is matched
int try_hash(const BYTE *pwd, int pwdsize, BYTE *hash_bytes, int hashcnt) {
    // generate sha256 hash for pwd
    // copied from sha256_test.c
    SHA256_CTX sha256_ctx;
    BYTE hash[SHA256_BLOCK_SIZE]; 
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, pwd, pwdsize);
    sha256_final(&sha256_ctx, hash);

    int hash_id = -1;
    // check each hash string
    for (int i = 0; i < hashcnt; i ++) {
        // compare each hash string
        if (memcmp(hash, hash_bytes + i * SHA256_BLOCK_SIZE, SHA256_BLOCK_SIZE) == 0) {
            hash_id = i;
            break;
        }
    }
    return hash_id;
}

// try to guess passwords with 4 charactersby brutal foce way
void guess_pwd4(BYTE *hash_bytes, int hashcnt, long *guesscnt, int mode) {
    int charcnt = '~' - ' ' + 1;

    // malloc a space to save newly generated password
    BYTE pwd[4];
    memset(pwd, 0, 4);
    // generate byte by byte
    for (int i = 0; i < charcnt; i ++) {
        // start from char A, because usually simple passwords are with commonly seen chars
        pwd[0] = 'A' + i;
        if (pwd[0] > '~') 
            pwd[0] = ' ' + pwd[0] - '~' - 1;

        for (int j = 0; j < charcnt; j ++) {
            pwd[1] = 'A' + j;
            if (pwd[1] > '~') 
                pwd[1] = ' ' + pwd[1] - '~' - 1;

            for (int k = 0; k < charcnt; k ++) {
                pwd[2] = 'A' + k;
                if (pwd[2] > '~') 
                    pwd[2] = ' ' + pwd[2] - '~' - 1;

                for (int l = 0; l < charcnt; l ++) {
                    pwd[3] = 'A' + l;
                    if (pwd[3] > '~') 
                        pwd[3] = ' ' + pwd[3] - '~' - 1;

                    if (*guesscnt == 0)
                        return;

                    int hash_id = try_hash(pwd, 4, hash_bytes, hashcnt);
                    if (hash_id >= 0) {
                        printf("%s %d\n", pwd, hash_id + 1);
                    }
                    if (mode == 2) {
                        printf("%s\n", pwd);
                    }
                    *guesscnt -= 1;
                }
            }
        }
    }
}

// try to guess passwords with 6 charactersby brutal foce way
void guess_pwd6(BYTE *hash_bytes, int hashcnt, int pwd4cnt, long *guesscnt, int mode) {
    int charcnt = '~' - ' ' + 1;

    // malloc a space to save newly generated password
    BYTE pwd[6];
    memset(pwd, 0, 6);
    // generate byte by byte
    for (int i = 0; i < charcnt; i ++) {
        // start from char A, because usually simple passwords are with commonly seen chars
        pwd[0] = 'a' + i;
        if (pwd[0] > '~') 
            pwd[0] = ' ' + pwd[0] - '~' - 1;
#ifdef DEBUG
        printf("%c ---------------------\n", pwd[0]);
#endif

        for (int j = 0; j < charcnt; j ++) {
            pwd[1] = 'a' + j;
            if (pwd[1] > '~') 
                pwd[1] = ' ' + pwd[1] - '~' - 1;

            for (int k = 0; k < charcnt; k ++) {
                pwd[2] = 'a' + k;
                if (pwd[2] > '~') 
                    pwd[2] = ' ' + pwd[2] - '~' - 1;

                for (int l = 0; l < charcnt; l ++) {
                    pwd[3] = 'a' + l;
                    if (pwd[3] > '~') 
                        pwd[3] = ' ' + pwd[3] - '~' - 1;

                    for (int m = 0; m < charcnt; m ++) {
                        pwd[4] = 'a' + m;
                        if (pwd[4] > '~') 
                            pwd[4] = ' ' + pwd[4] - '~' - 1;

                        for (int n = 0; n < charcnt; n ++) {
                            pwd[5] = 'a' + n;
                            if (pwd[5] > '~') 
                                pwd[5] = ' ' + pwd[5] - '~' - 1;

                            if (*guesscnt == 0) 
                                break;

                            int hash_id = try_hash(pwd, 6, hash_bytes, hashcnt);
                            if (hash_id >= 0) {
                                printf("%s %d\n", pwd, hash_id + 1 + pwd4cnt);
                            }
                            if (mode == 2) {
                                printf("%s\n", pwd);
                            }
                            *guesscnt -= 1;
                        }
                        if (*guesscnt == 0)
                            break;
                    }
                    if (*guesscnt == 0)
                        break;
                }
                if (*guesscnt == 0)
                    break;
            }
            if (*guesscnt == 0)
                break;
        }
        if (*guesscnt == 0)
            break;
    }
}

int freadline(FILE *file, char *buf, int size) {
    char ch = 0;
    int i = 0;
    while ((ch = fgetc(file)) != EOF) {
        if (ch == '\n')
            break;
        buf[i++] = ch;
        if (i == size)
            break;
    }
    return i;
}

// read pwds from given pwd file and execute match
void read_and_match_pwds(char *pwdfile, BYTE *hash_bytes, int hashcnt) {
    BYTE pwd[MAX_PWD_SIZE];

    FILE *file = NULL;
    if ((file = fopen(pwdfile, "r")) == NULL) {
        return;
    }

    memset((char *)pwd, 0, MAX_PWD_SIZE);
    // read pwd by line
    //while(fgets((char *)pwd, MAX_PWD_SIZE, file) != NULL) {
    while(freadline(file, (char *)pwd, MAX_PWD_SIZE) > 0) {
#ifdef DEBUG
        printf("pwd, size ---- %s, %d\n", (char *)pwd, (int)strlen((char *)pwd));
#endif
        // try to match with given hashes
        int hash_id = try_hash(pwd, (int)strlen((char *)pwd), hash_bytes, hashcnt);
        if (hash_id >= 0) {
            printf("%s %d\n", pwd, hash_id);
        }
        // reset buffer
        memset(pwd, 0, MAX_PWD_SIZE);
    }
}

int main(int argc, char *argv[]) {
    int mode =0;
    long guesscnt = pow('~' - ' ' + 1, 4) + pow('~' - ' ' + 1, 6);
    char pwdfilename[32];
    char hashfilename[32];
    memset(pwdfilename, 0, 32);
    memset(hashfilename, 0, 32);

    int size = 0;
    BYTE *hash_bytes = NULL;

    if (argc == 1) {
        mode = 1;
        hash_bytes = read_hashes(&size);

    } else if (argc == 2) {
        mode = 2;
        guesscnt = atoi(argv[1]);
#ifdef DEBUG
        printf("%ld\n", guesscnt);
#endif
        if (guesscnt <= 0)
            return 0;
        hash_bytes = read_hashes(&size);

    } else if (argc == 3) {
        mode = 3;
        memcpy(pwdfilename, argv[1], strlen(argv[1]));
        memcpy(hashfilename, argv[2], strlen(argv[2]));
#ifdef DEBUG
        printf("pwdfile, hashfile are ---- %s, %s\n", pwdfilename, hashfilename);
#endif
        hash_bytes = read_given_hashfile(hashfilename, &size);
    }

#ifdef DEBUG
    printf("Count of hash strings ------ %d\n", size);
#endif
    // no hashes can be got
    if (hash_bytes == NULL)
        return 0;

    if (mode == 1 || mode == 2) {
        // try to guess passwords to match hashes
        guess_pwd4(hash_bytes, size, &guesscnt, mode);
        // pwd5sha256 file has been given
        if (size > 10) 
            guess_pwd6(hash_bytes + 10*SHA256_BLOCK_SIZE, size-10, 10, &guesscnt, mode);
    } else {
        read_and_match_pwds(pwdfilename, hash_bytes, size);
    }

    free(hash_bytes);
    return 0;
}
