/**
* COMP30023 Computer Systems 2019
* Project 2: Password cracker
*
* Created by Ziqi Jia on 23/05/19.
* Copyright © 2019 Ziqi Jia. All rights reserved.
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "sha256.h"

#define MAX_PWD_SIZE 10240

// Reference link: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt
#define PWD_DICT "10-million-password-list-top-100000.txt"

char pop_letters[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
};
// numbers
char pop_nums[] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'
};
// marsk
char pop_marks[] = {
    '(', ')', '*', '_', '@', '.'
};

/* read line from file */
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

/* size will be set to the count of hash strings in given hash files, return all hash bytes from given files. */
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

    // close file
    fclose(file1);
    if (file2)
        fclose(file2);

    // convert to count of hash strings
    *size = *size/SHA256_BLOCK_SIZE;
    return hash_bytes;
}

/* read hash_bytes from a given hashfile, NULL means fail */
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

/* return the id of hash string, matches with pwd, and stored in hash_bytes, return -1 if no hash string is matched */
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


/* guess passwords in 3 steps. */
void do_good_guess(long guesscnt) {
    // Step 1. read from password dict, filtering each password with 6 characters and guessing based on the file
    FILE *file = NULL;
    if ((file = fopen(PWD_DICT, "r")) != NULL) {
        BYTE line[64];
        BYTE oldpwd[6];
        memset(line, 0, 64);
        memset((char *)oldpwd, 0, 6);

        // read dictionary
        while(freadline(file, (char *)line, 64) > 0) {
            if (strlen((char *)line) >= 6) {
                // skip redundant guess
                if (memcmp(line, oldpwd, 6) != 0) {
                    // save it for checking whether redundant later
                    memcpy((char *)oldpwd, (char *)line, 6);
                    // print orginal one
                    printf("%.6s\n", (char *)line);

                    guesscnt -= 1;
                    if (guesscnt == 0)
                        return;

                    for (int i = 0; i < 6; i ++) {
                        // convert each char to uppercase and guess
                        if (line[i] >= 'a' && line[i] <= 'z') {
                            line[i] -= 'a' - 'A';
                            printf("%.6s\n", (char *)line);
                            guesscnt -= 1;
                            if (guesscnt == 0)
                                return;
                        }
                    }
                }
            }
            memset(line, 0, 64);
        }
    }

    // Step 2. only use popular chars with rules, malloc a space to save newly generated password
    // rules include:
    //     1. letters + numbers;
    //     2. letters + marks;
    //     3. letters + marks + numbers;
    // Store characters that are commonly used in passwords, including, popular letters, popular numbers, and popular marks, only list lowercase letters here, they can be converted to uppercase later
    BYTE pwd[6];
    memset(pwd, 0, 6);
    int pop_letter_len = sizeof(pop_letters);
    int pop_num_len = 10;
    int pop_mark_len = sizeof(pop_marks);

    for (int i = 0; i < pop_letter_len; i ++) {
        pwd[i] = pop_letters[i];
        for (int j = 0; j < pop_letter_len; j ++) {
            pwd[j] = pop_letters[j];
            for (int k = 0; k < pop_letter_len; k ++) {
                pwd[k] = pop_letters[k];
                for (int l = 0; l < pop_letter_len; l ++) {
                    pwd[l] = pop_letters[l];
                    for (int m = 0; m < pop_letter_len; m ++) {
                        pwd[m] = pop_letters[m];

                        for (int n = 0; n < pop_letter_len; n ++) {
                            pwd[n] = pop_letters[n];
                        }
                        guesscnt -= 1;
                        printf("%s\n", (char *)pwd);
                        if (guesscnt == 0)
                            return;
                    }
                    for (int m = 0; m < pop_num_len; m ++) {
                        pwd[m] = pop_nums[m];
                        for (int n = 0; n < pop_letter_len; n ++) {
                            pwd[n] = pop_letters[n];
                        }
                        guesscnt -= 1;
                        printf("%s\n", (char *)pwd);
                        if (guesscnt == 0)
                            return;
                    }

                    for (int m = 0; m < pop_mark_len; m ++) {
                        pwd[m] = pop_marks[m];
                        for (int n = 0; n < pop_letter_len; n ++) {
                            pwd[n] = pop_letters[n];
                        }
                        guesscnt -= 1;
                        printf("%s\n", (char *)pwd);
                        if (guesscnt == 0)
                            return;
                    }
                }

            }
        }
    }


    // Step 3. brute force
    int charcnt = '~' - ' ' + 1;
    memset(pwd, 0, 6);
    // generate byte by byte
    for (int i = 0; i < charcnt; i ++) {
        // start from char A, because usually simple passwords are with commonly seen chars
        pwd[0] = ' ' + i;
        for (int j = 0; j < charcnt; j ++) {
            pwd[1] = ' ' + j;
            for (int k = 0; k < charcnt; k ++) {
                pwd[2] = ' ' + k;
                for (int l = 0; l < charcnt; l ++) {
                    pwd[3] = ' ' + l;
                    for (int m = 0; m < charcnt; m ++) {
                        pwd[4] = ' ' + m;
                        for (int n = 0; n < charcnt; n ++) {
                            pwd[5] = ' ' + n;
                            guesscnt -= 1;
                            printf("%s\n", (char *)pwd);
                            if (guesscnt == 0)
                                return;
                        }
                    }
                }
            }
        }
    }
}

/* try to guess passwords with 4 characters by brutal foce way */
void brute_force_guess_pwd4(BYTE *hash_bytes, int hashcnt) {
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

                    int hash_id = try_hash(pwd, 4, hash_bytes, hashcnt);
                    if (hash_id >= 0) {
                        printf("%s %d\n", pwd, hash_id + 1);
                    }
                }
            }
        }
    }
}

/* try to guess passwords with 6 characters by brutal foce way */
void brute_force_guess_pwd6(BYTE *hash_bytes, int hashcnt, int pwd4cnt) {
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

                            int hash_id = try_hash(pwd, 6, hash_bytes, hashcnt);
                            if (hash_id >= 0) {
                                printf("%s %d\n", pwd, hash_id + 1 + pwd4cnt);
                            }
                        }
                    }
                }
            }
        }
    }
}

/* guess from passward list */
void good_guess_pwd6(BYTE *hash_bytes, int hashcnt, int pwd4cnt) {
    // Step 1. read from password dict
    FILE *file = NULL;
    if ((file = fopen(PWD_DICT, "r")) != NULL) {
        BYTE line[64];
        BYTE oldpwd[6];
        memset(line, 0, 64);
        memset((char *)oldpwd, 0, 6);
        // read dictionary
        while(freadline(file, (char *)line, 64) > 0) {
            if (strlen((char *)line) >= 6) {
                // skip redundant guess
                if (memcmp(line, oldpwd, 6) == 0)
                    continue;
                memcpy((char *)oldpwd, (char *)line, 6);

                // print the value of dict
                int hash_id = try_hash(line, 6, hash_bytes, hashcnt);
                if (hash_id >= 0) {
                    printf("%s %d\n", line, hash_id + 1 + pwd4cnt);
                }

                // convert first char to uppercase and guess
                if (line[0] >= 'a')
                    line[0] -= 'a' - 'A';
                hash_id = try_hash(line, 6, hash_bytes, hashcnt);
                if (hash_id >= 0) {
                    printf("%s %d\n", line, hash_id + 1 + pwd4cnt);
                }
            }
            memset(line, 0, 64);
        }
    }
    if (file != NULL)
        fclose(file);
}

/* read pwds from given pwd file and execute match */
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
        // try to match with given hashes
        int hash_id = try_hash(pwd, (int)strlen((char *)pwd), hash_bytes, hashcnt);
        if (hash_id >= 0) {
            printf("%s %d\n", pwd, hash_id + 1);
        }
        // reset buffer
        memset(pwd, 0, MAX_PWD_SIZE);
    }
    fclose(file);
    
}
