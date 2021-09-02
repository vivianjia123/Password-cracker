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
#include "guess.h"

int main(int argc, char *argv[]) {
    long guesscnt = 0;
    char pwdfilename[32];
    char hashfilename[32];
    memset(pwdfilename, 0, 32);
    memset(hashfilename, 0, 32);

    int size = 0;
    BYTE *hash_bytes = NULL;

    // for case with no arguments
    if (argc == 1) {
        hash_bytes = read_hashes(&size);
        // no hashes can be got
        if (hash_bytes == NULL)
            return 0;

        // try to guess passwords to match hashes
        brute_force_guess_pwd4(hash_bytes, size);
        if (size > 10)
            brute_force_guess_pwd6(hash_bytes + 10*SHA256_BLOCK_SIZE, size-10, 10);

        free(hash_bytes);

    } else if (argc == 2) { // for case with one argument
        guesscnt = atoi(argv[1]);
        if (guesscnt <= 0)
            return 0;

        //try to guess passwords, and print them out
        do_good_guess(guesscnt);

    } else if (argc == 3) { // for case with two arguments
        // the filename of a list of passwords
        memcpy(pwdfilename, argv[1], strlen(argv[1]));
        // the filename of a list of SHA256 hashes
        memcpy(hashfilename, argv[2], strlen(argv[2]));
        hash_bytes = read_given_hashfile(hashfilename, &size);
        // test each of the passwords given in the first file against each of the hashes given in the second file
        read_and_match_pwds(pwdfilename, hash_bytes, size);

        free(hash_bytes);
    }

    return 0;
}
