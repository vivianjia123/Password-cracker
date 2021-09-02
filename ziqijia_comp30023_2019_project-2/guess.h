#ifndef _GUESS_
#define _GUESS_


/* read line from file */
int freadline(FILE *file, char *buf, int size);

/* return all hash bytes from given files */
BYTE *read_hashes(int *size);

/* read hash_bytes from a given hashfile */
BYTE *read_given_hashfile(char *hashfile, int *size);

/* generate sha256 hash for passwords */
int try_hash(const BYTE *pwd, int pwdsize, BYTE *hash_bytes, int hashcnt);

/* guess passwords in 3 steps */
void do_good_guess(long guesscnt);

/* try to guess passwords with 4 characters by brutal foce way */
void brute_force_guess_pwd4(BYTE *hash_bytes, int hashcnt);

/* try to guess passwords with 6 characters by brutal foce way */
void brute_force_guess_pwd6(BYTE *hash_bytes, int hashcnt, int pwd4cnt);

/* guess from passward list for 6 digit passwards*/
void good_guess_pwd6(BYTE *hash_bytes, int hashcnt, int pwd4cnt);

/* read passwards from given passward file and execute match */
void read_and_match_pwds(char *pwdfile, BYTE *hash_bytes, int hashcnt);



#endif
