/* Copyright (c) 2018 Doug Rogers under the terms of the MIT License. */
/* See http://www.opensource.org/licenses/mit-license.html.. */
/* $Id$ */

/**
 * This program searches for a given SHA1 hash in a sorted file of hashes and
 * occurrence counts. The input file is expected to have records that are
 * fully ASCII and are 63 bytes per record. This is the format used by
 * "pwned-passwords-sorted-2.0.txt" at https://haveibeenpwned.com/Passwords.
 *
 * The program allows specification of the hashes to search either on the
 * command line or from stdin.
 *
 * The program will also accept passwords as input, in which case it will
 * perform a SHA1 hash of each password then search for the resulting
 * hash. If stdin is a tty then the program will disable echoing from stdin
 * unless explicitly told not to with -no-secure.
 */

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "sha1.h"

/**
 * Default name of this program.
 */
#define kProgram "find-pwned-password-hash"

/**
 * Name of this program; this may be modified by argv[0] in main().
 */
const char* g_program = kProgram;

/**
 * Name of the text hash file. The file should be sorted by hash
 */
#define kDefaultTextHashFile "pwned-passwords-ordered-2.0.txt"

/**
 * File of sorted 63-byte lines of the format '<hash>:<count>' - like those
 * found in "pwned-passwords-ordered-2.0.txt".
 */
const char* g_text_hash_file = kDefaultTextHashFile;

/**
 * Size in bytes of each line of kTextHashFile.
 */
#define kTextHashLineBytes 63

/**
 * Size of binary SHA1 hash in bytes.
 */
#define kBinHashBytes SHA1_BINARY_BYTES

/**
 * Size of ASCII SHA1 hash (text) in bytes.
 */
#define kTextHashChars (2 * kBinHashBytes)

/**
 * Whether or not to emit verbose messages.
 */
#define kDefaultVerbose 0
int g_verbose = kDefaultVerbose;

/**
 * Whether or not to print '<hash>:<count>' rather than '<count>'.
 */
#define kDefaultPrintHash 0
int g_print_hash = kDefaultPrintHash;

/**
 * Whether or not to treat input items as passwords that should first be
 * hashed.
 */
#define kDefaultPassword 0
int g_password = kDefaultPassword;

/**
 * When reading passwords from stdin, whether or not to echo the characters
 * as they are typed. This will only happen if the shell is interactive.
 */
#define kDefaultSecure 1
int g_secure = kDefaultSecure;

/* ------------------------------------------------------------------------- */
/**
 * Prints usage information to @a file.
 *
 * Note: This function does not return.
 *
 * @param file - FILE stream to which to write the usage information.
 *
 * @param exit_code - value to pass to exit() when ending program.
 */
void Usage(FILE* file, int exit_code) __attribute__((noreturn));
void Usage(FILE* file, int exit_code) {
    fprintf(file,
            "\n"
            "USAGE\n"
            "    %s [options] [hash...]\n"
            , g_program);
    fprintf(file,
            "\n"
            "DESCRIPTION\n"
            "    %s finds the hash given on the command line (or stdin if no\n"
            "    command line arguments are given) in '%s'.\n"
            "\n"
            , g_program, kDefaultTextHashFile);
    fprintf(file,
            "    %s will print the count of passwords that were found with\n"
            "    that hash. If the hash is not found, 0 is printed and an error status code\n"
            "    is returned upon program exit.\n"
            "\n"
            "    If no hashes are given on the command line, %s will\n"
            "    read them from stdin. When entering text in a tty from stdin, use Ctrl-D to\n"
            "    end input.\n"
            "\n"
            , g_program, g_program);
    fprintf(file,
            "    When -password is specified, %s will treat each command\n"
            "    line argument or line from stdin as a password rather than a hash. In this\n"
            "    case, %s will perform the SHA1 hash of the password and\n"
            "    search for the associated hash. When reading from a tty with -secure (see\n"
            "    OPTIONS), %s will disable echoing to protect the password.\n"
            , g_program, g_program, g_program);
    fprintf(file,
            "\n"
            "OPTIONS\n"
            "    Options may begin with '-' or '--'. A ':' indicates where options may be\n"
            "    abbreviated\n");
    fprintf(file,
            "\n"
            "    -h:elp                      Show this usage information.\n");
    fprintf(file,
            "\n"
            "    -f:ile=filename             Name of text hash file. [%s]\n"
            , kDefaultTextHashFile);
    fprintf(file,
            "    -[no-]p:assword             Inputs are passwords that must be hashed. [%s-password]\n"
            , kDefaultPassword ? "" : "-no");
    fprintf(file,
            "    -[no-]e:cho:-hash           Print '<hash>:<count>' instead of just <count>. [%s-echo-hash]\n"
            , kDefaultPrintHash ? "" : "-no");
    fprintf(file,
            "    -[no-]s:ecure               Inhibit echo of password in interactive shell. [%s-secure]\n"
            , kDefaultSecure ? "" : "-no");
    /* fprintf(file, */
    /*         "    -[no-]v:erbose              Print verbose (debug) messages. [%s-verbose]\n" */
    /*         , kDefaultVerbose ? "" : "-no"); */
    exit(exit_code);
}   /* Usage() */

/* ------------------------------------------------------------------------- */
/**
 * Print an error message to stderr then exit the program with exit code 1.
 */
void PrintUsageError(const char* format, ...) {
    char text[0x0100] = "";
    va_list va;
    va_start(va, format);
    vsnprintf(text, sizeof(text), format, va);
    va_end(va);
    fprintf(stderr, "%s: %s\n", g_program, text);
    fprintf(stderr, "%s: Use '%s --help' for usage information.\n", g_program, g_program);
    exit(1);
}   /* PrintUsageError() */

/* ------------------------------------------------------------------------- */
/**
 * Find and return a pointer to the file name portion of @a path.
 *
 * @param path - a path whose name is desired. Typically this is argv[0] from
 * main().
 *
 * @return a pointer the first character after the last directory delimiter
 * (forward or back slash) in @a path, or @a path if none is found.
 */
const char* NamePartOfPath(const char* path) {
    const char* rval = path;
    if (NULL != path) {
        for (; 0 != *path; ++path) {
            if ((('/' == path[0]) || ('\\' == path[0])) &&
                !((0 == path[1]) || ('/' == path[1]) || ('\\' == path[1]))) {
                rval = &path[1];
            }
        }
    }
    return rval;
}   /* NamePartOfPath() */

/* ------------------------------------------------------------------------- */
/**
 * Look for an option of the form "[-[-]]option[=value]".
 *
 * If @a input contains '=' then non-null @a *value_ptr is set to point
 * to the character after '=' (or is set to NULL if there is no argument).
 *
 * @a descriptor may contain ':' characters which indicate abbreviation
 * points for the option. For example, "o:pt:ion" will match "-o",
 * "-o=value", "-opt", "-opt=value", "-option" and "-option=value".
 *
 * @return 1 if @a input matches @a descriptor, 0 otherwise.
 */
int IsOption(const char* input, const char** value_ptr, const char* descriptor) {
    int rval = 0;
    int finished = 0;
    assert(NULL != input);
    assert(NULL != descriptor);
    if ('-' == *input) {
        ++input;
        if ('-' == *input) {
            ++input;
        }
    } else {
        finished = 1;
    }
    while (!finished) {
        if ((0 == *input) || ('=' == *input)) {
            finished = 1;
            rval = (0 == *descriptor) || (':' == *descriptor);
        } else if ((0 == *descriptor) || ((':' != *descriptor) && (*input != *descriptor))) {
            finished = 1;
        } else {
            if (':' != *descriptor) {
                ++input;
            }
            ++descriptor;
        }
    }
    if (NULL != value_ptr) {
        *value_ptr = (rval && ('=' == *input)) ? (input + 1) : NULL;
    }
    return rval;
}   /* IsOption() */

/* ------------------------------------------------------------------------- */
/**
 * Look for flag option of the form "-[-][no-]option".
 *
 * @a descriptor may contain ':' characters which indicate abbreviation
 * points for the option. See IsOption() for more information.
 *
 * If @a input matches the descriptor then the value of @a *flag_value_ptr (if
 * not NULL) will be set to 1. If @a input matches the descriptor with "no-"
 * prefixed then @a *flag_value_ptr will be set to 0. If @a input does not
 * match @a descriptor, @a *flag_value_ptr is not modified.
 *
 * @return 1 if @a input matches @a descriptor with or without a "no-" prefix,
 * 0 otherwise.
 */
int IsFlagOption(const char* input, int* flag_value_ptr, const char* descriptor) {
    int flag_value = 1;
    int rval = 0;
    assert(NULL != input);
    assert(NULL != descriptor);
    if ('-' == *input) {
        rval = IsOption(input, NULL, descriptor);
        if (!rval) {
            flag_value = 0;
            const int k = ('-' == input[1]) ? 1 : 0;
            if (('n' == input[k+1]) && ('o' == input[k+2]) && ('-' == input[k+3])) {
                rval = IsOption(&input[k+3], NULL, descriptor);
            }
        }
    }
    if (rval && (NULL != flag_value_ptr)) {
        *flag_value_ptr = flag_value;
    }
    return rval;
}   /* IsFlagOption() */

/* ------------------------------------------------------------------------- */
/**
 * Parse options from the command line, removing them from @a argv[].
 *
 * Note that on error this function does not return.
 *
 * If an argument starts with '-' then it will be treated as an option. See
 * the OPTIONS section of Usage() for the list of options available to this
 * program.
 *
 * If "--" is encountered as an argument, no further option processing will
 * occur, even if a later argument begins with '-'.
 *
 * @param argc - number of argument pointers in array @a argv[].
 *
 * @param argv - array of argument string pointers to parse.
 *
 * @return the number of (non-option) command line arguments that remain in
 * @a argv[] after option processing.
 */
int ParseOptions(int argc, char* argv[]) {
    int rval = 1;       /* Skip program name. */
    char** non_option_argument_list = argv;
    int i = 0;
    int end_of_options = 0;
    for (i = 1; i < argc; ++i) {
        char* arg = argv[i];
        const char* opt = NULL;
        if (end_of_options || ('-' != *arg)) {
            non_option_argument_list[rval++] = arg;
        } else if (('-' == arg[1]) && (0 == arg[2])) {
            end_of_options = 1;
        } else if (IsOption(arg, NULL, "h:elp")) {
            Usage(stdout, 0);
        } else if (IsFlagOption(arg, &g_password, "p:assword")) {
        } else if (IsFlagOption(arg, &g_print_hash, "e:cho:-hash")) {
        } else if (IsOption(arg, &opt, "f:ile")) {
            if (NULL == opt) {
                fprintf(stderr, "%s: --file option requires argument\n", g_program);
                exit(2);
            }
            g_text_hash_file = opt;
        } else if (IsFlagOption(arg, &g_secure, "s:ecure")) {
        /* } else if (IsFlagOption(arg, &g_verbose, "v:erbose")) { */
        } else {
            PrintUsageError("invalid option \"%s\"", arg);
        }
    }
    return rval;
}   /* ParseOptions() */

/* ------------------------------------------------------------------------- */
/**
 * Perform a binary search for the given SHA1 @a hash in the memory-mapped
 * file and print the number of occurences of that hash to stdout, possibly
 * with the hash itself.
 *
 * When the hash is not found, print 0.
 *
 * @param file_data - mmap()'d pointer to the contents of a hash file in the
 * format of "pwned-passwords-ordered-2.0.txt".
 *
 * @param file_size - size, in bytes, of the data at @a file_data.
 *
 * @param hash - NUL-terminated string holding the hash to search. The string
 * should be exactly kTextHashChars in length.
 *
 * @param count - pointer to a count to hold the number of occurrences of @a
 * hash found in the file data.
 *
 * @return 1 if the hash was found, 0 otherwise.
 */
int find_hash(const char* data, off_t file_size, const char* hash, uint64_t* count) {
    off_t lo = 0;
    off_t hi = (file_size / kTextHashLineBytes) - 1;
    off_t mid = (lo + hi) / 2;
    int hash_len = strlen(hash);
    if (hash_len != kTextHashChars) {
        fprintf(stderr, "%s: hash '%s' should be %u bytes long, not %u\n", g_program, hash, kTextHashChars, hash_len);
        return 0;
    }

    while (1) {
        const char* file_hash = &data[mid * kTextHashLineBytes];
        char _file_hash[kTextHashChars+1] = {0};
        strncpy(_file_hash, file_hash, sizeof(_file_hash));
        _file_hash[kTextHashChars] = 0;
        int cmp = strncasecmp(hash, file_hash, kTextHashChars);
        /* printf("hash=%s file=%s lo=%-11llu mid=%-11llu hi=%-11llu  cmp=%d\n", */
        /*        hash, _file_hash, (long long) lo, (long long) mid, (long long) hi, cmp); */
        if (0 == cmp) {
            *count = atoi(&file_hash[kTextHashChars + 1]);  /* skip hash and colon */
            return 1;
        }
        if (lo == mid) {
            break;
        }
        if (cmp < 0) {
            hi = mid;
        } else {
            lo = mid;
        }
        mid = (lo + hi) / 2;
    }
    *count = 0;
    return 0;
}   /* find_hash() */

/* ------------------------------------------------------------------------- */
int handle_input(const char* input, const char* file_data, uint64_t file_size) {
    int found = 1;
    uint64_t count = 0 ;
    char hash[SHA1_TEXT_BYTES] = {0};
    if (g_password) {
        sha1_buffer_flags(input, strlen(input), hash, SHA1_FLAG_UPPER_CASE);
    } else if (strlen(input) != kTextHashChars) {
        fprintf(stderr, "%s: invalid SHA1 hash '%s' should have length %u but has length %u.\n",
                g_program, input, kTextHashChars, (unsigned int) strlen(input));
        return 0;
    } else {
        memcpy(hash, input, sizeof(hash) - 1);
    }
    found = find_hash(file_data, file_size, hash, &count);
    if (g_print_hash) {
        printf("%s:%llu\n", hash, (unsigned long long) count);
    } else {
        printf("%llu\n", (unsigned long long) count);
    }
}   /* handle_input() */

/* ------------------------------------------------------------------------- */
/**
 * Enable or disable echoing of input characters on stdin.
 *
 * @param enable - when 0, disable echoing of input characters, otherwise
 * enable echoing of character on stdin.
 */
void echo_on_stdin(int enable) {
    fprintf(stdout, "%s: %sabling echo of input\n", g_program, enable ? "en" : "dis");
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (enable) {
        tty.c_lflag |= ECHO;
    } else {
        tty.c_lflag &= ~ECHO;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}   /* echo_on_stdin() */

/* ------------------------------------------------------------------------- */
/**
 * Main program. Parses command line arguments. See Usage().
 *
 * @param argc - number of command line arguments, including program name.
 *
 * @param argv - list of pointers to command line argument strings.
 *
 * @return the program's exit code: 0 on success, something else on failure.
 */
int main(int argc, char* argv[]) {
    g_program = NamePartOfPath(argv[0]);
    argc = ParseOptions(argc, argv);  /* Remove options; leave program name and arguments. */
    int fd = open(g_text_hash_file, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: could not open '%s'\n", g_program, g_text_hash_file);
        return 2;
    }
    loff_t file_size =  lseek(fd, 0, SEEK_END);
    if (file_size < 0) {
        fprintf(stderr, "%s: _llseek() failed\n", g_program);
        return 3;
    }
    if ((0 == file_size) || (0 != (file_size % kTextHashLineBytes))) {
        fprintf(stderr, "%s: invalid file size %llu; should be > 0 and divisible by %u.\n",
                g_program, (long long) file_size, kTextHashLineBytes);
        return 4;
    }
    lseek(fd, 0, SEEK_SET);
    const char* file_data = (const char*) mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (NULL == file_data) {
        fprintf(stderr, "%s: mmap() failed\n", g_program);
        return 5;
    }
    int not_found = 0;
    if (argc > 1) {
        for (int i = 1; i < argc; ++i) {
            if (!handle_input(argv[i], file_data, file_size)) {
                not_found = 1;
            }
        }
    } else {
        if (g_password && g_secure && isatty(STDIN_FILENO)) {
            echo_on_stdin(0);
        }
        char* line = NULL;
        size_t alloc_n = 0;
        while (getline(&line, &alloc_n, stdin) >= 0) {
            size_t n = strlen(line);
            while ((n > 0) && ('\n' == line[n-1])) {
                line[--n] = 0;
            }
            if (!handle_input(line, file_data, file_size)) {
                not_found = 1;
            }
            free(line);
            line = NULL;
            alloc_n = 0;
        }
        if (g_password && g_secure && isatty(STDIN_FILENO)) {
            echo_on_stdin(1);
        }
    }
    munmap((void*) file_data, file_size);
    return 0;
}   /* main() */
