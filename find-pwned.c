/* Copyright (c) 2018 Doug Rogers under the terms of the MIT License. */
/* See http://www.opensource.org/licenses/mit-license.html.. */
/* $Id$ */

/**
 * find-pwned-password-hash Look up password hash in mambo list of them.
 *
 * This program searches for a given SHA1 hash in a sorted file of hashes and
 * occurrence counts. The input file is expected to have binary records that
 * are 24 bytes long. The first 20 bytes are the SHA1 hash of the password
 * and the next 4 bytes are a 32-bit little-endian occurrence count for the
 * corresponding password.
 *
 * A set of text hashes is provided by https://haveibeenpwned.com/Passwords.
 * The last two major versions (2.0 and 3.0) provide those passwords in text
 * files wrapped inside a 7z wrapper. Version 2.0 provided fixed-length
 * space-padded lines (63 bytes!) while version 3.0 provides variable-length
 * lines. To extract either of those into a binary, first build `pwned2bin`
 * in this directory (use `make`) then use:
 *
 * $ 7z x -so pwned-passwords-ordered-by-hash.7z \
 *       pwned-passwords-ordered-by-hash.txt | ./pwned2bin \
 *       > pwned-passwords-ordered-by-hash.bin
 *
 * This may take a few minutes. It may take a LOT of minutes!
 *
 * The program accepts SHA1 password *hashes* on the command line or via
 * stdin.
 *
 * The program will also accept passwords as input (-p), in which case it
 * will perform a SHA1 hash of each password then search for the resulting
 * hash. If stdin is a tty then the program will disable echoing from stdin
 * unless explicitly told not to with -no-secure.
 *
 * Use '-h' to see the options available.
 */

#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
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
 * Discrete version information.
 */
#define VERSION_MAJOR 3
#define VERSION_MINOR 0
#define VERSION_PATCH 0

#define STRING_VALUE(x) #x
#define EXPAND_VALUE(a) STRING_VALUE(a)

/**
 * Version information as a string.
 */
#define VERSION_TEXT (EXPAND_VALUE(VERSION_MAJOR) "."EXPAND_VALUE(VERSION_MINOR) "."EXPAND_VALUE(VERSION_PATCH))

/**
 * Size of binary SHA1 hash in bytes.
 */
#define kBinHashBytes SHA1_BINARY_BYTES

/**
 * Size of text SHA1 hash in bytes, not including a terminating NUL.
 */
#define kTextHashChars (2 * SHA1_BINARY_BYTES)

/**
 * An individual binary record consists of the SHA1 hash of a password
 * followed by an occurrence count.
 */
struct pwned_info_s {
    uint8_t hash[SHA1_BINARY_BYTES];    /**< SHA1 hash of password. */
    uint32_t count;                     /**< Number of times password was found in breaches. */
} __attribute__((packed));

typedef struct pwned_info_s pwned_info_t;

/**
 * Handy 64-bit size of the struct.
 */
const uint64_t kPwnedInfoSize = sizeof(pwned_info_t);

/**
 * Name of this program; this may be modified by argv[0] in main().
 */
const char* g_program = kProgram;

/**
 * Name of the text hash file. The file should be sorted by hash
 */
#define kDefaultHashFile "pwned-passwords-ordered-by-hash.bin"

/**
 * File of binary hashes and counts.
 */
const char* g_hash_file = kDefaultHashFile;

/**
 * Number of items so far processed.
 */
uint64_t g_count = 0;

/**
 * Whether or not to emit verbose messages.
 */
#define kDefaultVerbose 0
int g_verbose = kDefaultVerbose;

/**
 * Whether or not to suppress normal output.
 */
#define kDefaultQuiet 0
int g_quiet = kDefaultQuiet;

/**
 * Whether or not to print the index - the item number.
 */
#define kDefaultPrintIndex 0
int g_print_index = kDefaultPrintIndex;

/**
 * Whether or not to print the password when using '-p'.
 */
#define kDefaultPrintPassword 0
int g_print_password = kDefaultPrintPassword;

/**
 * Whether or not to print '<hash>:<count>' rather than '<count>'.
 */
#define kDefaultPrintHash 0
int g_print_hash = kDefaultPrintHash;

/**
 * Whether or not to print the occurrence count.
 */
#define kDefaultPrintCount 1
int g_print_count = kDefaultPrintCount;

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

/**
 * Whether or not to print items found in the database.
 */
#define kDefaultPrintFound 1
int g_print_found = kDefaultPrintFound;

/**
 * Whether or not to print items *not* found in the database.
 */
#define kDefaultPrintNotFound 1
int g_print_not_found = kDefaultPrintNotFound;

/**
 * Delimiter to use for fields when printing to output.
 */
#define kDefaultDelimiter ":"
const char* g_delimiter = kDefaultDelimiter;

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
            "    %s finds the hash given on the command line (or stdin if\n"
            "    no command line arguments are given) in '%s'.\n"
            "\n"
            "    %s exits with 0 (success) if the hash or password is found. If\n"
            "    any of the hashes or passwords is not found, 1 is set as the exit code.\n"
            "    Errors will use an exit code that is neither 0 nor 1.\n"
            "\n"
            , g_program, kDefaultHashFile, g_program);
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
            "CREATING HASH FILE\n"
            "    %s was developed to use the hash files graciously provided\n"
            "    by Troy at:\n"
            "\n"
            "        https://haveibeenpwned.com/Passwords\n"
            "\n"
            "    Thanks, Troy! The pwned-password files there are text files with one hash\n"
            "    per line. Version 2.0 had fixed-length lines which allowed them to be\n"
            "    mapped and searched easily. Version 3.0, though, has variable-length lines\n"
            "    which save a lot of space but make mapping less amenable to binary search.\n"
            "\n"
            "    So as of version 3.0 this program no longer accepts the native text file\n"
            "    but requires that you convert the text file to binary. Here's an example\n"
            "    of how to do that:\n"
            "\n"
            "       $ 7z x -so pwned-passwords-ordered-by-hash.7z \\\n"
            "           pwned-passwords-ordered-by-hash.txt | ./pwned2bin \\\n"
            "            > pwned-passwords-ordered-by-hash.bin\n"
            "\n"
            , g_program);
    fprintf(file,
            "\n"
            "OPTIONS\n"
            "    Options may begin with '-' or '--'. A ':' indicates where options may be\n"
            "    abbreviated\n");
    fprintf(file,
            "\n"
            "    -h:elp                      Show this usage information.\n");
    fprintf(file,
            "    -V, -version                Print version and copyright then exit.\n");
    fprintf(file,
            "    -q:uiet                     Quiet - suppress normal output.\n");
    fprintf(file,
           "\n"
            "    -f:ile=filename             Name of binary hash file that should be sorted\n"
            "                                by hash. [%s]\n"
            , kDefaultHashFile);
    fprintf(file,
            "    -[no-]p:assword             Inputs are passwords that must be hashed. [%s-password]\n"
            , kDefaultPassword ? "" : "-no");
    fprintf(file,
            "    -d:elim:iter=STRING         Delimiter to use for output fields. [%s]\n"
            , kDefaultDelimiter);
    fprintf(file,
            "    -[no-]pi                    Print index in result. [%s-pi]\n"
            , kDefaultPrintIndex ? "" : "-no");
    fprintf(file,
            "    -[no-]pp                    Print password in result when using '-p'. [%s-pp]\n"
            , kDefaultPrintPassword ? "" : "-no");
    fprintf(file,
            "    -[no-]ph                    Print hash in result. [%s-ph]\n"
            , kDefaultPrintHash ? "" : "-no");
    fprintf(file,
            "    -[no-]pc                    Print occurrence count in result'. [%s-pc]\n"
            , kDefaultPrintCount ? "" : "-no");
    fprintf(file,
            "    -[no-]s:ecure               Inhibit echo of password in interactive shell. [%s-secure]\n"
            , kDefaultSecure ? "" : "-no");
    fprintf(file,
            "    -[no-]pf                    Print values that appear in database. [%s-pf]\n"
            , kDefaultPrintFound ? "" : "-no");
    fprintf(file,
            "    -[no-]pnf                   Print values that do *not* appear in database. [%s-pnf]\n"
            , kDefaultPrintNotFound ? "" : "-no");
    fprintf(file,
            "    -[no-]v:erbose              Print verbose (debug) messages. [%s-verbose]\n"
            , kDefaultVerbose ? "" : "-no");
    exit(exit_code);
}   /* Usage() */

/* ------------------------------------------------------------------------- */
/**
 * Print an error message to stderr then exit the program with @p exit_code
 * if @p exit_code is non-zero.
 */
void PrintUsageError(int exit_code, const char* format, ...) {
    char text[0x0100] = "";
    va_list va;
    va_start(va, format);
    vsnprintf(text, sizeof(text), format, va);
    va_end(va);
    fprintf(stderr, "%s: %s\n", g_program, text);
    fprintf(stderr, "%s: Use '%s --help' for usage information.\n", g_program, g_program);
    if (exit_code) {
        exit(exit_code);
    }
}   /* PrintUsageError() */

/* ------------------------------------------------------------------------- */
/**
 * Print an error message to stderr.
 */
void PrintError(const char* format, ...) {
    char text[0x0100] = "";
    va_list va;
    va_start(va, format);
    vsnprintf(text, sizeof(text), format, va);
    va_end(va);
    fprintf(stderr, "%s: %s\n", g_program, text);
}   /* PrintError() */

/* ------------------------------------------------------------------------- */
/**
 * Print a verbose (debug) message to stderr if g_verbose is non-zero.
 */
void PrintVerbose(const char* format, ...) {
    if (g_verbose) {
        char text[0x0100] = "";
        va_list va;
        va_start(va, format);
        vsnprintf(text, sizeof(text), format, va);
        va_end(va);
        fprintf(stderr, "%s: %s\n", g_program, text);
    }
}   /* PrintVerbose() */

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
        } else if (IsFlagOption(arg, &g_quiet, "q:uiet")) {
        } else if (IsOption(arg, &opt, "d:elim:iter")) {
            if (NULL == opt) {
                PrintUsageError(2, "--delimiter option requires argument");
            }
            g_delimiter = opt;
        } else if (IsFlagOption(arg, &g_password, "p:assword")) {
        } else if (IsFlagOption(arg, &g_print_index, "pi")) {
        } else if (IsFlagOption(arg, &g_print_password, "pp")) {
        } else if (IsFlagOption(arg, &g_print_hash, "ph")) {
        } else if (IsFlagOption(arg, &g_print_count, "pc")) {
        } else if (IsOption(arg, &opt, "f:ile")) {
            if (NULL == opt) {
                PrintUsageError(2, "--file option requires argument");
            }
            g_hash_file = opt;
        } else if (IsFlagOption(arg, &g_secure, "s:ecure")) {
        } else if (IsFlagOption(arg, &g_print_found, "pf")) {
        } else if (IsFlagOption(arg, &g_print_not_found, "pnf")) {
        } else if (IsFlagOption(arg, &g_verbose, "v:erbose")) {
        } else if (IsOption(arg, NULL, "V") || IsOption(arg, NULL, "version")) {
            fprintf(stdout, "%s: v%s\n", g_program, VERSION_TEXT);
            fprintf(stdout, "Copyright (c) Doug Rogers under the MIT License.\n");
            exit(0);
        } else {
            PrintUsageError(2, "invalid option \"%s\"", arg);
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
int find_hash(const pwned_info_t* data, off_t file_size, const uint8_t* hash, uint64_t* count) {
    off_t lo = 0;
    off_t hi = (file_size / kPwnedInfoSize) - 1;
    off_t mid = (lo + hi) / 2;

    while (1) {
        const pwned_info_t* pwned = &data[mid];
        int cmp = memcmp(hash, pwned->hash, SHA1_BINARY_BYTES);
        if (0 == cmp) {
            *count = pwned->count;
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
static inline int hexval(char c) {
    if (('0' <= c) && (c <= '9')) return c - '0';
    if (('A' <= c) && (c <= 'F')) return 10 + c - 'A';
    if (('a' <= c) && (c <= 'f')) return 10 + c - 'a';
    return -1;
}   /* hexval() */

/* ------------------------------------------------------------------------- */
static int hex2byte(const char* h, uint8_t* byte) {
    assert(NULL != byte);
    int hi = hexval(h[0]);
    int lo = hexval(h[1]);
    if ((hi < 0) || (lo < 0)) {
        return 0;
    }
    *byte = (hi * 16) + lo;
    return 1;
}   /* hex2byte() */

/* ------------------------------------------------------------------------- */
int handle_input(const char* input, const char* file_data, uint64_t file_size) {
    int found = 1;
    uint64_t count = 0 ;
    uint8_t hash[SHA1_BINARY_BYTES] = {0};
    g_count++;
    if (g_password) {
        sha1_buffer_bin(input, strlen(input), hash);
    } else if (strlen(input) != kTextHashChars) {
        PrintUsageError(0, "invalid SHA1 hash '%s' should have length %u but has length %u.",
                        input, kTextHashChars, (unsigned int) strlen(input));
        return 0;
    } else {
        for (int i = 0; i < SHA1_BINARY_BYTES; ++i) {
            if (!hex2byte(&input[2*i], &hash[i])) {
                PrintUsageError(0, "invalid 2-digit hex byte at index %d of hash '%s'", 2*i, input);
                return 0;
            }
        }
    }
    found = find_hash((const pwned_info_t*) file_data, file_size, hash, &count);
    if (!g_quiet) {
        const char* delim = "";
        if ((found && g_print_found) ||
            (!found && g_print_not_found)) {
            if (g_print_index) {
                printf("%s%" PRIu64, delim, g_count);
                delim = g_delimiter;
            }
            if (g_print_password && g_password) {
                printf("%s%s", delim, input);
                delim = g_delimiter;
            }
            if (g_print_hash) {
                printf("%s", delim);
                for (int i = 0; i < SHA1_BINARY_BYTES; ++i) {
                    printf("%02X", hash[i]);
                }
                delim = g_delimiter;
            }
            if (g_print_count) {
                printf("%s%" PRIu64, delim, count);
                delim = g_delimiter;
            }
            if (delim == g_delimiter) {
                printf("\n");
            }
        }
    }
    return found;
}   /* handle_input() */

/* ------------------------------------------------------------------------- */
/**
 * Enable or disable echoing of input characters on stdin.
 *
 * @param enable - when 0, disable echoing of input characters, otherwise
 * enable echoing of character on stdin.
 */
void echo_on_stdin(int enable) {
    PrintVerbose("%sabling echo of input", enable ? "en" : "dis");
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
    assert(sizeof(pwned_info_t) == 24);
    argc = ParseOptions(argc, argv);  /* Remove options; leave program name and arguments. */
    int fd = open(g_hash_file, O_RDONLY);
    if (fd < 0) {
        PrintUsageError(2, "could not open \"%s\"", g_hash_file);
    }
    off_t file_size =  lseek(fd, 0, SEEK_END);
    if (file_size < 0) {
        PrintError("_llseek() failed");
        return 3;
    }
    if ((0 == file_size) || (0 != (file_size % kPwnedInfoSize))) {
        PrintUsageError(3, "invalid file size %" PRIu64 "; should be > 0 and divisible by %" PRIu64 ".",
                        file_size, kPwnedInfoSize);
        return 4;
    }
    lseek(fd, 0, SEEK_SET);
    uint64_t hashes = file_size / kPwnedInfoSize;
    PrintVerbose("file \"%s\" size=%" PRIu64 " bytes, %" PRIu64 " hash%s.",
                 g_hash_file, file_size, hashes, (1 == hashes) ? "" : "es");

    const char* file_data = (const char*) mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (NULL == file_data) {
        PrintError("mmap() failed");
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
        char line[0x100] = "";
        while (NULL != fgets(line, sizeof(line), stdin)) {
            size_t n = strlen(line);
            while ((n > 0) && ('\n' == line[n-1])) {
                line[--n] = 0;
            }
            if (!handle_input(line, file_data, file_size)) {
                not_found = 1;
            }
        }
        if (g_password && g_secure && isatty(STDIN_FILENO)) {
            echo_on_stdin(1);
        }
    }
    munmap((void*) file_data, file_size);
    return not_found ? 1 : 0;
}   /* main() */
