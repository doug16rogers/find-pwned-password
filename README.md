Haveibeenpwned Database Lookup
==============================

`find-pwned` looks for a SHA1 hash of a password in the pwned-password list
provided at:

    https://haveibeenpwned.com/Passwords

`find-pwned` takes a binary version of that file and looks up hashes (or
passwords) in the list. Currently the list consists of over 500 million
password hashes. This is similar to the password lookup offered on the web
page above, but it's local - it can be run offline.

Building the Program
--------------------

On any Unixy system with `gcc` you should be able to build this with:

```
    $ make
    gcc -o pwned2bin.o -Wall -Werror -std=c99 -c pwned2bin.c
    gcc -o pwned2bin pwned2bin.o
    gcc -o find-pwned.o -Wall -Werror -std=c99 -c find-pwned.c
    gcc -o sha1.o -Wall -Werror -std=c99 -c sha1.c
    gcc -o find-pwned find-pwned.o sha1.o
```

`pwned2bin` is used to prepare the hash file (see below).

Preparing the Hash File
-----------------------

The last two versions of the list (2.0 and 3.0) were provided as 7-zip
compressed files. The embedded files were text with a single hash and count
per line, separated by a colon. Version 2.0 was over 30 GB and had
fixed-length lines; version 3.0 is over 20 GB and has variable-length lines.

`find-pwned` uses a binary form of the hash file. To convert the input to
binary, download (or torrent) the password file *that is ordered by hash*,
then use the following after building the program with `make`:

```
    $ 7z x -so pwned-passwords-ordered-by-hash.7z \
       pwned-passwords-ordered-by-hash.txt | ./pwned2bin \
       > pwned-passwords-ordered-by-hash.bin
```

The name `pwned-passwords-ordered-by-hash.bin` is the default filename used
by the program, but you may keep multiple hash files around and use
`-f=<filename>` to select the hash file.

Note that the hash files *must* be sorted by hash.

Running `find-pwned`
--------------------

The program accepts input on the command line or from standard input. By
default the program accepts SHA1 hashes, but with `-p` it will generate the
password's hash for you. Normally the passwords are not printed to the
console but this may be disabled with `-no-secure`.

Here's a sample run:

```
    $ ./find-pwned -no-secure -p -pi -pp -ph -pc -file=../pwned-passwords-ordered-3.0.bin
    monkey123
    1:monkey123:721D65122734734800A1EDD6E68C03210E7B2ACA:60101
    password
    2:password:5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:3533661
    p@ssw0rd
    3:p@ssw0rd:57B2AD99044D337197C0C39FD3823568FF81E48A:49861
    never gonna guess me
    4:never gonna guess me:2F53394B7695ECBD651DB782181254FE88BB80C6:0
    Told you!
    5:Told you!:03B3B20CB98CD237D35DA4ABF5EB7650E915B34B:0
    ^D
```

`find-pwned` sets its exit status to 0 (success) only when a hash (or
password) is found in the hash list, it can be used to check for burned
passwords in scripts.

Usage information
-----------------

This is availabled directly from the program, but here ya go...

```
    $ ./find-pwned -h

    USAGE
        find-pwned [options] [hash...]

    DESCRIPTION
        find-pwned finds the hash given on the command line (or stdin if
        no command line arguments are given) in 'pwned-passwords-ordered-by-hash.bin'.

        find-pwned exits with 0 (success) if the hash or password is found. If
        any of the hashes or passwords is not found, 1 is set as the exit code.
        Errors will use an exit code that is neither 0 nor 1.

        find-pwned will print the count of passwords that were found with
        that hash. If the hash is not found, 0 is printed and an error status code
        is returned upon program exit.

        If no hashes are given on the command line, find-pwned will
        read them from stdin. When entering text in a tty from stdin, use Ctrl-D to
        end input.

        When -password is specified, find-pwned will treat each command
        line argument or line from stdin as a password rather than a hash. In this
        case, find-pwned will perform the SHA1 hash of the password and
        search for the associated hash. When reading from a tty with -secure (see
        OPTIONS), find-pwned will disable echoing to protect the password.

    CREATING HASH FILE
        find-pwned was developed to use the hash files graciously provided
        by Troy at:

            https://haveibeenpwned.com/Passwords

        Thanks, Troy! The pwned-password files there are text files with one hash
        per line. Version 2.0 had fixed-length lines which allowed them to be
        mapped and searched easily. Version 3.0, though, has variable-length lines
        which save a lot of space but make mapping less amenable to binary search.

        So as of version 3.0 this program no longer accepts the native text file
        but requires that you convert the text file to binary. Here's an example
        of how to do that:

           $ 7z x -so pwned-passwords-ordered-by-hash.7z \
               pwned-passwords-ordered-by-hash.txt | ./pwned2bin \
                > pwned-passwords-ordered-by-hash.bin


    OPTIONS
        Options may begin with '-' or '--'. A ':' indicates where options may be
        abbreviated

        -h:elp                      Show this usage information.
        -V, -version                Print version and copyright then exit.
        -q:uiet                     Quiet - suppress normal output.

        -f:ile=filename             Name of binary hash file that should be sorted
                                    by hash. [pwned-passwords-ordered-by-hash.bin]
        -[no-]p:assword             Inputs are passwords that must be hashed. [-no-password]
        -d:elim:iter=STRING         Delimiter to use for output fields. [:]
        -[no-]pi                    Print index in result. [-no-pi]
        -[no-]pp                    Print password in result when using '-p'. [-no-pp]
        -[no-]ph                    Print hash in result. [-no-ph]
        -[no-]pc                    Print occurrence count in result'. [-pc]
        -[no-]s:ecure               Inhibit echo of password in interactive shell. [-secure]
        -[no-]pf                    Print values that appear in database. [-pf]
        -[no-]pnf                   Print values that do *not* appear in database. [-pnf]
        -[no-]v:erbose              Print verbose (debug) messages. [-no-verbose]
```
