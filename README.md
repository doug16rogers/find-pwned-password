Haveibeenpwned Database Lookup
==============================

Old Notes
=========

Here are some notes about the haveibeenpwned.com password hash database,
version 2.0.

Included in this repository is a program called 'find-pwned-password-hash'
that allows for easier searching through the database. Using grep will work
but a linear search is just too slow for the failure case.

How to get the database
-----------------------

Download (torrent) the files from:

    https://haveibeenpwned.com/Passwords

These are collections of hashes, not passwords. They're SHA-1 hashed without
salt.

Using find-pwned-password-hash
------------------------------

To build it just use 'make'. Then here's a sample run:

```
    $ ./find-pwned-password-hash -p -e -no-secure -f=../pwned-passwords-ordered-2.0.txt
    monkey
    AB87D24BDC7452E55738DEB5F868E1F16DEA5ACE:932064
    password
    5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:3303003
    123456
    7C4A8D09CA3762AF61E59520943DC26494F8941B:20760336
    ThisPasswordAin'tInThere
    69799DEDFDECC043D04A80387341FD40805506E4:0
    ^D
```

Pretty easy. If it ends in ':0' then the password is not in the
list. Normally the passwords are not echoed from the command line.

Usage information
-----------------

Use -h for usage info:

```
    $ ./find-pwned-password-hash -h

    USAGE
        find-pwned-password-hash [options] [hash...]

    DESCRIPTION
        find-pwned-password-hash finds the hash given on the command line (or stdin if no
        command line arguments are given) in 'pwned-passwords-ordered-2.0.txt'.

        find-pwned-password-hash will print the count of passwords that were found with
        that hash. If the hash is not found, 0 is printed and an error status code
        is returned upon program exit.

        If no hashes are given on the command line, find-pwned-password-hash will
        read them from stdin. When entering text in a tty from stdin, use Ctrl-D to
        end input.

        When -password is specified, find-pwned-password-hash will treat each command
        line argument or line from stdin as a password rather than a hash. In this
        case, find-pwned-password-hash will perform the SHA1 hash of the password and
        search for the associated hash. When reading from a tty with -secure (see
        OPTIONS), find-pwned-password-hash will disable echoing to protect the password.

    OPTIONS
        Options may begin with '-' or '--'. A ':' indicates where options may be
        abbreviated

        -h:elp                      Show this usage information.

        -f:ile=filename             Name of text hash file. [pwned-passwords-ordered-2.0.txt]
        -[no-]p:assword             Inputs are passwords that must be hashed. [-no-password]
        -[no-]e:cho:-hash           Print '<hash>:<count>' instead of just <count>. [-no-echo-hash]
        -[no-]s:ecure               Inhibit echo of password in interactive shell. [-secure]

```

Querying the database from a shell script
-----------------------------------------

To determine if a password is in the collection, run:

```
    $ grep -i -m1 $(echo -n 'password' | sha1sum | cut -f1 '-d ') \
          pwned-passwords-2.0.txt
```

Hey, it works. It's better to read the password without echo from stdin, like
this script:

```
    $ cat try-password.sh
    #!/bin/bash

    while read -s -p "Password to check (Ctrl-C to quit): " pass; do
        start=$SECONDS
        hash=$(echo -n "$pass" | sha1sum | cut -f1 '-d ' | tr [:lower:] [:upper:])
        pass=""
        echo -e "\nLooking for hash $hash."
        echo -n "... "
        result=$(grep -m1 "^$hash" pwned-passwords-2.0.txt | tr -d ' \r\n')
        if [[ -z "$result" ]]; then
            result="<not-found>"
        fi
        stop=$SECONDS
        echo "$result ($[stop-start]s)"
    done
```

Note that grepping through a 31GB file can take quite a while. It took 2416s
for the first miss! The next miss - my password for Kickstarter - took just
365s (to miss). Better, but still too slow. I need it to be in the sub-second
range.

Converting to binary format (not used)
--------------------------------------

Looking at going binary. SHA-1 is 20 bytes, plus 4 bytes for a count (if I
even care). The file will be just 12GB (or 10GB) then. I can create a better
data structure for lookups using the hash-ordered file.

```
    $ wc -l pwned-passwords-2.0.txt
    501636842 pwned-passwords-2.0.txt

    $ echo $[501636842 * (20+4)]
    12039284208

    $ echo $[501636842 * (20)]
    10032736840
```

Also, the file pwned-passwords-ordered-2.0.txt is ordered by hash rather than
prevalence. That will be easier to use in a binary lookup.

Each line in the text files ends in a string of spaces (20s) followed by
CR/LF (0D 0A) that pads the line out to 63 bytes, strangely:

```
      $ ls -l pwn*.txt
      -rw-r--r-- 1 durg durg 31603121046 Feb 15 05:02 pwned-passwords-2.0.txt
      -rw-r--r-- 1 durg durg 31603121046 Feb 16 23:13 pwned-passwords-ordered-2.0.txt

      $ echo $[ 31603121046 / 501636842 ]
      63

      $ echo $[ 31603121046 - (63 *  501636842) ]
      0

      $ hex -n40 pwned-passwords-2.0.txt
      00000: 37 43 34 41  38 44 30 39  43 41 33 37  36 32 41 46 |7C4A8D09CA3762AF|
      00010: 36 31 45 35  39 35 32 30  39 34 33 44  43 32 36 34 |61E59520943DC264|
      00020: 39 34 46 38  39 34 31 42  3A 32 30 37  36 30 33 33 |94F8941B:2076033|
      00030: 36 20 20 20  20 20 20 20  20 20 20 20  20 0D 0A 46 |6              F|

      $ hex -n30 pwned-passwords-2.0.bin
      00000: 7C 4A 8D 09  CA 37 62 AF  61 E5 95 20  94 3D C2 64 ||J   7b a    = d|
      00010: 94 F8 94 1B  10 C7 3C 01  F7 C3 BC 1D  80 8E 04 73 |      <        s|
      00020: 2A DF 67 99  65 CC C3 4C  A7 AE 34 41  DD 10 6B 00 |* g e  L  4A  k |
```

I was able to determine the first few passwords below.

```
      $ head -25 pwned-passwords-2.0.txt     # Then edit....
      7C4A8D09CA3762AF61E59520943DC26494F8941B:20760336 123456
      F7C3BC1D808E04732ADF679965CCC34CA7AE3441:7016669  123456789
      B1B3773A05C0ED0176787A4F1574FF0075F7521E:3599486  qwerty
      5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:3303003  password
      3D4F2BF07DC1BE38B20CD6E46949A1071F9D0E3D:2900049  111111
      7C222FB2927D828AF22F592134E8932480637C0D:2680521  12345678
      6367C48DD193D56EA7B0BAAD25B19455E529F5EE:2670319  abc123
      E38AD214943DAAD1D64C102FAEC29DE4AFE9DA3D:2310111  password1
      20EABE5D64B0E216796E834F52D61FD0B70332FC:2298084  1234567
      8CB2237D0679CA88DB6464EAC60DA96345513964:2088998  12345
      01B307ACBA4F54F55AAFC33BB06BBBF6CA803E9A:2075018  1234567890
      601F1889667EFAEBB33B8C12572835DA3F027F78:2048411  123123
      ...
```

Next will be a dictionary search. There are plenty of password lists out
there so this will be easy to fill in.
