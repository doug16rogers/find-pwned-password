/* (c) 2018 Doug Rogers under Zero Clause BSD License. See LICENSE.txt. */
/* You are free to do whatever you want with this software. Have at it! */

#include "bsd_0_clause_license.h"

/* ------------------------------------------------------------------------- */
void print_bsd_0_clause_license(FILE *stream,
                                int copyright_first_year,
                                int copyright_last_year,
                                const char *copyright_holder) {
    if (copyright_last_year <= copyright_first_year) {
        fprintf(stream, "Copyright (C) %d by %s\n",
                copyright_first_year,
                copyright_holder ? copyright_holder : "Software Developer");
    } else {
        fprintf(stream, "Copyright (C) %d-%d by %s\n",
                copyright_first_year, copyright_last_year,
                copyright_holder ? copyright_holder : "Software Developer");
    }
    fputs(
        "\n"
        "Permission to use, copy, modify, and/or distribute this software for any\n"
        "purpose with or without fee is hereby granted.\n", stream);
}   /* print_bsd_0_clause_license() */

/* ------------------------------------------------------------------------- */
void print_bsd_0_clause_disclaimer(FILE *stream) {
    fputs("THE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH\n"
          "REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY\n"
          "AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,\n"
          "INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM\n"
          "LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR\n"
          "OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR\n"
          "PERFORMANCE OF THIS SOFTWARE.\n", stream);
}   /* print_bsd_0_clause_disclaimer() */

/* ------------------------------------------------------------------------- */
void print_bsd_0_clause_license_and_disclaimer(FILE *stream,
                                               int copyright_first_year,
                                               int copyright_last_year,
                                               const char *copyright_holder) {
    print_bsd_0_clause_license(stream,
                               copyright_first_year,
                               copyright_last_year,
                               copyright_holder);
    fputs("\n", stream);
    print_bsd_0_clause_disclaimer(stream);
}   /* print_bsd_0_clause_license_and_disclaimer() */
