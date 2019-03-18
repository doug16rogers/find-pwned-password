/* (c) 2018 Doug Rogers under Zero Clause BSD License. See LICENSE.txt. */
/* You are free to do whatever you want with this software. Have at it! */

#ifndef BSD_0_CLAUSE_LICENSE_H_
#define BSD_0_CLAUSE_LICENSE_H_

#include <stdio.h>

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Print the BSD 0-clause license for the given range of years and the given 
 * copyright holder. This does *NOT* print the disclaimer. See
 * https://en.wikipedia.org/wiki/BSD_licenses.
 *
 * If @p copyright_last_year is less than or equal to @p copyright_first_year
 * then only a single year will be printed.
 *
 * Use print_bsd_0_clause_disclaimer() to print the associated "AS-IS"
 * disclaimer.
 *
 * @param stream - FILE stream to which to print the license terms.
 *
 * @param copyright_first_year - first year in range of copyright years.
 *
 * @param copyright_last_year - last year in range of copyright years;
 * ignored if this is less than or equal to @p copyright_first_year.
 *
 * @param copyright_holder - name of copyright holder.
 */
void print_bsd_0_clause_license(FILE *stream,
                                int copyright_first_year,
                                int copyright_last_year,
                                const char *copyright_holder);

/**
 * Print the "AS-IS" disclaimer that accompanies the BSD 0-clause license.
 *
 * @param stream - FILE stream to which to print the disclaimer.
 */
void print_bsd_0_clause_disclaimer(FILE *stream);

/**
 * Same as:
 * ```
 *     print_bsd_0_clause_license(stream,
 *                                copyright_first_year,
 *                                copyright_last_year,
 *                                copyright_holder);
 *     print_bsd_0_clause_disclaimer(stream);
 * ```
 */
void print_bsd_0_clause_license_and_disclaimer(FILE *stream,
                                               int copyright_first_year,
                                               int copyright_last_year,
                                               const char *copyright_holder);
#if defined(__cplusplus)
}
#endif

#endif  // BSD_0_CLAUSE_LICENSE_H_
