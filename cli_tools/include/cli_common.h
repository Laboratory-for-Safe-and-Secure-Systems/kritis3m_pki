#ifndef CLI_COMMON_H
#define CLI_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* Read the content of the file from `filePath` and store it in `buffer`. On function
 * entry, `bufferSize` must contain the size of the provided buffer. After function
 * exit, the number of read bytes is stored in `bufferSize`.
 *
 * Returns 0 on success, -1 in case of an error.
 */
int readFile(const char* filePath, uint8_t* buffer, size_t* bufferSize);

/* Write `bufferSize` bytes from `buffer` to the file at `filePath`. If `append` is true,
 * the content is appended to the file, otherwise the file is overwritten.
 *
 * Returns 0 on success, -1 in case of an error.
 */
int writeFile(const char* filePath, uint8_t* buffer, size_t bufferSize, bool append);

#endif /* CLI_COMMON_H */
