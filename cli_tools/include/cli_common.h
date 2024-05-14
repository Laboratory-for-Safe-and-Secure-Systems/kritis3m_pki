#ifndef CLI_COMMON_H
#define CLI_COMMON_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

int readFile(const char* filePath, uint8_t* buffer, size_t* bufferSize);

int writeFile(const char* filePath, uint8_t* buffer, size_t bufferSize);

#endif /* CLI_COMMON_H */
