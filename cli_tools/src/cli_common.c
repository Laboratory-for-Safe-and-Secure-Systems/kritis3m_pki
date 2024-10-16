#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "cli_common.h"


/* Read the content of the file from `filePath` and store it in `buffer`. On function
 * entry, `bufferSize` must contain the size of the provided buffer. After function
 * exit, the number of read bytes is stored in `bufferSize`.
 *
 * Returns 0 on success, -1 in case of an error.
 */
int readFile(const char* filePath, uint8_t* buffer, size_t* bufferSize)
{
        /* Open the file */
        FILE* file = fopen(filePath, "rb");

        if (file == NULL)
        {
                printf("file (%s) cannot be opened\n", filePath);
                return -1;
        }

        /* Get length of file */
        fseek(file, 0, SEEK_END);
        long fileSize = ftell(file);
        rewind(file);

        if ((size_t)fileSize > *bufferSize)
        {
                printf("file (%s) is too large for buffer\n", filePath);
                fclose(file);
                return -1;
        }

        /* Read file to buffer */
        int bytesRead = 0;
        while (bytesRead < fileSize)
        {
                int read = fread(buffer + bytesRead, sizeof(uint8_t), fileSize - bytesRead, file);
                if (read < 0)
                {
                        printf("unable to read file (%s)\n", filePath);
                        fclose(file);
                        return -1;
                }
                bytesRead += read;
        }

        fclose(file);

        *bufferSize = bytesRead;

        return 0;
}


/* Write `bufferSize` bytes from `buffer` to the file at `filePath`. If `append` is true,
 * the content is appended to the file, otherwise the file is overwritten.
 *
 * Returns 0 on success, -1 in case of an error.
 */
int writeFile(const char* filePath, uint8_t* buffer, size_t bufferSize, bool append)
{
        /* Open the file */
        FILE* file = fopen(filePath, append ? "ab" : "wb");

        if (file == NULL)
        {
                printf("file (%s) cannot be opened: %s\n", filePath, strerror(errno));
                return -1;
        }

        /* Write buffer to file */
        size_t bytesWriten = 0;
        uint8_t* ptr = buffer;
        while (bytesWriten < bufferSize)
        {
                int written = fwrite(ptr, sizeof(uint8_t), bufferSize - bytesWriten, file);
                if (written < 0)
                {
                        printf("unable to write file (%s)\n", filePath);
                        fclose(file);
                        return -1;
                }
                bytesWriten += written;
                ptr += written;
        }

        fclose(file);

        return 0;
}

