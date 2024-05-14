#include <stdio.h>

#include "cli_common.h"


int readFile(const char* filePath, uint8_t* buffer, size_t* bufferSize)
{
        /* Open the file */
        FILE* file = fopen(filePath, "r");

        if (file == NULL)
        {
                printf("file (%s) cannot be opened\n", filePath);
                return -1;
        }

        /* Get length of file */
        fseek(file, 0, SEEK_END);
        int fileSize = ftell(file);
        rewind(file);

        if (fileSize > *bufferSize)
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


int writeFile(const char* filePath, uint8_t* buffer, size_t bufferSize)
{
        /* Open the file */
        FILE* file = fopen(filePath, "wb");

        if (file == NULL)
        {
                printf("file (%s) cannot be opened\n", filePath);
                return -1;
        }

        /* Write buffer to file */
        int bytesWriten = 0;
        uint8_t* ptr = buffer;
        while (bytesWriten < bufferSize)
        {
                int writen = fwrite(ptr, sizeof(uint8_t), bufferSize - bytesWriten, file);
                if (writen < 0)
                {
                        printf("unable to write file (%s)\n", filePath);
                        fclose(file);
                        return -1;
                }
                bytesWriten += writen;
                ptr += writen;
        }

        fclose(file);

        return 0;
}

