/* Copyright 2024 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef __STB_DILUTILS_H
#define __STB_DILUTILS_H

enum
{
    RawDilithiumR28x7PublicKeySize  = 2336,
    RawDilithiumR28x7PrivateKeySize = 5136,
    SHA3_512_DigestSize             = (512 / 8),
};

int readFile(unsigned char* data, size_t* length, const char* filename);
int writeFile(const unsigned char* data, size_t length, const char* filename);

int readFile(unsigned char* data, size_t* length, const char* filename)
{
    int    sRc    = 0;
    size_t sBytes = 0;
    FILE*  sFile  = NULL;

    if(NULL == data || NULL == length || NULL == filename)
    {
        printf("**** ERROR : readFile: Invalid parms\n");
        sRc = 1;
    }

    if(0 == sRc)
    {
        sFile = fopen(filename, "rb");
        if(NULL == sFile)
        {
            printf("**** ERROR: readFile: Unable to open file : %s\n", filename);
            sRc = 1;
        }
    }

    /* Verify we have enough space */
    if(0 == sRc)
    {
        sRc = fseek(sFile, 0, SEEK_END);
        if(-1 == sRc)
        {
            printf("**** ERROR : readFile: Unable to find end of : %s\n", filename);
            sRc = 1;
        }
    }

    if(0 == sRc)
    {
        long sLen = ftell(sFile);
        if(-1 == sLen)
        {
            printf("**** ERROR : readFile: Unable to determine length of %s\n", filename);
            sRc = 1;
        }
        else if(*length < (size_t)sLen)
        {
            printf(
                "**** ERROR : readFile: Not enough space for contents of file E:%lu A:%lu : %s\n",
                (size_t)sLen,
                *length,
                filename);
            sRc = 1;
        }
        else
        {
            *length = (size_t)sLen;
        }
    }

    if(0 == sRc)
    {
        fseek(sFile, 0, SEEK_SET);

        sBytes = fread(data, 1, *length, sFile);
        if(sBytes != *length)
        {
            printf("**** ERROR: readFile: Failure reading from file : %s\n", filename);
            sRc = 1;
        }
    }
    if(NULL != sFile)
    {
        if(fclose(sFile))
        {
            printf("**** ERROR: readFile: Failure closing file : %s\n", filename);
            if(0 == sRc)
                sRc = 1;
        }
    }
    return sRc;
}

int writeFile(const unsigned char* data, size_t length, const char* filename)
{
    int    sRc    = 0;
    size_t sBytes = 0;
    FILE*  sFile  = NULL;

    if(NULL == data || NULL == filename)
    {
        printf("**** ERROR : writeFile: Invalid parms\n");
        sRc = 1;
    }

    if(0 == sRc)
    {
        sFile = fopen(filename, "wb");
        if(NULL == sFile)
        {
            printf("**** ERROR: writeFile: Unable to open file : %s\n", filename);
            sRc = 1;
        }
    }

    if(0 == sRc)
    {
        sBytes = fwrite(data, 1, length, sFile);
        if(sBytes != length)
        {
            printf("**** ERROR: writeFile: Failure writing to file : %s\n", filename);
            sRc = 1;
        }
    }
    if(NULL != sFile)
    {
        if(fclose(sFile))
        {
            printf("**** ERROR: writeFile: Failure closing file : %s\n", filename);
            if(0 == sRc)
                sRc = 1;
        }
    }
    return sRc;
}

#endif