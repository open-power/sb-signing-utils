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

#include "dilutils.h"
#include "mlca2.h"
#include "pqalgs.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* gAlgname = MLCA_ALGORITHM_SIG_DILITHIUM_87_R2;

#define BUF_SIZE 8000

int main(int argc, char** argv)
{
    size_t      sPrivKeyBytes     = BUF_SIZE;
    size_t      sPubKeyBytes      = BUF_SIZE;
    size_t      sWirePrivKeyBytes = BUF_SIZE;
    size_t      sWirePubKeyBytes  = BUF_SIZE;
    int         sIdx              = 0;
    int         sRc               = 0;
    bool        sPrintHelp        = false;
    bool        sRaw              = false;
    const char* sPubKeyFile       = NULL;
    const char* sPrivKeyFile      = NULL;

    for(sIdx = 1; sIdx < argc; sIdx++)
    {
        if(strcmp(argv[sIdx], "-h") == 0)
        {
            sPrintHelp = true;
        }
        else if (strcmp(argv[sIdx], "-raw") == 0)
        {
            sRaw = true;
        }
        else if(strcmp(argv[sIdx], "-pub") == 0)
        {
            sIdx++;
            sPubKeyFile = argv[sIdx];
        }
        else if(strcmp(argv[sIdx], "-priv") == 0)
        {
            sIdx++;
            sPrivKeyFile = argv[sIdx];
        }
        else if (strcmp(argv[sIdx], "-alg") == 0)
        {
            sIdx ++;
            if (strcmp(argv[sIdx], "dilr2-87") == 0) {
                gAlgname = MLCA_ALGORITHM_SIG_DILITHIUM_87_R2;
            }
            else if (strcmp(argv[sIdx], "mldsa-87") == 0) {
                gAlgname = MLCA_ALGORITHM_SIG_MLDSA_87;
            }
            else
            {
                printf("**** ERROR : Unknown algoritym : %s\n", argv[sIdx]);
                sPrintHelp = true;
            }
        }
        else
        {
            printf("**** ERROR : Unknown parameter : %s\n", argv[sIdx]);
            sPrintHelp = true;
        }
    }

    if(!sPrintHelp && (NULL == sPubKeyFile || NULL == sPrivKeyFile))
    {
        printf("**** ERROR : Missing input parms\n");
        sPrintHelp = true;
    }

    if(sPrintHelp)
    {
        printf("\ngendilkey -priv <private key file> -pub <public key file> [-alg <algorithm>]\n");
        printf("\n");
        printf("\t-alg <dilr2-87|mldsa-87>\tDefault: dilr2-87\n");
        exit(0);
    }

    mlca_ctx_t     sCtx;
    MLCA_RC        sMlRc        = 0;
    unsigned char* sPubKey      = malloc(BUF_SIZE);
    unsigned char* sPrivKey     = malloc(BUF_SIZE);
    unsigned char* sWirePubKey  = malloc(BUF_SIZE);
    unsigned char* sWirePrivKey = malloc(BUF_SIZE);

    if(!sPubKey || !sPrivKey || !sWirePubKey || !sWirePrivKey)
    {
        printf("**** ERROR : Allocation Failure\n");
        exit(1);
    }

    if(0 == sRc)
    {
        sMlRc = mlca_init(&sCtx, 1, 0);
        if(sMlRc)
        {
            printf("**** ERROR : Failed mlca_init : %d\n", sMlRc);
            sRc = 1;
        }
    }
    if(0 == sRc)
    {
        sMlRc = mlca_set_alg(&sCtx, gAlgname, OPT_LEVEL_AUTO);
        if(sMlRc)
        {
            printf("**** ERROR : Failed mlca_set_alg : %d\n", sMlRc);
            sRc = 1;
        }
    }
    if(0 == sRc)
    {
        sMlRc = mlca_set_encoding_by_idx(&sCtx, 0);
        if(sMlRc)
        {
            printf("**** ERROR : Failed mlca_set_encoding_by_name_oid : %d\n", sMlRc);
            sRc = 1;
        }
    }

    if(0 == sRc)
    {
        printf("Generating %s key pair ...\n", gAlgname);
        sPubKeyBytes  = mlca_sig_crypto_publickeybytes(&sCtx);
        sPrivKeyBytes = mlca_sig_crypto_secretkeybytes(&sCtx);
        sMlRc         = mlca_sig_keygen(&sCtx, sPubKey, sPrivKey);
        if(sMlRc)
        {
            printf("**** ERROR : Failed mlca_sig_keygen : %d\n", sMlRc);
            sRc = 1;
        }
    }

    if (sRaw)
    {
        // Just copy over the key
        memcpy(sWirePrivKey, sPrivKey, sPrivKeyBytes);
        sWirePrivKeyBytes = sPrivKeyBytes;
        memcpy(sWirePubKey, sPubKey, sPubKeyBytes);
        sWirePubKeyBytes = sPubKeyBytes;
    }
    else
    {
        if(0 == sRc)
        {
            // Convert private key
            sRc = mlca_key2wire(sWirePrivKey,
                                sWirePrivKeyBytes,
                                sPrivKey,
                                sPrivKeyBytes,
                                0,
                                sPubKey,
                                sPubKeyBytes,
                                NULL,
                                0);
            if(sRc < 0)
            {
                printf("**** ERROR: Failure during private key conversion : %d\n", sRc);
            }
            else
            {
                sWirePrivKeyBytes = sRc;
                sRc                  = 0;
            }
        }

        if(0 == sRc)
        {

            // Convert public key
            sRc = mlca_key2wire(
                sWirePubKey, sWirePubKeyBytes, sPubKey, sPubKeyBytes, 0, NULL, 0, NULL, 0);
            if(sRc < 0)
            {
                printf("**** ERROR: Failure during public key conversion : %d\n", sRc);
                sRc = 1;
            }
            else
            {
                sWirePubKeyBytes = sRc;
                sRc = 0;
            }
        }
    }

    if(0 == sRc)
    {
        writeFile(sWirePrivKey, sWirePrivKeyBytes, sPrivKeyFile);
        writeFile(sWirePubKey, sWirePubKeyBytes, sPubKeyFile);

        printf("Private Key Size : %lu\n", sPrivKeyBytes);
        printf("Public Key Size  : %lu\n", sPubKeyBytes);

        printf("Private Key File : %s\n", sPrivKeyFile);
        printf("Public Key File  : %s\n", sPubKeyFile);
    }

    free(sPrivKey);
    free(sPubKey);
    free(sWirePrivKey);
    free(sWirePubKey);

    mlca_ctx_free(&sCtx);
    exit(sRc);
}
