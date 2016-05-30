/*************************************************************************
Single mode encryption program, written by A.Arıcıoğlu and M.Yeniay
///////////////////////////////////////////////////////////////////////////
Number of rounds : 8
Block size : 8
Padding character: 'x'


**************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>


void getSubBytes();
void InvertSubBytes();
void stateFunc();

static uint8_t xtime(uint8_t);
static uint8_t Multp(uint8_t, uint8_t);
static void mixColumns(void);
static void InvMixColumns(void);
static void InvShiftColumn(void);
static void ShiftColumn(void);

static uint8_t xtime(uint8_t x);

static uint8_t getSBoxValue(uint8_t);
static uint8_t getSBoxInvert(uint8_t);

static void KeyExpansion(void);
static void addRoundKey(uint8_t);

static void Cipher(void);
static void InvCipher(void);

void padding(uint8_t inText[8]);

uint8_t inTextPadd[16];
uint8_t state[4][4];

uint8_t sboxIndex[16];

static uint8_t roundKey[176];
//default key
uint8_t Key[16] = { (uint8_t) 0x61, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16,
                    (uint8_t) 0x61, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6,
                    (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88,
                    (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };


static const uint8_t sbox[256] =   {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
/* 0 */  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
/* 1 */  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
/* 2 */  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
/* 3 */  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
/* 4 */  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
/* 5 */  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
/* 6 */  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
/* 7 */  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
/* 8 */  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
/* 9 */  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
/* A */  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
/* B */  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
/* C */  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
/* D */  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
/* E */  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
/* F */  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] =
{
//        0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
/* 0 */ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
/* 1 */ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
/* 2 */ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
/* 3 */ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
/* 4 */ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
/* 5 */ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
/* 6 */ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
/* 7 */ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
/* 8 */ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
/* 9 */ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
/* A */ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
/* B */ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
/* C */ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
/* D */ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
/* E */ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
/* F */ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

static const uint8_t Rcon[255] = {
//        0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
/* 0 */  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
/* 1 */  0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
/* 2 */  0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
/* 3 */  0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
/* 4 */  0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
/* 5 */  0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
/* 6 */  0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
/* 7 */  0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
/* 8 */  0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
/* 9 */  0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
/* A */  0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
/* B */  0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
/* C */  0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
/* D */  0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
/* E */  0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
/* F */  0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb  };
int main(int argc, char * * argv) {
    // uint8_t a[8] = {0x61, 0x79, 0x6b, 0x6b, 0x74, 0x72, 0x65, 0x77 };
    uint8_t buff[8];
    int i, j, m = 0, opt;
    clock_t begin, end;
    begin=clock();
    double time_spent;



    FILE * fp, * fp1, * log;
    //TODO logları kaydetmek için log.dat
    log = fopen("log.dat", "a");
    //Option belirteçleri
    //e for Encryption
    //d for Decryption
    while ((opt = getopt(argc, argv, "e:d:")) != -1)
        switch (opt) {
        case 'e':
            fp = fopen(optarg, "r");
            if (fp == NULL) {
                printf("Dosya1 açılamadı. Dosya yolunu ve erişim izinlerini kontrol edin.\n");
                break;
            } else {
                //Dosya boyutunu al
                fseek(fp, 0L, SEEK_END);
                int sz = ftell(fp) - 1;
                //printf("%d\n\n", sz);
                rewind(fp);
                //Pointerı başa çek
                fp1 = fopen (argv[3], "w");
                fclose(fp1);


                fp1 = fopen(argv[3], "a");
                if (fp1 == NULL) {
                    printf("Dosya2 açılamadı. Dosya yolunu ve erişim izinlerini kontrol edin.\n");
                    break;
                } else {
                    //printf("Dosya açıldı.");
                    KeyExpansion();
                    while (m < (sz / 8)) {
                        m++;
                        fgets(buff, 9, fp);
                        //Keyexpansion was here.
                        padding(buff);
                        stateFunc();

                        Cipher();

                        for (i = 0; i < 4; i++) {
                            for (j = 0; j < 4; j++) {
                                //printf("!>%c<! ", state[i][j]);

                                fprintf(fp1, "%c", state[i][j]);
                                //fputs(state[i][j], fp1);
                            }
                        }
                    }
                    fgets(buff, (sz % 8) + 1, fp);
                    for (m = ((sz % 8)); m < 8; m++)
                        buff[m] = 'x';

                    KeyExpansion();
                    padding(buff);
                    stateFunc();

                    Cipher();

                    for (i = 0; i < 4; i++) {
                        for (j = 0; j < 4; j++) {
                            //printf("!>%c<! ", state[i][j]);

                            fprintf(fp1, "%c", state[i][j]);
                            //fputs(state[i][j], fp1);
                        }
                    }

                }
            }
            fclose(fp);
            fclose(fp1);
            printf("Encrypted.\n");
            break;
        case 'd':
            fp1 = fopen(optarg, "r");
            //dosya boyutunu al
            fseek(fp1, 0L, SEEK_END);
            int sz = ftell(fp1) - 1;
            rewind(fp1);
            //printf("%d\n\n", sz);
            //pointerı başa at.
            fp = fopen (argv[3], "w");
                fclose(fp);
            fp = fopen(argv[3], "a");

            while (m < ((sz / 16) + 1)) {
                m++;
                //TODO aldığımız değerle intextpaddi doldurup state func çağılırmalı
                fgets(inTextPadd, 17, fp1);
                /*for (i = 0; i < 16; i++) {
                    printf("%x  ", inTextPadd[i]);
                }
                printf("\n");
                printf("\n");
                for (i = 0; i < 16; i++) {
                    printf("%x  ", inTextPadd[i]);
                }
                printf("\n");*/
                KeyExpansion();
                stateFunc();
                InvCipher();
                //TODO şifrelenmiş karakterin 'x' olma ihtimali ile oluşan yanlış filtrelemeyi düzelt.
                for (i = 0; i < 4; i++) {
                    for (j = 0; j < 4; j++) {
                        //printf("!%c! ", state[i][j]);
                        if (state[i][j] != 'x')
                            fprintf(fp, "%c", state[i][j]);
                    }

                }

            }
            fclose(fp1);
            printf("Decrypted.\n");
            break;
        default:
            printf("Invalid option.\n");
        }

    printf("\n");
    end =clock();
    time_spent= (double)(end - begin) / CLOCKS_PER_SEC;

    printf("Process time: %f\n", time_spent);
    return 0;
}

void padding(uint8_t inText[8]) {
    int i;
    for (i = 0; i < 8; i++) {
        inTextPadd[i] = inText[i];
        inTextPadd[i + 8] = 0x78;
    }

}

static uint8_t getSBoxValue(uint8_t num) {
    return sbox[num];
}

static uint8_t getSBoxInvert(uint8_t num) {
    return rsbox[num];
}

void getSubBytes(void) {

    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[j][i] = getSBoxValue((state)[j][i]);
        }
    }

}

void InvertSubBytes(void) {

    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[j][i] = getSBoxInvert((state)[j][i]);
        }
    }
}

void swapBytes(uint8_t inSwap[16]) {
    uint8_t temp;
    int i;
    for (i = 0; i < 16; i++) {
        temp = inSwap[i];
        inSwap[i] = inSwap[i + 8];
        inSwap[i + 8] = temp;
    }

}

void stateFunc() {
    int i, j, k = 0;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {

            state[i][j] = inTextPadd[k];
            k++;

        }
    }
}

void shiftRows() {
    uint8_t temp;
    // 2. satır sol 1 kere
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // 3. satır sol 2 kere
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;

    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // 4. satır sol 3 kere
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

void InvShiftRows() {
    uint8_t temp;

    // 2. satır sağ 1 kere
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // 3. satır sağ 2 kere
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    state[2][2] = temp;

    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // 4. satır sağ 3 kere
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

static void InvShiftColumn(void) {
    uint8_t temp;
    //2. kolon 1 aşağı
    temp = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = temp;
    //3. kolon 2 aşağı
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;
    //4. kolon 3 aşağı
    temp = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = temp;
}

static void ShiftColumn(void) {
    uint8_t temp;
    //2. kolon 1 yukarı
    temp = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = temp;
    //3. kolon 2 yukarı
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;
    //4. kolon 3 yukarı
    temp = state[0][3];
    state[0][3] = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = temp;
}

static uint8_t xtime(uint8_t x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}
static uint8_t Multp(uint8_t x, uint8_t y) {
    return (((y & 1) * x) ^
        ((y >> 1 & 1) * xtime(x)) ^
        ((y >> 2 & 1) * xtime(xtime(x))) ^
        ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
        ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

static void mixColumns(void) {
    int i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i) {
        a = state[i][0];
        b = state[i][1];
        c = state[i][2];
        d = state[i][3];
        //mixcolumn yapılacak matrisle çarpılır.
        state[i][0] = Multp(a, 0x02) ^ Multp(b, 0x03) ^ Multp(c, 0x01) ^ Multp(d, 0x01);
        state[i][1] = Multp(a, 0x01) ^ Multp(b, 0x02) ^ Multp(c, 0x03) ^ Multp(d, 0x01);
        state[i][2] = Multp(a, 0x01) ^ Multp(b, 0x01) ^ Multp(c, 0x02) ^ Multp(d, 0x03);
        state[i][3] = Multp(a, 0x03) ^ Multp(b, 0x01) ^ Multp(c, 0x01) ^ Multp(d, 0x02);
    }
}

static void InvMixColumns(void) {
    int i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i) {
        a = state[i][0];
        b = state[i][1];
        c = state[i][2];
        d = state[i][3];
        //invmixcolumn yapılacak matrisle çarpılır.
        state[i][0] = Multp(a, 0x0e) ^ Multp(b, 0x0b) ^ Multp(c, 0x0d) ^ Multp(d, 0x09);
        state[i][1] = Multp(a, 0x09) ^ Multp(b, 0x0e) ^ Multp(c, 0x0b) ^ Multp(d, 0x0d);
        state[i][2] = Multp(a, 0x0d) ^ Multp(b, 0x09) ^ Multp(c, 0x0e) ^ Multp(d, 0x0b);
        state[i][3] = Multp(a, 0x0b) ^ Multp(b, 0x0d) ^ Multp(c, 0x09) ^ Multp(d, 0x0e);
    }
}

static void KeyExpansion(void) {
    uint32_t i, j, k;
    uint8_t temp[4];

    // ilk round key kendisi
    for (i = 0; i < 4; ++i) {
        roundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        roundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        roundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        roundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    for (; i < 36; ++i) {
        for (j = 0; j < 4; ++j) {
            temp[j] = roundKey[(i - 1) * 4 + j];
        }

        if (i % 4 == 0) // satır satır almak için
        {

            // rotWord
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            //subword
            temp[0] = getSBoxValue(temp[0]);
            temp[1] = getSBoxValue(temp[1]);
            temp[2] = getSBoxValue(temp[2]);
            temp[3] = getSBoxValue(temp[3]);

            temp[0] = temp[0] ^ Rcon[i / 4];
        }

    }
}

static void addRoundKey(uint8_t round) {
    uint8_t i, j;

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[i][j] ^= roundKey[round * 16 + i * 4 + j]; //her roundda 16 karakter işlediği için
        }
    }
}

static void Cipher(void) {
    uint8_t round = 0;

    // Roundlar başlamadan önce ilk keyi state e yerleştir.
    addRoundKey(0);

    //7 round
    for (round = 1; round < 8; ++round) {

        getSubBytes();
        ShiftColumn();
        shiftRows();
        mixColumns();
        addRoundKey(round);
    }

    // son round mixcolumn yok.

    getSubBytes();
    ShiftColumn();
    shiftRows();
    addRoundKey(8);

}

static void InvCipher(void) {
    uint8_t round = 0;

    // Roundlar başlamadan önce ilk keyi state e yerleştir.
    addRoundKey(8);

    // 7 round geriden

    for (round = 7; round > 0; round--) {
        InvShiftRows();
        InvShiftColumn();
        InvertSubBytes();
        addRoundKey(4);
        InvMixColumns();
    }

    // son round mixcolumn yok.
    InvShiftRows();
    InvShiftColumn();
    InvertSubBytes();
    addRoundKey(0);
}
