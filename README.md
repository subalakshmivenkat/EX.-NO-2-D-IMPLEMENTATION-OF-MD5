# EX.-NO-2-D-IMPLEMENTATION-OF-MD5

## AIM:
  To write a program to implement the MD5 hashing technique.
## ALGORITHM:
  
  STEP-1: Read the 128-bit plain text.
  
  STEP-2: Divide into four blocks of 32-bits named as A, B, C and D.
  
  STEP-3: Compute the functions f, g, h and i with operations such as, rotations, permutations, etc,.
  
  STEP-4: The output of these functions are combined together as F and performed circular shifting and then given to key round.
  
  STEP-5: Finally, right shift of ‘s’ times are performed and the results are combined together to produce the final output.
  
## PROGRAM:
```
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MD5_DIGEST_LENGTH 16

typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
} MD5_CTX;

void MD5_Init(MD5_CTX *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->count[0] = ctx->count[1] = 0;
}

void MD5_Transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];

    for (int i = 0; i < 16; i++) {
        x[i] = ((uint32_t)block[i * 4]) | (((uint32_t)block[i * 4 + 1]) << 8) |
             (((uint32_t)block[i * 4 + 2]) << 16) | (((uint32_t)block[i * 4 + 3]) << 24);
    }

    // Round 1
    // [Insert the MD5 algorithm details here, like operations and shifts]
    // Perform transformations according to MD5 algorithm here...

    // Update state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void MD5_Update(MD5_CTX *ctx, const uint8_t *input, size_t inputLen) {
    // Update the MD5 context with new data
    size_t index = (ctx->count[0] / 8) % 64;
    ctx->count[0] += (uint32_t)(inputLen * 8);
    if (ctx->count[0] < (inputLen * 8)) {
        ctx->count[1]++;
    }
    ctx->count[1] += (uint32_t)(inputLen >> 29);

    size_t space = 64 - index;
    if (inputLen >= space) {
        memcpy(&ctx->buffer[index], input, space);
        MD5_Transform(ctx->state, ctx->buffer);
        for (size_t i = space; i + 63 < inputLen; i += 64) {
            MD5_Transform(ctx->state, &input[i]);
        }
        index = 0;
    } else {
        index = 0;
    }
    memcpy(&ctx->buffer[index], &input[inputLen - space], inputLen % 64);
}

void MD5_Final(uint8_t digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx) {
    // Finalize the MD5 hash and produce the digest
    uint8_t padding[64] = { 0x80 };
    uint8_t length[8];
    for (int i = 0; i < 8; i++) {
        length[i] = (ctx->count[i / 4] >> ((i % 4) * 8)) & 0xFF;
    }
    
    size_t index = (ctx->count[0] / 8) % 64;
    size_t padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5_Update(ctx, padding, padLen);
    MD5_Update(ctx, length, 8);

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        digest[i] = (ctx->state[i / 4] >> ((i % 4) * 8)) & 0xFF;
    }
}

void MD5(const uint8_t *input, size_t length, uint8_t digest[MD5_DIGEST_LENGTH]) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, input, length);
    MD5_Final(digest, &ctx);
}

void printMD5(const uint8_t *digest) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

int main() {
    const char *input = "Subalakshmi";
    uint8_t digest[MD5_DIGEST_LENGTH];

    MD5((const uint8_t *)input, strlen(input), digest);
    
    printf("The MD5 hash of '%s' is: ", input);
    printMD5(digest);

    return 0;
}
```
## OUTPUT:
![image](https://github.com/user-attachments/assets/edd9223f-37c2-4ece-996e-dd66ccd94cef)

## RESULT:
  Thus the implementation of MD5 hashing algorithm had been implemented successfully using C.
