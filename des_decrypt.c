/* Jacob Gutierrez, Computer Security HW 2 */
/* DES Process as outlined in the assigned reading 5 */

#include <stdio.h>
#include <stdlib.h>

typedef struct subKey{ // Step 1: Create 16 subkeys, each of which is 48-bits long.
    unsigned long key : 48; // allocate the amount of bits needed
} subKey;

typedef struct Key{
    unsigned long base_key : 56;
    unsigned int left_part : 28;
    unsigned int right_part : 28;
    subKey* subKeys;
} Key;

// cipher text and key
unsigned long des_ctext = 0b1100101011101101101000100110010101011111101101110011100001110011;
unsigned long des_key = 0b0100110001001111010101100100010101000011010100110100111001000100;

// static arrays for the permutation tables 
// alll values here are from the reading 
int perm1[56]         = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
int perm2[48]         = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
int ip[64]            = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
int e_bit_table[48]   = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
int number_shifts[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1}; // page 4 
// pages 9 and 10 for s function 
int sFunc1[4][16]     = {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}};
int sFunc2[4][16]     = {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}};
int sFunc3[4][16]     = {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}};
int sFunc4[4][16]     = {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}};
int sFunc5[4][16]     = {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}};
int sFunc6[4][16]     = {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}};
int sFunc7[4][16]     = {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}};
int sFunc8[4][16]     = {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};
int p[32]             = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
int final_p[64]       = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};


int main(int argc, char* argv[]){

    unsigned long cipher = des_ctext;
    unsigned long key = des_key;
    unsigned long msg = 0;  // variable to hold the permuted message
    unsigned int msgLeft, msg_right;
    // allocate memory for the Key structure
    Key* k = (Key*)malloc(sizeof(Key));
    k->base_key = 0; // Initialize the base_key member

    // apply the permutation specified by perm1 to the key
    for (int i = 0; i < 56; i++) {
        // Extract the bit at the position specified by perm1[i], and place it at the correct position in base_key
        k->base_key |= ((key >> (64 - perm1[i])) & 0x01) << (55 - i);
    }
   

    k->left_part = k->base_key >> 28; // isolate the top 4 bits of base_key and store in left_part
    k->right_part = k->base_key & 0xFFFFFFF; // isolate the lower 28 bits of base_key and store in right_part
    k->subKeys = (subKey*)calloc(16, sizeof(subKey)); // memory for 16 subKey structures, initializing them to zero

    // loop through all 16 rounds of key processing
    for (int keyNum = 0; keyNum < 16; keyNum++){ 
        if (number_shifts[keyNum] == 1){ // if shit value is 1
            // rotate the keys 1 bit by shifting left then oring with the bits shifted out
            k->left_part = (k->left_part << 1) | (k->left_part >> 27);
            k->right_part = (k->right_part << 1) | (k->right_part >> 27);
        }else{
            // else two shifts
            k->left_part = (k->left_part << 2) | (k->left_part >> 26);
            k->right_part = (k->right_part << 2) | (k->right_part >> 26);
        }
        
        k->base_key = 0; // reset the working key
        k->base_key = k->left_part; // move the left key to the upper 28 bits of base_key
        k->base_key = (k->base_key << 28) | k->right_part; // combine the right key into the lower 28 bits of base_key
        
        // init the subkey for this round
        for (int i = 0; i < 48; i++){
            int bitPosition = 56 - perm2[i]; // the bit position in the combined key to select
            unsigned long selectedBit = (k->base_key >> bitPosition) & 0x01; // shift the combined key right to bring the selected bit to the lsb position, then mask with 0x01 to isolate it
            int subKeyBitPosition = 47 - i; // calculate the position where this bit should be placed in the subkey
            unsigned long positionedBit = selectedBit << subKeyBitPosition; // shift the selected bit to its position in the subkey
            k->subKeys[keyNum].key = k->subKeys[keyNum].key | positionedBit; // inser the positioned bit into the subkey w OR operation
            // preserves existing bits and sets the new bit in its correct position
        }
    }

    // loop over each of the 64 bits
    for (int i = 0; i < 64; i++){
        int bitPosition = 64 - ip[i]; // determine the position of  current bit in  original message using permutation array
        unsigned long selectedBit = (cipher >> bitPosition) & 0x01; // isolate bit
        int newPosition = 63 - i; // calculate the new position for this bit in the permuted message
        msg = msg | (selectedBit << newPosition); //place bit in messafge 
    }

    // divide the 64-bit message into two 32-bit halves and shift right to get the left 32 bits
    msgLeft = msg >> 32;
    msg_right = msg & 0xFFFFFFFF;  // apply a bitmask to isolate the right 32 bits

    for (int subKeyNum = 15; subKeyNum > -1; subKeyNum--) {
        int current_round = 16 - subKeyNum;
        unsigned int omsg_right = msg_right;

        subKey rightExpanded;
        rightExpanded.key = 0;
        for (int j = 0; j < 48; j++) {
            long temp = 0;
            temp = (msg_right >> (32 - e_bit_table[j])) & 0x01;
            temp = temp << (47 - j);
            rightExpanded.key = rightExpanded.key | temp;
        }

        rightExpanded.key = rightExpanded.key^k->subKeys[subKeyNum].key;

        msg_right = 0; //right half of the data block post operation s
        // for loop to loop through the s boxes one by one 
        for (int sBoxIndex= 0; sBoxIndex< 8; sBoxIndex++) {
        int segmentIndex = sBoxIndex * 6; // calculate the start index of the 6-bit segment
        int bitsForSBox = (rightExpanded.key >> (48 - segmentIndex - 6)) & 0x3F; // isolate the 6-bit segment
        int row = ((bitsForSBox & 0x20) >> 4) | (bitsForSBox & 0x01);     // row by combining the first and last bit of the segment
        int col = (bitsForSBox >> 1) & 0x0F; // column by isolating the middle four bits of the segment
            if (sBoxIndex== 0) {
                msg_right = msg_right | sFunc1[row][col] << (28 - sBoxIndex*4);
            } else if (sBoxIndex== 1) {
                msg_right = msg_right | sFunc2[row][col] << (28 - sBoxIndex*4);
            } else if (sBoxIndex== 2) {
                msg_right = msg_right | sFunc3[row][col] << (28 - sBoxIndex*4);
            } else if (sBoxIndex== 3) {
                msg_right = msg_right | sFunc4[row][col] << (28 - sBoxIndex*4);
            } else if (sBoxIndex== 4) {
                msg_right = msg_right | sFunc5[row][col] << (28 - sBoxIndex*4);
            } else if (sBoxIndex== 5) {
                msg_right = msg_right | sFunc6[row][col] << (28 - sBoxIndex*4);
            } else if (sBoxIndex== 6) {
                msg_right = msg_right | sFunc7[row][col] << (28 - sBoxIndex*4);
            } else if (sBoxIndex== 7) {
                msg_right = msg_right | sFunc8[row][col] << (28 - sBoxIndex*4);
            }
        }

        unsigned int tempRight = 0;
        for (int i = 0; i < 32; i++) {
            tempRight = tempRight | (((msg_right >> (32 - p[i])) & 0x01) << (31 - i));
        }
        msg_right = tempRight;
        msg_right = msgLeft^msg_right;
        msgLeft = omsg_right;

        printf("Round %d:\n   L%dR%d: %x%x \n", current_round,current_round,current_round, msgLeft, msg_right); //as hex
        printf("   Generated Key: %lx\n", k->subKeys[subKeyNum].key);
    }

    unsigned long combined_c = ((unsigned long)msg_right << 32) | msgLeft; // combine left and right half of message  
    unsigned long final_message = 0; //  variable to store the final message after applying the final permutation

    // the final permutation to the combined message
    for (int i = 0; i < 64; i++) {
        final_message |= ((combined_c >> (64 - final_p[i])) & 0x01) << (63 - i);
    }

    // convert and print message as ascii characters
    printf("Decypted Message: 0x%lx\n", final_message);
    printf("Final Decrypted Message: ");
    for (int i = 0; i < 8; i++) {
        printf("%c", (char)(final_message >> (56 - 8 * i))); // extract each byte and cast to char
    }
    printf("\n"); 
    return 0;
}