#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Simple XOR function for "encryption"
void xor_string(char* input, char* key, char* output) {
    int key_len = strlen(key);
    int input_len = strlen(input);
    
    for (int i = 0; i < input_len; i++) {
        output[i] = input[i] ^ key[i % key_len];
    }
    output[input_len] = '\0';
}

// License validation function
int validate_license(char* license) {
    // Expected license format: XXXX-YYYY-ZZZZ-WWWW
    if (strlen(license) != 19) {
        return 0;
    }
    
    // Check dashes are in correct positions
    if (license[4] != '-' || license[9] != '-' || license[14] != '-') {
        return 0;
    }
    
    // Simple checksum algorithm
    int checksum = 0;
    for (int i = 0; i < 19; i++) {
        if (license[i] != '-') {
            checksum += license[i];
        }
    }
    
    // Magic number check (reverse engineers need to find this)
    if (checksum != 1337) {
        return 0;
    }
    
    // Additional validation - must start with "DSCR"
    if (strncmp(license, "DSCR", 4) != 0) {
        return 0;
    }
    
    return 1;
}

void show_flag() {
    // Pre-computed flag for simplicity
    printf("🎉 License Valid! Here's your flag: DSCCTF{L1C3NS3_R3V3RS3_M4ST3R_2026}\n");
}

int main() {
    char license[100];
    
    printf("═══════════════════════════════════════\n");
    printf("       SOFTWARE LICENSE CHECKER       \n");
    printf("═══════════════════════════════════════\n");
    printf("Enter your license key: ");
    
    if (fgets(license, sizeof(license), stdin)) {
        // Remove newline
        license[strcspn(license, "\n")] = 0;
        
        if (validate_license(license)) {
            show_flag();
        } else {
            printf("❌ Invalid license key!\n");
            printf("Expected format: XXXX-YYYY-ZZZZ-WWWW\n");
            printf("Make sure your license is properly registered.\n");
        }
    }
    
    return 0;
}