#include "vulnerable.h"

#ifndef BUFFER_SIZE
#error "Define BUFFER_SIZE"
#endif // BUFFER_SIZE

char vulnerable(const char *input) {
    char buffer[BUFFER_SIZE] = {0};
    for (unsigned long i = 0; input[i] != '\0'; ++i) {
        buffer[i] = input[i];
    }
    return buffer[0];
}
