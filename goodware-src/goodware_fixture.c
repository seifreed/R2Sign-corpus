#include <stdint.h>

static uint32_t r2sign_fixture_score(uint32_t value) {
    value ^= UINT32_C(0x9e3779b9);
    value *= UINT32_C(0x85ebca6b);
    return value ^ (value >> 13);
}

int main(void) {
    uint32_t score = r2sign_fixture_score(UINT32_C(0x13579bdf));
    return (int)(score & 1U);
}
