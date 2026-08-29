#include <stdint.h>

__attribute__((noinline)) uint64_t r2sign_stable_transform(uint64_t value) {
    uint64_t mixed = value ^ UINT64_C(0x9e3779b97f4a7c15);
    mixed ^= mixed >> 29;
    mixed *= UINT64_C(0xbf58476d1ce4e5b9);
    mixed ^= mixed >> 31;
    mixed *= UINT64_C(0x94d049bb133111eb);
    return mixed ^ (mixed >> 28);
}

__attribute__((noinline)) uint64_t r2sign_stable_fold(const uint64_t *values) {
    uint64_t result = UINT64_C(0x243f6a8885a308d3);
    for (uint64_t index = 0; index < 8; ++index) {
        result ^= r2sign_stable_transform(values[index] + index);
        result = (result << 7) | (result >> 57);
    }
    return result;
}

int main(void) {
    const uint64_t values[8] = {1, 3, 5, 7, 11, 13, 17, 19};
    return (int)(r2sign_stable_fold(values) & UINT64_C(0xff));
}
