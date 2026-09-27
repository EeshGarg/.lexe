#include <stdio.h>
unsigned long first_value(void);
unsigned long second_value(void);
unsigned long third_value(void);

int main(void) {
    printf("FIXTURE_ID=portable-build-fails-partway\n");
    printf("SUM=%lu\n", first_value() + second_value() + third_value());
    printf("SHOULD_NOT_HAVE_BUILT=yes\n");
    printf("RESULT=PASS\n");
    return 0;
}
