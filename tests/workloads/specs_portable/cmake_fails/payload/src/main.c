/* Never compiled: the configure step fails first. */
#include <stdio.h>
int main(void) {
    printf("FIXTURE_ID=unreachable\n");
    printf("RESULT=FAIL\n");
    return 0;
}
