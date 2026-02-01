#include <stdio.h>

int secret_function(int a) {
    return a * 42;
}

int main() {
    int key = 10;
    printf("The secret is %d\n", secret_function(key));
    return 0;
}
