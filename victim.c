#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>


#define SLEEP 3

char test_str[] = "[+] test\n";

int main()
{
    while(1) {
        printf("%s\n", test_str);
        sleep(SLEEP);
    }
}
