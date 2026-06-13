#include <stdio.h>
#include <string.h>
int check(const char *s){ return strcmp(s, "rizin") == 0; }
int main(int argc, char **argv){
    if (argc > 1 && check(argv[1])) { puts("correct: secret_flag_abc"); return 0; }
    puts("wrong"); return 1;
}
