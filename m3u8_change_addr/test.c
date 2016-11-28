#include <stdio.h>
int main()
{
    char *pos= "http://www.baidu.com/dir1/index.html\nabcdefg";
    char cc[80]="http://";
    sscanf(pos,
            "http://%[^\n]",&cc[7]);
    printf("%s\n",cc);
}
