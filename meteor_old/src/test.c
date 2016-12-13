#define print_conf_str_value(config,str) \
    printf("%20s%s",#config,str)
#include <stdio.h>
#define copy(member) abc(config->member,setconfig->member)
#include <string.h>

char a[][15]={
    "yejingrong",
    "huanghuageng",
    "lihe",
    "fengzhenyang",
    "zhangpiao",
    "liwujun",
    "liulin"
};

char b[][15]={
    "yejingrong",
    "huanghuageng",
    "lihe",
    "fengzhenyang",
    "zhangpiao",
    "liwujun",
    "liulin"
};

char** environ;

int main (int argc,char**argv) 
{
    int i=0;
    //printf("%s#%s\n",argv[0],argv[1]);
    //argv[0]="myname is lihe";
    //strcpy(argv[0],"mynameislihe");
    //printf("%s#%s\n",argv[0],argv[1]);
    while(environ[i])
        printf("%s\n",environ[i++]);
    
}
