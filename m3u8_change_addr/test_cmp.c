#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <regex.h>
#include <malloc.h>


static int rgx_status = 0;  // notcompiled? compiled? freed? 

//absolute path ?  nmatch: 1+count(subexpression)
char *replace_str(const char*origal, const char *pattern,const size_t nmatch)
{
	    int status;
	    int i;
	    regex_t reg;

	    int org_pos = 0;
	    int rep_pos = 0;


	    regmatch_t pmatch[nmatch];

	    const char *org_str = origal;
	    char *replace = (char *)malloc(4096);

	    regcomp(&reg,pattern,REG_EXTENDED);

	    while (1)
	    {
		    status = regexec(&reg, org_str+org_pos, nmatch,pmatch,0);

	    	if( status == 0) // success
	    	{
	    		strncpy(replace+rep_pos,org_str+org_pos,pmatch[0].rm_so);//or memcpy
		    	rep_pos += pmatch[0].rm_so;

		    	strncpy(replace+rep_pos,"REPLACE",7);
		    	rep_pos += 7;

		    	org_pos += pmatch[0].rm_eo;
	    	}
	    	else if (status == REG_NOMATCH) //nomatch
	    	{
	    		strcpy(replace+rep_pos,org_str+org_pos);
		    	break;
	    	}
	    	else // error
	    	{
	    		//TODO:LOG_ERROR ->regexerror()
	    		break;
	    	}
		}

		printf("%s\n",replace);
	    regfree(&reg);

	    return replace;
}

static char *c_name[]={
    "com",
    "edu",
    NULL
};
int is_domain_same_corp(char *visiting_domain, char *domain_in_file)
{
    if (visiting_domain == NULL || domain_in_file == NULL)
    	return -1;

    int len_v = strlen(visiting_domain);
    int len_f = strlen(domain_in_file);

    int short_len = len_f > len_v ? len_v : len_f;
    int dot_count = 0;

    char *v = visiting_domain + len_v;
    char *f = domain_in_file + len_f;

    while ( *--v == *--f )
    {
        if ( v == visiting_domain || f == domain_in_file)
            break;
        if ( *v == '.') 
            dot_count++;
    }

    if ( dot_count > 2)
        return 1;
    else if ( dot_count < 2)
       
        goto done;
    else
    {
        int in_list,i;

        if(*v == *f && len_v == len_f)
            return 1;

        char *cc = strchr(v,'.');
        char c_tmp[len_v];

        for( i=0,cc++; c_tmp[i] = *cc ; i++,cc++)
        {
            if(c_tmp[i] == '.' )
            {
                c_tmp[i] = '\0';
                break;
            }
        }

        in_list = 0;
        for ( i = 0; c_name[i]; i++)
        {
            if(!strcmp(c_name[i],c_tmp)) //
            {
                in_list = 1;
                break;
            }
        }

        if (in_list)
        	goto done;
        else
        	return 1;
    }

    done: 
    	if (*v != *f)
    	{
    		return 0;
    	}
    	else
    	{
    		if ( len_v == len_f ) 
    			return 1;
    		return v == visiting_domain ? *--f == '.' : *--v == '.';
    	}
}

int main(int argc,char** argv)
{
	int i,j,num;
	char *a[] = {
		"www.baidu.com",
		"xxx.baidu.com",
		"xxx.yyy.baidu.com",
		"zzz.ccc.baidu.com",
		"baidu.com",
		"sina.com",
		"sina.com.cn",
		"sina.com.cn",
		"baidu.org",
		"sina.cn",
	};
	for (i = 0,num = sizeof(a)/sizeof(a[0]); i < num ; i++)
	{
		for (j = i; j < num; j++)
		{
			printf("[%s,%s] ",a[i],a[j]);
			fflush(stdout);

			if (is_domain_same_corp(a[i],a[j]))
			{
				printf("same corp\n");
			}
			else
			{
				printf("NOTSAME CORP\n");
			}
		}
	}
  	//replace_str("my name is ye jingrong ye qingxia li bainameye ye ye","qing",1);
}


