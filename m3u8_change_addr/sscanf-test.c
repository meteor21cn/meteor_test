#include <stdio.h>
#include <string.h>

int main()
{
	char *domain = "www.sina.com.cn";
	char url[10][1024];
	sscanf(domain, "%[^/.].%[^/.].%[^/.]$", url[0], url[1], url[2], url[3]);
	printf("%s || %s || %s || %s\n", url[0], url[1], url[2], url[3]);
	return 0;
}