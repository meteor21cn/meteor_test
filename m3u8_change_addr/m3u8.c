#include <stdio.h>
int pocceess_from_stream(char *stream, char *str, char *url, struct hls_media_playlist *me)
{
	int n = strlen(stream);
	while(stream[n] != '\n' && n >= 0)
	{
		//...
		n--;
	}
	stream[n] = '\0';
	strcat(str, stream);
	strcpy(me->source, str);
	strcpy(str, stream[n+1]);

	return 1;
}

