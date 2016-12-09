/**
*	from https://github.com/google/streamhtmlparser
*/

#include <stdio.h>
#include <string.h>
#include <streamhtmlparser/htmlparser.h>


//streamhtmlparser/htmlparser.h

/* Returns the contents of the current attribute value.
 *
 * Returns NULL if not inside an attribute value.
 */
//const char *htmlparser_value(htmlparser_ctx *ctx);

/* Returns true if the parser is inside an attribute value and the value is
 * surrounded by single or double quotes. */
//int htmlparser_is_attr_quoted(htmlparser_ctx *ctx);

/* Returns the current attribute type.
 *
 * The attribute type can be one of:
 *   HTMLPARSER_ATTR_NONE - not inside an attribute.
 *   HTMLPARSER_ATTR_REGULAR - Inside a normal attribute.
 *   HTMLPARSER_ATTR_URI - Inside an attribute that accepts a uri.
 *   HTMLPARSER_ATTR_JS - Inside a javascript attribute.
 *   HTMLPARSER_ATTR_STYLE - Inside a css style attribute.
 */
//int htmlparser_attr_type(htmlparser_ctx *ctx);
//htmlparser_attr_type(ctx) == HTMLPARSER_ATTR_URI

/* Returns the position inside the current attribute value (-1 outside)
 */
//int htmlparser_value_index(htmlparser_ctx *ctx);
//htmlparser_value_index(ctx) != -1


int rewrite_url_stream_html(htmlparser_ctx *ctx, char *str, int length, int *last_attr_type, char *result) {
  int i;
  char *url, *url_temp;
  int rewrited = 0;
  static int inside_url;
  int length_of_result = 0;
  for(i = 0; i < length; i++) {
    char c = str[i];
    htmlparser_parse_chr(ctx, c);
    
    if(*last_attr_type == HTMLPARSER_ATTR_URI) {
        //url_temp = htmlparser_value(ctx);
        //if(url_temp)  url = url_temp;
        //printf("len:%d   ", strlen(url_temp));
        //printf("url: %s\n", url_temp);
        if( (htmlparser_is_attr_quoted(ctx) || htmlparser_value_index(ctx) != -1 )
            && htmlparser_attr_type(ctx) == HTMLPARSER_ATTR_URI) {
              inside_url = 1;
              url = htmlparser_value(ctx);
        }
        else {
          if(inside_url)  {
              inside_url = 0;
              printf("URL:     %s\n", url);

              //TODO: rewrite url


              strcat(result, url);
              length_of_result += strlen(url);
              *last_attr_type = htmlparser_attr_type(ctx);
              printf("last_attr_type: %d\n", *last_attr_type);
          }
        }
        
    }
    if(*last_attr_type != HTMLPARSER_ATTR_URI) {
        result[ length_of_result++ ] = c;
        *last_attr_type = htmlparser_attr_type(ctx);
    }
  }
  result[ length_of_result ++ ] = '\0';
  return length_of_result;
}


int main()
{
  //char *str = "<html><body><title></title><a href=http://www.baidu.com alt=\"123\">url</a></body></html>";

  char *total = malloc(4096);
  char result[4096];
  char *stream;
  size_t line = 2048;
  int length;
  

  int last_attr_type = -1;
  htmlparser_ctx *ctx = htmlparser_new();
  printf("HTMLPARSER_ATTR_URI: %d\n", HTMLPARSER_ATTR_URI);
  // rewrite_stream_html(ctx, str, strlen(str), -1);
  // press CTRL+D to end !!!
  while((length = getline(&stream, &line, stdin)) != EOF) {
      //remove '\n'
      length--; 
      stream[length] ='\0';
      int len = rewrite_url_stream_html(ctx, stream, length, &last_attr_type, result);
      if(len > 0 )  {
        printf("result: %s\n", result);
        strcat(total, result);
        strcpy(result, "");
      }
  }
  printf("total: %s\n", total);
  
  return 0;
}

/*
input
<html> 
  <body $> 
    <title> $ </title> 
    <a href="$" alt="$"> url </a> 
  </body> 
</html>


output
<html> 
  <body [[ tag=body ]]> 
    <title> [[ tag=title ]] </title> 
    <a href="[[ tag=a attr=href ]]" alt="[[ tag=a attr=alt ]]"> url </a> 
  </body> 
</html>
*/
