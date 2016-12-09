struct md5_list
{
	char *head;
	size_t size;
};

int md5_list_init(struct md5_list *list, int count);
