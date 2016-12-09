struct rb_node *md5_list_pop(struct md5_list *list)
{
	struct rb_node *head, *next, *prev, *tmp;
	head = &(list->head);
	next = head->md5_right;
	
	// Èç¹ûÁ´±íÒÑ¿Õ£¬ÁÙÊ±´´½¨Ò»¸ö½Úµã
	if( next == head ){
		tmp = _md5_node_calloc();
		return tmp;
	}

	tmp = next;
	prev = tmp->md5_left;
	next = tmp->md5_right;
	
	next->md5_left = prev;
	prev->md5_right = next;
	

	list->size--;
	return tmp;
}